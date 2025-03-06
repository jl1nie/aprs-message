use anyhow::{bail, Error, Result};
use regex::Regex;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{span, Level};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AprsCallsign {
    pub callsign: String,
    pub ssid: Option<u32>,
}

impl From<&AprsCallsign> for String {
    fn from(c: &AprsCallsign) -> Self {
        match c.ssid {
            Some(ssid) => format!("{}-{}", c.callsign, ssid),
            None => c.callsign.clone(),
        }
    }
}

impl From<&String> for AprsCallsign {
    fn from(c: &String) -> Self {
        let mut ssid = None;
        let mut callsign = c.trim_end().to_string();
        if let Some((new_callsign, new_ssid)) = callsign.rsplit_once('-') {
            ssid = new_ssid.parse::<u32>().ok();
            callsign = new_callsign.to_string();
        }
        AprsCallsign { callsign, ssid }
    }
}

#[derive(Debug)]
pub enum AprsData {
    AprsPosition {
        callsign: AprsCallsign,
        longitude: f64,
        latitude: f64,
    },
    AprsMesasge {
        callsign: AprsCallsign,
        addressee: String,
        message: String,
    },
}

#[derive(Debug)]
struct MsgHist {
    time: SystemTime,
    addressee: String,
    acknum: i32,
}
#[derive(Clone)]
pub struct AprsIS {
    acknum: Arc<Mutex<i32>>,
    ackpool: Arc<Mutex<Vec<MsgHist>>>,
    rx: Arc<Mutex<mpsc::Receiver<AprsData>>>,
    sender: String,
    writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    _handle: Arc<JoinHandle<Result<(), Error>>>,
}

impl AprsIS {
    pub async fn connect(host: &str, callsign: &str, password: &str) -> Result<Self> {
        let span = span!(Level::INFO, "AprsIS");
        let _enter = span.enter();

        let stream = TcpStream::connect(host).await?;
        stream.set_nodelay(true)?;

        let (rh, wh) = stream.into_split();
        let mut reader = BufReader::new(rh);
        let mut writer = BufWriter::new(wh);

        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await?;

        tracing::info!("connect to {} read {} bytes {:?}", host, n, buf);
        if n == 0 || !buf.starts_with("#") {
            bail!("Invalid bannder from server")
        }
        tracing::info!("succesfully connected");

        let login_str = format!(
            "user {} pass {} vers aprs_inet 0.0_1\r\n",
            callsign, password
        );
        writer.write_all(login_str.as_bytes()).await?;
        writer.flush().await?;

        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await?;
        if n > 0 {
            tracing::info!("login response {}", buf);
            if buf.contains("verified") || password == "-1" {
                let (tx, rx) = mpsc::channel(32);

                let sender = callsign.to_string();

                let acknum = Arc::new(Mutex::new(0));
                let ackpool = Arc::new(Mutex::new(Vec::new()));
                let ackpool_thread = ackpool.clone();

                let writer = Arc::new(Mutex::new(writer));
                let writer_thread = writer.clone();
                let rx = Arc::new(Mutex::new(rx));

                let _handle = Arc::new(tokio::spawn(async move {
                    AprsIS::run(&sender, reader, &writer_thread, &ackpool_thread, tx).await
                }));

                return Ok(Self {
                    acknum,
                    ackpool,
                    rx,
                    sender: callsign.to_string(),
                    writer,
                    _handle,
                });
            }
        }
        bail!("login error")
    }

    async fn store_ack(
        ackpool: &Arc<Mutex<Vec<MsgHist>>>,
        addressee: &str,
        acknum: i32,
    ) -> Result<()> {
        let mut ackpool = ackpool.lock().await;

        let now = SystemTime::now();
        let since = now - Duration::new(15 * 60, 0);

        ackpool.retain(|m| m.time > since);
        ackpool.push(MsgHist {
            time: now,
            addressee: addressee.to_string(),
            acknum,
        });
        Ok(())
    }

    async fn new_ack(acknum: &Arc<Mutex<i32>>, ackpool: &Arc<Mutex<Vec<MsgHist>>>) -> Result<i32> {
        let mut ackpool = ackpool.lock().await;
        let mut acknum = acknum.lock().await;

        let now = SystemTime::now();
        let since = now - Duration::new(15 * 60, 0);

        ackpool.retain(|m| m.time > since);
        *acknum = (*acknum + 1) % 100;

        Ok(*acknum)
    }

    async fn find_ack(ackpool: &Arc<Mutex<Vec<MsgHist>>>, from: &str, acknum: i32) -> Result<bool> {
        let mut ackpool = ackpool.lock().await;

        let result = ackpool
            .iter()
            .find(|m| m.acknum == acknum && m.addressee == from);

        if result.is_some() {
            ackpool.retain(|m| m.acknum != acknum || m.addressee != from);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn send_all(writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>, buf: String) -> Result<()> {
        let buf = buf.trim_end_matches(&['\r', '\n'][..]).to_string() + "\r\n";
        let mut writer = writer.lock().await;
        writer.write_all(buf.as_bytes()).await?;
        writer.flush().await?;

        Ok(())
    }

    pub async fn set_filter(&self, filter: String) -> Result<()> {
        let buf = format!("#filter {}", filter);
        AprsIS::send_all(&self.writer, buf).await?;
        Ok(())
    }

    pub async fn set_prefix_filter(&self, prefix: Vec<String>) -> Result<()> {
        let filter = prefix.join("/");
        self.set_filter(format!("p/{}", filter)).await
    }

    pub async fn set_budlist_filter(&self, buddy: Vec<String>) -> Result<()> {
        let filter = buddy.join("/");
        self.set_filter(format!("b/{}", filter)).await
    }

    async fn send_ack(
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        sender: &str,
        mut addressee: String,
        id: String,
    ) -> Result<()> {
        addressee += "        ";
        addressee.truncate(9);
        let buf = format!("{}>APRS,TCPIP*::{}:ack{}", sender, addressee, id);
        AprsIS::send_all(writer, buf).await?;
        Ok(())
    }

    pub async fn write_message(&self, addressee: &AprsCallsign, messages: &str) -> Result<()> {
        let sender = self.sender.clone();
        let addressee: String = addressee.into();

        let mut to_addr = format!("{}         ", addressee);
        to_addr.truncate(9);

        for message in messages.lines() {
            let message = message.to_string();
            let ackpool = self.ackpool.clone();
            let addressee = addressee.clone();
            let writer = self.writer.clone();
            let acknum = self.acknum.clone();
            let header = format!("{}>APRS,TCPIP*::{}:", sender, to_addr);
            tokio::spawn(async move {
                let body = format!(
                    "{}{}",
                    header,
                    if message.len() > 67 {
                        &message[..67]
                    } else {
                        &message
                    }
                );
                let mut wait_time = 7;
                let acknum = AprsIS::new_ack(&acknum, &ackpool).await.unwrap();
                for _i in 0..3 {
                    AprsIS::send_all(&writer, format!("{}{{{}", body, acknum))
                        .await
                        .unwrap();
                    tokio::time::sleep(Duration::from_secs(wait_time)).await;
                    if AprsIS::find_ack(&ackpool, &addressee, acknum)
                        .await
                        .unwrap()
                    {
                        break;
                    };
                    wait_time *= 2;
                }
            });
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }

    pub async fn read_packet(&self) -> Result<AprsData> {
        let mut rx = self.rx.lock().await;
        if let Some(packet) = rx.recv().await {
            Ok(packet)
        } else {
            bail!("packet read error")
        }
    }

    async fn run(
        sender: &String,
        mut reader: BufReader<OwnedReadHalf>,
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        ackpool: &Arc<Mutex<Vec<MsgHist>>>,
        tx: mpsc::Sender<AprsData>,
    ) -> Result<()> {
        let re_ack = Regex::new(r"ack(\d+)").unwrap();

        loop {
            let mut buf = String::new();

            match reader.read_line(&mut buf).await {
                Ok(n) if n > 0 && !buf.starts_with("#") => {
                    buf = buf.trim_end_matches("\r\n").to_string();

                    match aprs_parser::AprsPacket::decode_textual(buf.as_bytes()) {
                        Ok(aprs_parser::AprsPacket { from, data, .. }) => {
                            let mut callsign = from.call().to_string();
                            callsign = callsign.trim_end().to_string();

                            let ssid = if from.ssid().is_some() {
                                Some(from.ssid().unwrap().parse::<u32>().unwrap_or_default())
                            } else {
                                None
                            };

                            let callsign = AprsCallsign { callsign, ssid };

                            match &data {
                                aprs_parser::AprsData::Position(aprs_parser::AprsPosition {
                                    latitude,
                                    longitude,
                                    ..
                                }) => {
                                    let packet = AprsData::AprsPosition {
                                        callsign,
                                        longitude: **longitude,
                                        latitude: **latitude,
                                    };
                                    tx.try_send(packet).unwrap_or_else(|e| {
                                        tracing::error!("packet send failed {:?}", e)
                                    });
                                }

                                aprs_parser::AprsData::MicE(aprs_parser::AprsMicE {
                                    latitude,
                                    longitude,
                                    ..
                                }) => {
                                    let packet = AprsData::AprsPosition {
                                        callsign,
                                        longitude: **longitude,
                                        latitude: **latitude,
                                    };
                                    tx.try_send(packet).unwrap_or_else(|e| {
                                        tracing::error!("packet send failed {:?}", e)
                                    });
                                }

                                aprs_parser::AprsData::Message(aprs_parser::AprsMessage {
                                    addressee,
                                    text,
                                    id,
                                    ..
                                }) => {
                                    let mut addressee =
                                        String::from_utf8(addressee.clone()).unwrap_or_default();
                                    let mut message =
                                        String::from_utf8(text.clone()).unwrap_or_default();

                                    addressee = addressee.trim_end().to_string();
                                    message = message.trim_end_matches("\r\n").to_string();

                                    if addressee == *sender {
                                        let from = String::from(&callsign);

                                        if let Some(acknum) = re_ack
                                            .captures(&message)
                                            .and_then(|c| c.get(1))
                                            .and_then(|m| m.as_str().parse::<i32>().ok())
                                        {
                                            AprsIS::store_ack(ackpool, &from, acknum).await?;
                                            continue;
                                        }

                                        if let Some(id) = id.clone() {
                                            let id = String::from_utf8(id).unwrap_or_default();
                                            AprsIS::send_ack(writer, sender, from, id).await?;
                                        }
                                        let packet = AprsData::AprsMesasge {
                                            callsign,
                                            addressee,
                                            message,
                                        };
                                        tx.try_send(packet).unwrap_or_else(|e| {
                                            tracing::error!("packet send failed {:?}", e)
                                        });
                                    }
                                }

                                _packet => {}
                            }
                        }

                        Err(e) => {
                            tracing::info!("parser decode error {}", e);
                        }
                    }
                }

                Ok(_) => {
                    //tracing::info!("server ident:{}", buf);
                }

                Err(e) => {
                    tracing::info!("parket formart error:{:?}", e)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio;
    #[tokio::test]
    async fn it_works() {
        tracing_subscriber::fmt()
            .event_format(
                tracing_subscriber::fmt::format()
                    .with_file(true)
                    .with_line_number(true),
            )
            .init();
        let aprshost = env::var("APRSHOST").unwrap();
        let aprsuser = env::var("APRSUSER").unwrap();
        let aprspasword = env::var("APRSPASSWORD").unwrap();
        let server = AprsIS::connect(&aprshost, &aprsuser, &aprspasword)
            .await
            .expect("Can not connect server");

        let userfilter = aprsuser.clone();
        let userfilter = vec![userfilter
            .rsplit_once('-')
            .map(|(call, _)| call.to_string())
            .unwrap_or(userfilter)];

        //let filter = format!("r/35.684074/139.75296/100 b/{}", userfilter);
        //tracing::info!("set filter to {}", filter);
        //server.set_filter(filter).await.expect("set filter faied");

        server
            .set_budlist_filter(userfilter)
            .await
            .expect("set filter faied");

        tracing::info!("running");
        loop {
            if let Ok(packet) = server.read_packet().await {
                tracing::info!("packet = {:?}", packet);
                match packet {
                    AprsData::AprsMesasge {
                        callsign,
                        addressee,
                        message,
                    } => {
                        let addressee: AprsCallsign = AprsCallsign::from(&addressee);
                        tracing::info!(
                            "message from {:?} to {:?} = {}",
                            callsign,
                            addressee,
                            message
                        );
                        let _ = server
                            .write_message(&callsign, &format!("reply={}\nLine2\nLine3", message))
                            .await;
                    }
                    _ => {}
                }
            } else {
                panic!("channel closed");
            }
        }
    }
}
