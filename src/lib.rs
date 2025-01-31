use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::tcp::{OwnedWriteHalf,OwnedReadHalf};
use tokio::sync::{mpsc,Mutex};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tracing::{span, Level};

pub use aprs_parser::{self, AprsData, AprsMessage, AprsMicE, AprsPacket, AprsPosition, Callsign, Longitude, Latitude};

pub struct AprsIS {
    acks: Arc<Mutex<HashMap<String, String>>>,
    tx: mpsc::Sender<AprsData>,
    rx: mpsc::Receiver<AprsData>,
    writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    reader: Arc<Mutex<BufReader<OwnedReadHalf>>>,
}

impl AprsIS {
    pub async fn connect(host: &str) -> Result<Self> {
        let span = span!(Level::INFO, "AprsIS");
        let _enter = span.enter();

        let stream = TcpStream::connect(host).await?;
        let (rh, wh ) = stream.into_split();
        let reader = Arc::new(Mutex::new(BufReader::new(rh)));
        let writer = Arc::new(Mutex::new(BufWriter::new(wh)));
        let mut buf = String::new();
        tracing::info!("connected to {}", host);
        
        let chk   = reader.clone();
        let mut chk = chk.lock().await;
        let n = chk.read_line(&mut buf).await?;
        tracing::info!("read {} bytes {:?}", n, buf);
        
        if n == 0 || !buf.starts_with("#") {
            bail!("Invalid bannder from server");
        }
        tracing::info!("succesfully connected");
        let (tx, rx) = mpsc::channel(32);
        Ok(Self {
            acks : Arc::new(Mutex::new(HashMap::new())),
            tx,
            rx,
            reader,
            writer
        })
    }
    
    async fn read_message(&self, message :&mut String) -> Result<usize> {
        let mut reader = self.reader.lock().await;
        let n = reader.read_line(message).await?;
        Ok(n)
    }
    
    async fn write_message(&self, message: String) -> Result<()> {
        let mut writer = self.writer.lock().await;
        writer.write_all(message.as_bytes()).await?;
        writer.flush().await?;
        Ok(())
    }

    async fn send_all(&mut self, buf: String) -> Result<()> {
        let buf = buf.trim_end_matches(&['\r', '\n'][..]).to_string() + "\r\n";
        self.write_message(buf).await?;
        Ok(())
    }

    pub async fn login(&mut self, callsign: &str, password: &str) -> Result<()> {
        let mut response = String::new();
        let login_str = format!("user {} pass {} vers aprs_inet 0.0_1", callsign, password);
        self.send_all(login_str).await?;
        let n = self.read_message(&mut response).await?;
        if n > 0 {
            tracing::info!("server response = {:?}", response);
            let response = response
                .split(|c| [' ', ','].contains(&c))
                .collect::<Vec<_>>();
            let is_verified = *response.get(3).unwrap_or(&"");
            if is_verified == "verified" || password == "-1" {
                return Ok(());
            }
            bail!(format!("incorrect password {:?}",response))
        }
        bail!("incorrect server response")
    }

    pub async fn set_filter(&mut self, filter: String) -> Result<()> {
        let buf = format!("#filter {}", filter);
        self.send_all(buf).await?;
        Ok(())
    }

    pub async fn set_prefix_filer(&mut self, prefix: Vec<String>) -> Result<()> {
        let filter = prefix.join("/");
        self.set_filter(format!("p/{}", filter)).await
    }

    pub async fn set_budlist_filer(&mut self, buddy: Vec<String>) -> Result<()> {
        let filter = buddy.join("/");
        self.set_filter(format!("b/{}", filter)).await
    }

    pub async fn run(&mut self) -> Result<JoinHandle<()>> {

        loop {
            let mut buf = String::new();
            match self.read_message(&mut buf).await {
                Ok(n) if n > 0 && !buf.starts_with("#") => {
                    match AprsPacket::decode_textual(buf.as_bytes()) {
                        Ok(AprsPacket { from, data, .. }) => {
                            tracing::info!("from = {}-{:?}", from.call(), from.ssid());
                            match data {
                                AprsData::Position(AprsPosition {
                                    to,
                                    latitude,
                                    longitude,
                                    ..
                                }) => {
                                    tracing::info!(
                                        "poisition to={:?}, lat={:?} lon={:?}",
                                        to,
                                        latitude,
                                        longitude
                                    );
                                    //self.tx.try_send(data);
                                }
                                AprsData::MicE(AprsMicE {
                                    latitude,
                                    longitude,
                                    ..
                                }) => {
                                    tracing::info!("mic-e lat={:?} lon={:?}", latitude, longitude);
                                    //self.tx.try_send(data);
                                }
                                AprsData::Message(AprsMessage {
                                    to,
                                    addressee,
                                    text,
                                    id,
                                }) => {
                                    let addressee =
                                        String::from_utf8(addressee).unwrap_or_default();
                                    let message = String::from_utf8(text).unwrap_or_default();
                                    tracing::info!(
                                        "message to={} addressee = {} message={} id={:?}",
                                        to,
                                        addressee,
                                        message,
                                        id
                                    );
                                }
                                p => { tracing::info!("discard packer {:?}",p)}
                            }
                        }
                        Err(e) => tracing::warn!("parse error {}", e),
                    }
                }
                Ok(_) => { tracing::info!("skip server response {}", buf);
                }
                Err(e) => { tracing::warn!("parket formart error :{:?}", e)
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
        tracing_subscriber::fmt::init();
        let aprshost = env::var("APRSHOST").unwrap();
        let aprsuser = env::var("APRSUSER").unwrap();
        let aprspasword = env::var("APRSPASSWORD").unwrap();
        let mut userfilter = aprsuser.clone();
        userfilter = userfilter
            .rsplit_once('-')
            .map(|(before, _)| format!("{}-*", before))
            .unwrap_or(userfilter);
        let filter = format!("r/35.684074/139.75296/100 b/{}", userfilter);
        tracing::info!("set filter to {}", filter);
        let mut server = AprsIS::connect(&aprshost)
            .await
            .expect("Can not connect server");
        server
            .login(&aprsuser, &aprspasword)
            .await
            .expect("Login failure");
        server.set_filter(filter).await.expect("set filter faied");
        tracing::info!("running");
        let handle = async { server.run().await.expect("message error").await };
        let _res = tokio::join!(handle);
    }
}
