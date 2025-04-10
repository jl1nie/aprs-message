use anyhow::{bail, Result};
use regex::Regex;
use serde::Serialize;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpStream,
};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize)]
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
        let mut callsign = c.trim().to_string();
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

/// 内部状態保持用。接続中のwriterとかrxとかを持つ～
struct AprsWorkerState {
    acknum: Arc<Mutex<i32>>,
    ackpool: Arc<Mutex<Vec<MsgHist>>>,
    rx: Arc<Mutex<mpsc::Receiver<AprsData>>>,
    writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    sender: String,
}

/// 実際の接続や再接続処理を行うワーカーだぜ！
pub struct AprsWorker {
    host: String,
    callsign: String,
    password: String,
    state: Arc<Mutex<AprsWorkerState>>,
    // 背景で動く再接続ループのタスク
    handle: JoinHandle<()>,
}

impl AprsWorker {
    // login処理。成功したら(reader, writer, tx, rx)返す！
    async fn login(
        host: &str,
        callsign: &str,
        password: &str,
    ) -> Result<(
        BufReader<OwnedReadHalf>,
        Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        mpsc::Sender<AprsData>,
        Arc<Mutex<mpsc::Receiver<AprsData>>>,
    )> {
        let stream = TcpStream::connect(host).await?;
        stream.set_nodelay(true)?;

        let (rh, wh) = stream.into_split();
        let mut reader = BufReader::new(rh);
        let mut writer = BufWriter::new(wh);

        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await?;
        info!("connect to {} read {} bytes {:?}", host, n, buf);
        if n == 0 || !buf.starts_with("#") {
            bail!("Invalid banner from server")
        }
        info!("succesfully connected");

        let login_str = format!(
            "user {} pass {} vers aprs_inet 0.0_1\r\n",
            callsign, password
        );
        writer.write_all(login_str.as_bytes()).await?;
        writer.flush().await?;

        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n > 0 && (buf.contains("verified") || password == "-1") {
            info!("login response {}", buf);
            let (tx, rx) = mpsc::channel(32);
            let writer = Arc::new(Mutex::new(writer));
            let rx = Arc::new(Mutex::new(rx));
            return Ok((reader, writer, tx, rx));
        }
        bail!("login error")
    }

    // run_loop：readerからパケットを読み出してtxに流す。接続が切れたらエラー返す！
    async fn run_loop(
        sender: &str,
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
                            let mut cs = from.call().to_string();
                            cs = cs.trim_end().to_string();
                            let ssid = if let Some(s) = from.ssid() {
                                s.parse::<u32>().ok()
                            } else {
                                None
                            };
                            let callsign = AprsCallsign { callsign: cs, ssid };

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
                                        error!("packet send failed: {:?}", e);
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
                                        error!("packet send failed: {:?}", e);
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
                                            .and_then(|caps| caps.get(1))
                                            .and_then(|m| m.as_str().parse::<i32>().ok())
                                        {
                                            let _ =
                                                Self::store_ack_inner(ackpool, &from, acknum).await;
                                            continue;
                                        }
                                        if let Some(id) = id.clone() {
                                            let id = String::from_utf8(id).unwrap_or_default();
                                            let _ = Self::send_ack_inner(writer, sender, &from, id)
                                                .await;
                                        }
                                        let packet = AprsData::AprsMesasge {
                                            callsign,
                                            addressee,
                                            message,
                                        };
                                        tx.try_send(packet).unwrap_or_else(|e| {
                                            error!("packet send failed: {:?}", e);
                                        });
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            info!("parser decode error: {}", e);
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => match e.kind() {
                    ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => {
                        error!("Connection lost: {:?}", e);
                        return Err(e.into());
                    }
                    _ => {
                        warn!("Unexpected read error: {:?}", e);
                    }
                },
            }
        }
    }

    async fn send_ack_inner(
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        sender: &str,
        addressee: &str,
        id: String,
    ) -> Result<()> {
        let mut addressee = addressee.to_string() + "        ";
        addressee.truncate(9);
        let buf = format!("{}>APRS,TCPIP*::{}:ack{}", sender, addressee, id);
        Self::send_all_inner(writer, buf).await
    }

    async fn send_all_inner(
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        buf: String,
    ) -> Result<()> {
        let buf = buf.trim_end_matches(&['\r', '\n'][..]).to_string() + "\r\n";
        let mut w = writer.lock().await;
        w.write_all(buf.as_bytes()).await?;
        w.flush().await?;
        Ok(())
    }

    async fn store_ack_inner(
        ackpool: &Arc<Mutex<Vec<MsgHist>>>,
        addressee: &str,
        acknum: i32,
    ) -> Result<()> {
        let mut pool = ackpool.lock().await;
        let now = SystemTime::now();
        let since = now - Duration::new(15 * 60, 0);
        pool.retain(|m| m.time > since);
        pool.push(MsgHist {
            time: now,
            addressee: addressee.to_string(),
            acknum,
        });
        Ok(())
    }

    async fn find_ack_inner(
        ackpool: &Arc<Mutex<Vec<MsgHist>>>,
        from: &str,
        acknum: i32,
    ) -> Result<bool> {
        let mut ackpool = ackpool.lock().await;

        let result = ackpool
            .iter()
            .find(|m| m.acknum == acknum && m.addressee == from);

        if result.is_some() {
            // 見つかったら削除しちゃう！
            ackpool.retain(|m| m.acknum != acknum || m.addressee != from);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn new_ack_inner(
        acknum: &Arc<Mutex<i32>>,
        ackpool: &Arc<Mutex<Vec<MsgHist>>>,
    ) -> Result<i32> {
        let mut ackpool = ackpool.lock().await;
        let mut acknum = acknum.lock().await;

        let now = SystemTime::now();
        let since = now - Duration::new(15 * 60, 0);

        // 古いのを削除～
        ackpool.retain(|m| m.time > since);
        *acknum = (*acknum + 1) % 100; // 1-99でループさせるの素敵～♡

        Ok(*acknum)
    }

    async fn write_message_inner(
        sender: &str,
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        ackpool: &Arc<Mutex<Vec<MsgHist>>>,
        acknum: &Arc<Mutex<i32>>,
        addressee: &str,
        messages: &str,
    ) -> Result<()> {
        let mut to_addr = format!("{}         ", addressee);
        to_addr.truncate(9);

        let header = format!("{}>APRS,TCPIP*::{}:", sender, to_addr);

        for message in messages.lines() {
            let message = message.to_string();

            let body = format!(
                "{}{}",
                header,
                if message.len() > 67 {
                    &message[..67]
                } else {
                    &message
                }
            );

            let mut wait_time = 10;
            let ack = Self::new_ack_inner(acknum, ackpool).await?;

            for _ in 0..2 {
                let packet = format!("{}{{{}", body, ack);
                Self::send_all_inner(writer, packet).await?;

                tokio::time::sleep(Duration::from_secs(wait_time)).await;

                if Self::find_ack_inner(ackpool, addressee, ack).await? {
                    break;
                }

                wait_time *= 2;
            }
        }

        Ok(())
    }

    // Background reconnection loop. 再接続に成功したらstate.writerなどを更新するぜ！
    async fn reconnect_loop(worker: Arc<Mutex<AprsWorker>>) {
        loop {
            {
                let _worker_guard = worker.lock().await;
                // ここでworker.state.writer等は最新状態
                // もしrun_loopが落ちたなら、再接続処理に入るはず
            }
            // 簡単な例：一定時間ごとに再接続試行する。
            tokio::time::sleep(Duration::from_secs(5)).await;
            let (new_reader, new_writer, tx, _rx) = match Self::login(
                &worker.lock().await.host,
                &worker.lock().await.callsign,
                &worker.lock().await.password,
            )
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    error!("Reconnection failed: {:?}", e);
                    continue;
                }
            };
            {
                let worker_guard = worker.lock().await;
                // 更新する！writerは新しいものに置き換える
                worker_guard.state.lock().await.writer = new_writer.clone();
                worker_guard.state.lock().await.sender = worker_guard.callsign.clone();

                // Start new run_loop with new_reader in a detached task.
                let sender_clone = worker_guard.callsign.clone();
                let ackpool_clone = worker_guard.state.lock().await.ackpool.clone();
                let writer_clone = new_writer.clone();
                let tx_clone = tx.clone();
                tokio::spawn(async move {
                    let _ = Self::run_loop(
                        &sender_clone,
                        new_reader,
                        &writer_clone,
                        &ackpool_clone,
                        tx_clone,
                    )
                    .await;
                });
            }
            info!("Reconnected and updated worker state.");
            break;
        }
    }
}

/// --- Public API --- ///

#[derive(Clone)]
pub struct AprsIS {
    worker: Arc<Mutex<AprsWorker>>,
}

impl AprsIS {
    // 外部からのconnect。内部でAprsWorkerを生成して、背景で再接続ループも動かす～
    pub async fn connect(host: &str, callsign: &str, password: &str) -> Result<Self> {
        let (reader, writer, tx, rx) = AprsWorker::login(host, callsign, password).await?;
        let state = Arc::new(Mutex::new(AprsWorkerState {
            acknum: Arc::new(Mutex::new(0)),
            ackpool: Arc::new(Mutex::new(Vec::new())),
            rx,
            writer: writer.clone(),
            sender: callsign.to_string(),
        }));

        // Start initial run_loop
        let state_clone = state.clone();
        let sender_clone = callsign.to_string();
        let worker_handle = tokio::spawn(async move {
            let res = AprsWorker::run_loop(
                &sender_clone,
                reader,
                &writer,
                &state_clone.lock().await.ackpool,
                tx,
            )
            .await;
            if let Err(e) = res {
                error!("run_loop exited with error: {:?}", e);
            }
        });

        let worker = AprsWorker {
            host: host.to_string(),
            callsign: callsign.to_string(),
            password: password.to_string(),
            state,
            handle: worker_handle,
        };

        let worker_arc = Arc::new(Mutex::new(worker));

        // Start background reconnection loop (detach it)
        {
            let worker_clone = worker_arc.clone();
            tokio::spawn(async move {
                AprsWorker::reconnect_loop(worker_clone).await;
            });
        }

        Ok(AprsIS { worker: worker_arc })
    }

    pub async fn read_packet(&self) -> Result<AprsData> {
        let worker_guard = self.worker.lock().await;
        let rx_guard = worker_guard.state.lock().await;
        let mut rx = rx_guard.rx.lock().await;
        if let Some(packet) = rx.recv().await {
            Ok(packet)
        } else {
            bail!("packet read error")
        }
    }

    pub async fn set_budlist_filter(&self, buddy: Vec<String>) -> Result<()> {
        let filter = buddy.join("/");
        self.set_filter(format!("b/{}", filter)).await
    }

    pub async fn set_filter(&self, filter: String) -> Result<()> {
        let worker_guard = self.worker.lock().await;
        let cmd = format!("#filter {}", filter);
        AprsWorker::send_all_inner(&worker_guard.state.lock().await.writer, cmd).await?;
        Ok(())
    }

    pub async fn write_message(&self, addressee: &AprsCallsign, messages: &str) -> Result<()> {
        let addressee_str: String = addressee.into();
        let worker_guard = self.worker.lock().await;
        let state = worker_guard.state.lock().await;

        let sender = state.sender.clone();
        let writer = state.writer.clone();
        let ackpool = state.ackpool.clone();
        let acknum = state.acknum.clone();
        let messages = messages.to_string();
        let addressee_str_clone = addressee_str.clone();

        tokio::spawn(async move {
            if let Err(e) = AprsWorker::write_message_inner(
                &sender,
                &writer,
                &ackpool,
                &acknum,
                &addressee_str_clone,
                &messages,
            )
            .await
            {
                tracing::error!("APRS Message failed.: {:?}", e);
            }
        });

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
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
