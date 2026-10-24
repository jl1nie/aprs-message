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

impl From<String> for AprsCallsign {
    fn from(c: String) -> Self {
        let mut ssid = None;
        let mut callsign = c.trim().to_string();
        if let Some((new_callsign, new_ssid)) = callsign.rsplit_once('-') {
            ssid = new_ssid.parse::<u32>().ok();
            callsign = new_callsign.to_string();
        }
        AprsCallsign { callsign, ssid }
    }
}

#[derive(Debug, Clone)] // ← Cloneつけるよ！データパスしやすくなる
pub enum AprsData {
    AprsPosition {
        callsign: AprsCallsign,
        longitude: f64,
        latitude: f64,
    },
    AprsMessage {
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

/// ワーカーの内部状態保持用
struct AprsWorkerState {
    acknum: Arc<Mutex<i32>>,
    ackpool: Arc<Mutex<Vec<MsgHist>>>,
    writer: Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    sender: String,
}

/// 接続の監視と再接続の間隔
#[derive(Debug, Clone, Copy)]
struct Timing {
    /// この時間なにも受信しなければ、接続が死んだとみなす(APRS-IS は 20 秒ごとに "#" の行を送る)
    idle_timeout: Duration,
    /// 受信ループが終わっていないかを見る間隔
    check_interval: Duration,
    /// 再接続の前に待つ時間
    reconnect_delay: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            idle_timeout: Duration::from_secs(120),
            check_interval: Duration::from_secs(10),
            reconnect_delay: Duration::from_secs(5),
        }
    }
}

/// 接続状態を管理するワーカー
struct AprsWorker {
    host: String,
    callsign: String,
    password: String,
    state: Arc<Mutex<AprsWorkerState>>,
    handle: JoinHandle<()>,
    /// 最後に設定したフィルター。再接続したら送り直す
    filter: Option<String>,
    timing: Timing,
}

/// 公開API！
#[derive(Clone)]
pub struct AprsIS {
    worker: Arc<Mutex<AprsWorker>>,
    rx: Arc<Mutex<mpsc::Receiver<AprsData>>>,
}

impl AprsWorker {
    // login処理
    async fn login(
        host: &str,
        callsign: &str,
        password: &str,
    ) -> Result<(
        BufReader<OwnedReadHalf>,
        Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
    )> {
        let stream = TcpStream::connect(host).await?;
        stream.set_nodelay(true)?;

        let (rh, wh) = stream.into_split();
        let mut reader = BufReader::new(rh);
        let mut writer = BufWriter::new(wh);

        let mut buf = String::new();
        let n = reader.read_line(&mut buf).await?;
        if n == 0 || !buf.starts_with("#") {
            bail!("Invalid banner from server")
        }
        // バナーからサーバーバージョンを抽出して表示
        // 例: "# aprsc 2.1.20-gdaa359f\r\n"
        let banner = buf.trim_end();
        let server_version = banner
            .strip_prefix("# ")
            .unwrap_or(banner);
        info!("APRS-IS connected to {} | server: {}", host, server_version);

        let login_str = format!(
            "user {} pass {} vers aprs_inet 0.0_1\r\n",
            callsign, password
        );
        writer.write_all(login_str.as_bytes()).await?;
        writer.flush().await?;

        buf.clear();
        let n = reader.read_line(&mut buf).await?;
        if n > 0 && (buf.contains("verified") || password == "-1") {
            // ログイン応答からサーバー名を抽出して表示
            // 例: "# logresp JL1NIE-9 verified, server T2HAKATA\r\n"
            let resp = buf.trim_end();
            let assigned_server = resp
                .split(", server ")
                .nth(1)
                .unwrap_or("unknown");
            info!("APRS-IS login OK | callsign: {} | assigned server: {}", callsign, assigned_server);
            let writer = Arc::new(Mutex::new(writer));
            return Ok((reader, writer));
        }
        bail!("login error")
    }

    // パケット読み出しループ
    async fn run_loop(
        sender: &str,
        mut reader: BufReader<OwnedReadHalf>,
        writer: &Arc<Mutex<BufWriter<OwnedWriteHalf>>>,
        ackpool: &Arc<Mutex<Vec<MsgHist>>>,
        tx: mpsc::Sender<AprsData>, // 外部送信用チャネル
        idle_timeout: Duration,
    ) -> Result<()> {
        let re_ack = Regex::new(r"ack(\d+)").unwrap();

        loop {
            let mut raw = Vec::new();
            let read = match tokio::time::timeout(idle_timeout, reader.read_until(b'\n', &mut raw)).await {
                Ok(read) => read,
                Err(_) => {
                    error!("No data from APRS-IS for {:?}; treating the connection as dead", idle_timeout);
                    bail!("APRS-IS connection idle for {:?}", idle_timeout);
                }
            };
            match read {
                // 相手が接続を閉じた。読み直してもすぐ 0 が返るだけなので、抜けて再接続させる
                Ok(0) => {
                    error!("Connection closed by APRS-IS server");
                    bail!("APRS-IS connection closed by server");
                }
                Ok(n) if n > 0 && raw.first() == Some(&b'#') => {
                    let buf = String::from_utf8_lossy(&raw);
                    tracing::debug!("APRS-IS server: {}", buf.trim_end());
                }
                Ok(_n) if !raw.is_empty() => {
                    let buf = String::from_utf8_lossy(&raw);
                    let buf = buf.trim_end_matches("\r\n").to_string();
                    tracing::debug!("raw packet: {}", buf);
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
                                        let packet = AprsData::AprsMessage {
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
                // 読み込みのエラーはどれも接続の異常として抜け、再接続させる(続けると空回りすることがある)
                Err(e) => {
                    match e.kind() {
                        ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => error!("Connection lost: {:?}", e),
                        _ => warn!("Unexpected read error: {:?}", e),
                    }
                    return Err(e.into());
                }
            }
        }
    }

    // 他のヘルパーメソッドはそのまま使う
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
        tracing::debug!("send_all_inner: buf = {}", buf);
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
        let mut acknum = acknum.lock().await;
        let mut ackpool = ackpool.lock().await;

        let now = SystemTime::now();
        let since = now - Duration::new(15 * 60, 0);

        // 古いのを削除～
        ackpool.retain(|m| m.time > since);
        *acknum = (*acknum + 1) % 100; // 1-99でループさせる

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

            let mut wait_time = 7;
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

    // 再接続ロジック！
    // 受信ループが終わるたびに再接続する(何度でも)
    async fn reconnect_loop(worker: Arc<Mutex<AprsWorker>>, external_tx: mpsc::Sender<AprsData>) {
        loop {
            // ワーカーがアクティブかチェック
            let (should_reconnect, timing) = {
                let worker_guard = worker.lock().await;
                (worker_guard.handle.is_finished(), worker_guard.timing) // awaitしない！is_finishedでチェックするだけ
            };

            // 実行中なら再接続しない
            if !should_reconnect {
                tracing::debug!("Worker thread still running, no need to reconnect");
                tokio::time::sleep(timing.check_interval).await;
                continue;
            }

            tracing::info!("Reconnecting...");
            // 再接続待機
            tokio::time::sleep(timing.reconnect_delay).await;

            // 再接続試行
            let host;
            let callsign;
            let password;
            let filter;

            {
                let w = worker.lock().await;
                host = w.host.clone();
                callsign = w.callsign.clone();
                password = w.password.clone();
                filter = w.filter.clone();
            }

            match Self::login(&host, &callsign, &password).await {
                Ok((new_reader, new_writer)) => {
                    // 新しい接続にはフィルターがないので、設定してあったものを送り直す
                    if let Some(f) = &filter {
                        if let Err(e) = Self::send_all_inner(&new_writer, format!("#filter {}", f)).await {
                            error!("Failed to restore filter after reconnect: {:?}", e);
                            continue;
                        }
                    }
                    // 必要なデータだけ先に取り出す
                    let ackpool_clone;
                    let sender_clone = callsign.clone();

                    {
                        let worker_guard = worker.lock().await;
                        let mut state_guard = worker_guard.state.lock().await;

                        // 新しいwriterで更新
                        state_guard.writer = new_writer.clone();

                        // ackpoolはコピーだけ取得
                        ackpool_clone = state_guard.ackpool.clone();
                    }

                    let tx = external_tx.clone();
                    let new_handle = tokio::spawn(async move {
                        if let Err(e) = Self::run_loop(
                            &sender_clone,
                            new_reader,
                            &new_writer,
                            &ackpool_clone,
                            tx,
                            timing.idle_timeout,
                        )
                        .await
                        {
                            tracing::error!("APRS run loop exited with error: {:?}", e);
                        }
                    });

                    let mut worker_guard = worker.lock().await;
                    worker_guard.handle = new_handle;

                    info!("Successfully reconnected!");
                    // ループは続ける。次に切れたときも再接続する
                }
                Err(e) => {
                    error!("Reconnection failed: {:?}", e);
                    // 次の再接続へ
                }
            }
        }
    }
}

impl AprsIS {
    // 外部API: connect
    pub async fn connect(host: &str, callsign: &str, password: &str) -> Result<Self> {
        Self::connect_with(host, callsign, password, Timing::default()).await
    }

    async fn connect_with(host: &str, callsign: &str, password: &str, timing: Timing) -> Result<Self> {
        // 外部へのデータ送信用チャネル作成
        let (tx, rx) = mpsc::channel(32);
        let rx = Arc::new(Mutex::new(rx)); // ← ここでラップ！

        // ログイン処理
        let (reader, writer) = AprsWorker::login(host, callsign, password).await?;

        // 状態作成
        let state = Arc::new(Mutex::new(AprsWorkerState {
            acknum: Arc::new(Mutex::new(0)),
            ackpool: Arc::new(Mutex::new(Vec::new())),
            writer: writer.clone(),
            sender: callsign.to_string(),
        }));

        // 初期run_loop起動
        let sender_clone = callsign.to_string();
        let tx_clone = tx.clone();
        let ackpool_clone = {
            let state_guard = state.lock().await;
            state_guard.ackpool.clone()
        };

        let worker_handle = tokio::spawn(async move {
            let res = AprsWorker::run_loop(
                &sender_clone,
                reader,
                &writer,
                &ackpool_clone,
                tx_clone,
                timing.idle_timeout,
            )
            .await;

            if let Err(e) = res {
                tracing::error!("APRS run loop exited with error: {:?}", e);
            }
        });

        // ワーカー作成
        let worker = AprsWorker {
            host: host.to_string(),
            callsign: callsign.to_string(),
            password: password.to_string(),
            state,
            handle: worker_handle,
            filter: None,
            timing,
        };

        let worker_arc = Arc::new(Mutex::new(worker));

        // バックグラウンド再接続ループ起動
        let worker_clone = worker_arc.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            AprsWorker::reconnect_loop(worker_clone, tx_clone).await;
        });

        // インスタンス返却
        Ok(Self {
            worker: worker_arc,
            rx, // 外部用チャネル
        })
    }

    // パケット読み出し - ロック不要！
    pub async fn read_packet(&self) -> Result<AprsData> {
        let mut rx_guard = self.rx.lock().await;
        if let Some(packet) = rx_guard.recv().await {
            Ok(packet)
        } else {
            bail!("Packet channel closed")
        }
    }

    // バディリスト設定
    pub async fn set_budlist_filter(&self, buddy: Vec<String>) -> Result<()> {
        let filter = buddy.join("/");
        self.set_filter(format!("b/{}", filter)).await
    }

    // フィルター設定
    pub async fn set_filter(&self, filter: String) -> Result<()> {
        let mut worker_guard = self.worker.lock().await;
        worker_guard.filter = Some(filter.clone());
        let state_guard = worker_guard.state.lock().await;
        let cmd = format!("#filter {}", filter);
        AprsWorker::send_all_inner(&state_guard.writer, cmd).await?;
        Ok(())
    }

    // メッセージ送信
    pub async fn write_message(&self, addressee: &AprsCallsign, messages: &str) -> Result<()> {
        let addressee_str: String = addressee.into();
        // 必要な状態を取得して早めにロック解放
        let (sender, writer, ackpool, acknum) = {
            let worker_guard = self.worker.lock().await;
            let state_guard = worker_guard.state.lock().await;
            (
                state_guard.sender.clone(),
                state_guard.writer.clone(),
                state_guard.ackpool.clone(),
                state_guard.acknum.clone(),
            )
        };

        // データのコピー
        let messages_clone = messages.to_string();
        let addressee_clone = addressee_str.clone();
        // 送信処理を別タスクで実行
        tokio::spawn(async move {
            if let Err(e) = AprsWorker::write_message_inner(
                &sender,
                &writer,
                &ackpool,
                &acknum,
                &addressee_clone,
                &messages_clone,
            )
            .await
            {
                error!("APRS message send failed: {:?}", e);
            }
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use tokio::net::TcpListener;

    /// 偽の APRS-IS。ログインに答え、hold だけ受信した行を記録してから接続を閉じる。接続ごとの受信行を返す
    async fn fake_server(hold: Duration) -> (String, Arc<Mutex<Vec<Vec<String>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let conns: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let c = conns.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (rh, mut wh) = stream.into_split();
                let mut reader = BufReader::new(rh);
                wh.write_all(b"# fake 1.0\r\n").await.unwrap();
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                wh.write_all(b"# logresp TEST verified, server FAKE\r\n").await.unwrap();
                let idx = {
                    let mut g = c.lock().await;
                    g.push(vec![line.trim_end().to_string()]);
                    g.len() - 1
                };
                let deadline = tokio::time::Instant::now() + hold;
                loop {
                    let mut l = String::new();
                    match tokio::time::timeout_at(deadline, reader.read_line(&mut l)).await {
                        Ok(Ok(n)) if n > 0 => c.lock().await[idx].push(l.trim_end().to_string()),
                        _ => break,
                    }
                }
                // ここで rh・wh が落ちて接続が閉じる
            }
        });
        (addr, conns)
    }

    async fn connected_pair() -> (BufReader<OwnedReadHalf>, Arc<Mutex<BufWriter<OwnedWriteHalf>>>, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let (rh, wh) = client.into_split();
        (BufReader::new(rh), Arc::new(Mutex::new(BufWriter::new(wh))), server)
    }

    #[tokio::test]
    async fn run_loop_returns_when_server_closes() {
        // 以前は Ok(0) を無視して読み直し続け、CPU を使い切ったまま再接続もしなかった
        let (reader, writer, server) = connected_pair().await;
        drop(server);
        let (tx, _rx) = mpsc::channel(4);
        let ackpool = Arc::new(Mutex::new(Vec::new()));
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            AprsWorker::run_loop("TEST", reader, &writer, &ackpool, tx, Duration::from_secs(60)),
        )
        .await
        .expect("run_loop did not return after the server closed the connection");
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn run_loop_returns_when_idle() {
        let (reader, writer, _server) = connected_pair().await; // 開いたまま何も送らない
        let (tx, _rx) = mpsc::channel(4);
        let ackpool = Arc::new(Mutex::new(Vec::new()));
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            AprsWorker::run_loop("TEST", reader, &writer, &ackpool, tx, Duration::from_millis(200)),
        )
        .await
        .expect("run_loop did not time out on an idle connection");
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn reconnects_every_time_and_restores_filter() {
        // 以前は 1 回再接続すると監視をやめ、2 回目の切断から復帰しなかった
        let (addr, conns) = fake_server(Duration::from_millis(300)).await;
        let timing = Timing {
            idle_timeout: Duration::from_secs(5),
            check_interval: Duration::from_millis(50),
            reconnect_delay: Duration::from_millis(50),
        };
        let aprs = AprsIS::connect_with(&addr, "TEST", "-1", timing).await.unwrap();
        aprs.set_filter("r/36/137/1500 t/p/m".to_string()).await.unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while conns.lock().await.len() < 4 {
            assert!(tokio::time::Instant::now() < deadline, "only {} connections", conns.lock().await.len());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let g = conns.lock().await;
        for (i, lines) in g.iter().enumerate().take(4) {
            assert!(lines[0].starts_with("user TEST pass -1"), "{:?}", lines);
            assert!(lines.iter().any(|l| l == "#filter r/36/137/1500 t/p/m"), "connection {} did not get the filter: {:?}", i, lines);
        }
    }
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

        server
            .set_budlist_filter(userfilter)
            .await
            .expect("set filter faied");

        tracing::info!("running");
        loop {
            if let Ok(packet) = server.read_packet().await {
                tracing::info!("packet = {:?}", packet);
                match packet {
                    AprsData::AprsMessage {
                        callsign,
                        addressee,
                        message,
                    } => {
                        let addressee: AprsCallsign = AprsCallsign::from(addressee);
                        tracing::info!(
                            "message from {:?} to {:?} = {}",
                            callsign,
                            addressee,
                            message
                        );
                        let _ = server
                            .write_message(
                                &callsign,
                                &format!("reply={}\n{}2\n{}3", message, message, message),
                            )
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
