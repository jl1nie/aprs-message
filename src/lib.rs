use anyhow::{bail, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tracing::{span, Level};

pub use aprs_parser::{self, AprsData, AprsMessage, AprsMicE, AprsPacket, AprsPosition};
pub struct AprsIS {
    buffer: BufStream<TcpStream>,
}

impl AprsIS {
    pub async fn connect(host: &str) -> Result<Self> {
        let stream = TcpStream::connect(host).await?;
        let mut buffer = BufStream::new(stream);
        let mut buf = String::new();
        let span = span!(Level::INFO, "AprsIS");
        let _enter = span.enter();

        tracing::info!("connected to {}", host);
        let n = buffer.read_line(&mut buf).await?;
        tracing::info!("read {} bytes {:?}", n, buf);
        if n > 0 && buf.starts_with("#") {
            tracing::info!("succesfully connected");
            return Ok(Self { buffer });
        }
        bail!("Invalid bannder from server")
    }

    async fn sendall(&mut self, buf: String) -> Result<()> {
        let buf = buf.trim_end_matches(&['\r', '\n'][..]).to_string() + "\r\n";
        self.buffer.write_all(buf.as_bytes()).await?;
        self.buffer.flush().await?;
        Ok(())
    }

    pub async fn set_filter(&mut self, filter: String) -> Result<()> {
        let buf = format!("#filter {}", filter);
        self.sendall(buf).await?;
        self.buffer.flush().await?;
        Ok(())
    }

    pub async fn login(&mut self, callsign: &str, password: &str) -> Result<()> {
        let mut response = String::new();
        let login_str = format!("user {} pass {} vers aprs_inet 0.0_1", callsign, password);
        self.sendall(login_str).await?;
        let n = self.buffer.read_line(&mut response).await?;
        if n > 0 {
            tracing::info!("server response = {:?}", response);
            let response = response
                .split(|c| [' ', ','].contains(&c))
                .collect::<Vec<_>>();
            let is_verified = *response.get(3).unwrap_or(&"");
            if is_verified == "verified" || password == "-1" {
                return Ok(());
            }
            bail!("incorrect password")
        }
        bail!("incorrect server response")
    }

    pub async fn consume(&mut self) -> Result<()> {
        loop {
            let mut buf = String::new();
            match self.buffer.read_line(&mut buf).await {
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
                                }
                                AprsData::MicE(AprsMicE {
                                    latitude,
                                    longitude,
                                    ..
                                }) => {
                                    tracing::info!("mic-e lat={:?} lon={:?}", latitude, longitude);
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
                                _ => {}
                            }
                        }
                        Err(e) => tracing::warn!("parse error {}", e),
                    }
                }
                Ok(_) => { //tracing::info!("skip server response : {}", buf);
                }
                Err(_) => { //tracing::warn!("parket formart error :{:?}", e)
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
        server.consume().await.expect("message error");
    }
}
