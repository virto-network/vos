use crate::os::{self, net};
use edge_net::nal::{TcpAccept, TcpSplit};
use futures_concurrency::future::Race;
use serde::Deserialize;
use sunset::SignKey;
use sunset_embassy::ProgressHolder;

use super::ConnectionError;

pub struct Port {
    conn: net::Connection,
    key: SignKey,
}

impl super::SystemPort for Port {
    type Cfg = Config;
    type Error = ConnectionError;

    async fn configure(cfg: Option<Self::Cfg>) -> Self {
        let cfg = cfg.unwrap_or_default();
        let conn = net::bind(cfg.port).await.expect("bind ssh port");
        Self {
            conn,
            key: SignKey::Ed25519(cfg.key),
        }
    }

    async fn accept_connection(&mut self) -> Result<(), Self::Error> {
        let (addr, mut socket) = self.conn.accept().await.expect("tcp connect");
        log::trace!("connected to peer {addr}");

        let mut rx_buf = [0; 1024 * 4];
        let mut tx_buf = [0; 1024 * 2];
        let srv = sunset_embassy::SSHServer::new(&mut rx_buf, &mut tx_buf).expect("ssh server");
        let session_chan = os::Channel::<sunset::ChanHandle>::new();

        let conn = async {
            loop {
                let mut ph = ProgressHolder::new();
                match srv.progress(&mut ph).await? {
                    sunset::ServEvent::Hostkeys(hk) => hk.hostkeys(&[&self.key])?,
                    sunset::ServEvent::PasswordAuth(a) => {
                        log::trace!("password auth");
                        a.allow()?;
                    }
                    sunset::ServEvent::PubkeyAuth(a) => {
                        log::trace!("pubkey auth");
                        a.allow()?;
                    }
                    sunset::ServEvent::FirstAuth(a) => {
                        let user = a.username()?;
                        log::trace!("first auth for '{user}'");
                        a.allow()?;
                    }
                    sunset::ServEvent::OpenSession(session) => {
                        log::trace!("open session");
                        let ch = session.accept()?;
                        session_chan.send(ch).await;
                    }
                    sunset::ServEvent::SessionShell(req) => {
                        log::trace!("shell request");
                        let _c = req.channel()?;
                        req.succeed()?;
                    }
                    sunset::ServEvent::SessionExec(req) => {
                        log::trace!("exec command");
                        let _c = req.channel()?;
                        req.succeed()?;
                    }
                    sunset::ServEvent::SessionPty(req) => {
                        log::trace!("requested pty");
                        let _c = req.channel()?;
                        req.succeed()?;
                    }
                    sunset::ServEvent::Defunct => todo!(),
                };
            }
            #[allow(unreachable_code)]
            Ok::<_, ConnectionError>(())
        };
        let session = async {
            loop {
                let ch = session_chan.receive().await;
                let mut io = srv.stdio(ch).await?;
                let mut line_buf = [0; 1024];
                let mut term = noline::builder::EditorBuilder::from_slice(&mut line_buf)
                    .build_async(&mut io)
                    .await
                    .map_err(|e| {
                        log::debug!("noline {e:?}");
                        ConnectionError
                    })?;
                match term.readline(">", &mut io).await {
                    Ok(prompt) => {
                        log::debug!("prompt {prompt}")
                    }
                    Err(_) => break,
                }
            }
            Ok::<_, ConnectionError>(())
        };
        let srv = async {
            let (mut rsock, mut wsock) = socket.split();
            srv.run(&mut rsock, &mut wsock).await?;
            Ok(())
        };
        (conn, session, srv).race().await
    }
}

#[derive(Deserialize)]
pub struct Config {
    port: u16,
    key: ed25519_dalek::SigningKey,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            port: 2222,
            key: TryFrom::try_from(&[0; 32]).expect("256bit long"),
        }
    }
}

impl From<sunset::Error> for ConnectionError {
    fn from(err: sunset::Error) -> Self {
        log::trace!("ssh error: {err:?}");
        ConnectionError
    }
}
