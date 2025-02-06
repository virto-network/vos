use crate::os::{self, net};
use serde::Deserialize;
use static_cell::StaticCell;
use zssh::{ed25519_dalek::SigningKey, Transport, TransportError};

use super::ConnectionError;

static PACKET_BUF: StaticCell<[u8; 1024]> = StaticCell::new();

pub type Port = Transport<'static, Ssh>;

impl super::SystemPort for Port {
    type Cfg = Config;
    type Error = TransportError<Ssh>;

    async fn configure(cfg: Option<Self::Cfg>) -> Self {
        let cfg = cfg.unwrap_or_default();
        let (_, socket) = net::listen(cfg.port).await.expect("tcp listen");
        Transport::new(PACKET_BUF.init([0u8; 1024]), Ssh::new(cfg, socket))
    }

    async fn accept_connection(&mut self) -> Result<os::Pipe, Self::Error> {
        let _c = self.accept().await?;
        Ok(os::Pipe::new())
    }
}

#[derive(Deserialize)]
pub struct Config {
    pk: [u8; 32],
    port: u16,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            pk: [0; 32],
            port: 2222,
        }
    }
}

pub struct Ssh {
    socket: net::Socket,
    rng: os::Rng,
    sk: zssh::SecretKey,
}

impl Ssh {
    fn new(cfg: Config, socket: net::Socket) -> Self {
        let sk = zssh::SecretKey::Ed25519 {
            secret_key: SigningKey::from_bytes(&cfg.pk),
        };
        Ssh {
            socket,
            rng: todo!(),
            sk,
        }
    }
}

impl zssh::Behavior for Ssh {
    type Command = ();
    type Random = os::Rng;
    type Stream = net::Socket;
    type User = ();
    fn stream(&mut self) -> &mut Self::Stream {
        &mut self.socket
    }

    fn random(&mut self) -> &mut Self::Random {
        &mut self.rng
    }

    fn host_secret_key(&self) -> &zssh::SecretKey {
        &self.sk
    }

    fn allow_user(&mut self, username: &str, auth_method: &zssh::AuthMethod) -> Option<Self::User> {
        let zssh::AuthMethod::PublicKey(pk) = auth_method else {
            return None;
        };
        Some(())
    }

    fn parse_command(&mut self, command: &str) -> Self::Command {
        todo!()
    }
}

impl From<TransportError<Ssh>> for ConnectionError {
    fn from(err: TransportError<Ssh>) -> Self {
        log::trace!("ssh error: {err:?}");
        ConnectionError
    }
}
