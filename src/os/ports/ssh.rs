use crate::os::{self, net};
use core::str::FromStr;
use edge_net::nal::TcpAccept;
use serde::Deserialize;
use zssh::{ed25519_dalek::SigningKey, Transport, TransportError};

use super::ConnectionError;

const BUF_SIZE: usize = 16 * 1024;

pub struct Port {
    conn: net::Connection,
    key: [u8; 32],
}

impl super::SystemPort for Port {
    type Cfg = Config;
    type Error = TransportError<Ssh>;

    async fn configure(cfg: Option<Self::Cfg>) -> Self {
        let cfg = cfg.unwrap_or_default();
        let conn = net::bind(cfg.port).await.expect("bind ssh port");
        Self { conn, key: cfg.key }
    }

    async fn accept_connection(&mut self) -> Result<(), Self::Error> {
        let (addr, socket) = self.conn.accept().await.expect("tcp connect");
        log::trace!("connected to peer {addr}");
        let mut buf = [0u8; BUF_SIZE];
        let mut t = Transport::new(&mut buf, Ssh::new(&self.key, socket, os::rng().await));

        let mut chan = t.accept().await?;
        log::trace!("ssh client request {:?}", chan.request());
        match chan.request() {
            zssh::Request::Shell => {}
            zssh::Request::Exec(_) => {}
        }
        chan.write_all_stderr(b"not implemented yet\n").await?;
        chan.exit(1).await
    }
}

#[derive(Deserialize)]
pub struct Config {
    key: [u8; 32],
    port: u16,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            key: [0; 32],
            port: 2222,
        }
    }
}

pub struct Ssh {
    socket: net::Socket,
    sk: zssh::SecretKey,
    rng: os::Rng,
}

impl Ssh {
    fn new(pk: &[u8; 32], socket: net::Socket, rng: os::Rng) -> Self {
        let sk = zssh::SecretKey::Ed25519 {
            secret_key: SigningKey::from_bytes(&pk),
        };
        Ssh { socket, sk, rng }
    }
}

impl zssh::Behavior for Ssh {
    type Command = ();
    type Random = os::Rng;
    type Stream = net::Socket;
    type User = os::UserId;

    fn stream(&mut self) -> &mut Self::Stream {
        &mut self.socket
    }
    fn random(&mut self) -> &mut Self::Random {
        &mut self.rng
    }
    fn host_secret_key(&self) -> &zssh::SecretKey {
        &self.sk
    }
    fn server_id(&self) -> &'static str {
        "SSH-2.0-VOS_0.1"
    }
    fn allow_shell(&self) -> bool {
        true
    }

    fn allow_user(&mut self, username: &str, auth_method: &zssh::AuthMethod) -> Option<Self::User> {
        let zssh::AuthMethod::PublicKey(zssh::PublicKey::Ed25519 { public_key: pk }) = auth_method
        else {
            log::trace!("ssh connection without credentials");
            return None;
        };
        let user = os::UserId::from_str(username).ok()?;
        log::debug!("ssh {user} connecting with ed25519 {:?}", pk.as_bytes());
        Some(user)
    }

    fn parse_command(&mut self, command: &str) -> Self::Command {
        log::trace!("ssh parsing command {command}");
        ()
    }
}

impl From<TransportError<Ssh>> for ConnectionError {
    fn from(err: TransportError<Ssh>) -> Self {
        log::trace!("ssh error: {err:?}");
        ConnectionError
    }
}
