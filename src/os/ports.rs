///! Ports are well known system services that expose default network connectity for applications
///! allowing external clients using common protocols to start an authenticated session
/// to interact with installed scripts and applications
use super::shell;
use embassy_executor::SendSpawner;
use futures_concurrency::future::Race as _;
use serde::Deserialize;

#[cfg(feature = "std")]
pub mod ssh;
// TODO
// #[cfg(feature = "std")]
// pub mod http;
// #[cfg(feature = "web")]
// pub mod web;

#[embassy_executor::task]
pub async fn handle_connections(s: SendSpawner, ports: Config) {
    let mut ports = ports.configure().await;
    // loop {
    let io = ports.next_connection().await.expect("connected");
    if let Err(e) = s.spawn(shell::new_session(io)) {
        log::warn!("Couldn't connect shell. {:?}", e);
    }
    // }
}

/// A system service that connects clients to a shell that runs applications
pub trait SystemPort {
    type Cfg: for<'de> Deserialize<'de> + Default;
    type Error: Into<ConnectionError>;

    async fn configure(cfg: Option<Self::Cfg>) -> Self;
    async fn accept_connection(&mut self) -> Result<super::Pipe, Self::Error>;
}

#[derive(Debug)]
pub struct ConnectionError;

type CfgFor<T> = Option<<T as SystemPort>::Cfg>;

#[derive(Deserialize, Default)]
pub struct Config {
    pub ssh: CfgFor<ssh::Port>,
    // pub http: CfgFor<http::Connector>,
}
impl Config {
    async fn configure(self) -> Ports {
        Ports {
            ssh: ssh::Port::configure(self.ssh).await,
        }
    }
}

pub struct Ports {
    ssh: ssh::Port,
}
impl Ports {
    async fn next_connection(&mut self) -> Result<super::Pipe, ConnectionError> {
        (self.ssh.accept_connection(),)
            .race()
            .await
            .map_err(ConnectionError::from)
    }
}
