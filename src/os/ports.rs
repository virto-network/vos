///! Ports are well known system services that expose default network connectity for applications
///! allowing external clients using common protocols to start an authenticated session
/// to interact with installed scripts and applications
use super::shell;
use embassy_executor::SendSpawner;
use futures_concurrency::future::Race as _;
use serde::Deserialize;

#[cfg(feature = "port-http")]
pub mod http;
#[cfg(feature = "port-ssh")]
pub mod ssh;
// #[cfg(feature = "web")]
// pub mod web;

#[embassy_executor::task]
pub async fn handle_connections(s: SendSpawner, ports: Config) {
    let mut ports = ports.configure().await;
    loop {
        if let Err(e) = ports.next_connection().await {
            log::warn!("{e:?}");
            continue;
        };
        if let Err(e) = s.spawn(shell::new_session(super::Pipe::new())) {
            log::warn!("Couldn't connect shell. {:?}", e);
        }
    }
}

/// A system service that connects clients to a shell that runs applications
pub trait SystemPort {
    type Cfg: for<'de> Deserialize<'de> + Default;
    type Error: Into<PortError>;

    async fn configure(cfg: Option<Self::Cfg>) -> Self;
    async fn accept_connection(&mut self) -> Result<(), Self::Error>;
}

// TODO
#[derive(Debug)]
pub struct PortError;

type CfgFor<T> = Option<<T as SystemPort>::Cfg>;

// TODO macro generated?

#[derive(Deserialize, Default)]
pub struct Config {
    #[cfg(feature = "port-ssh")]
    pub ssh: CfgFor<ssh::Port>,
    #[cfg(feature = "port-http")]
    pub http: CfgFor<http::Port>,
}
impl Config {
    async fn configure(self) -> Ports {
        Ports {
            #[cfg(feature = "port-ssh")]
            ssh: ssh::Port::configure(self.ssh).await,
            #[cfg(feature = "port-http")]
            http: http::Port::configure(self.http).await,
        }
    }
}

pub struct Ports {
    #[cfg(feature = "port-ssh")]
    ssh: ssh::Port,
    #[cfg(feature = "port-http")]
    http: http::Port,
}
impl Ports {
    async fn next_connection(&mut self) -> Result<(), PortError> {
        (
            core::future::pending::<Result<(), PortError>>(),
            #[cfg(feature = "port-ssh")]
            self.ssh.accept_connection(),
            #[cfg(feature = "port-http")]
            self.http.accept_connection(),
        )
            .race()
            .await
            .map_err(PortError::from)
    }
}
