//! The onion's ports (`light-node.md` §6.1): its own HTTP server and, with
//! an SSH port, its own SSH server (s4's screens, when the file names the
//! demo, and the `vos-api` subsystem), both served the onion's streams
//! with their circuits' addresses, marking onion, counting each circuit as
//! an address and capping its calls; their streams from arti in process
//! (the `tor` feature) or from a C tor beside the gateway
//! ([`crate::circuits::sidecar`]).

use std::sync::Arc;

use vos_api::Mark;

use crate::Gateway;
use crate::caps::Caps;
use crate::circuits::{self, Circuits, Onion};
use crate::config::{self, Config};
use crate::front::{self, Http};
use crate::limits::Limits;

/// The onion's ports, served.
pub struct Served {
    pub circuits: Arc<Circuits>,
    pub caps: Arc<Caps>,
    /// The onion arti hosts, if it does.
    #[cfg(feature = "tor")]
    pub hosted: Option<crate::onion::Hosted>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Served {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        #[cfg(feature = "tor")]
        if let Some(hosted) = &self.hosted {
            hosted.task.abort();
        }
    }
}

/// Serve the onion `onion` of the gateway the file `config` describes, in
/// front of `gateway`, on the runtime: SSH if the file names an SSH port,
/// as the gateway's SSH port serves it, its demo's claims going as the
/// app's key marked onion.
pub async fn onion(
    config: &Config,
    onion: &config::Onion,
    gateway: Arc<Gateway>,
) -> Result<Served, String> {
    let circuits = Circuits::new(onion.per_circuit());
    let limits = Limits::new(onion.limits());
    let caps = Caps::new(onion.caps());
    let mut tasks = Vec::new();
    let ssh = cfg!(feature = "ssh") && config.ssh.is_some();
    let (front, listener, ssh_listener) = Onion::new(Arc::clone(&circuits), ssh);
    #[cfg(feature = "ssh")]
    if let Some(listener) = ssh_listener {
        tasks.push(ssh_server(config, &gateway, &limits, &caps, listener)?);
    }
    #[cfg(not(feature = "ssh"))]
    let _ = ssh_listener;
    let http = Http {
        tls: None,
        connections: config.connections.unwrap_or(1024),
        mark: Mark::Onion,
        caps: Arc::clone(&caps),
    };
    tasks.push(tokio::spawn(front::serve_on(
        Arc::clone(&gateway),
        limits,
        listener,
        http,
        std::future::pending(),
    )));
    if onion.sidecar() {
        for (address, port) in [
            (onion.sidecar_ssh, circuits::SSH),
            (onion.sidecar_http, circuits::HTTP),
        ] {
            let Some(address) = address else { continue };
            if !address.ip().is_loopback() {
                return Err(format!("{address}: a C tor's listener is a loopback one"));
            }
            if port == circuits::SSH && !ssh {
                return Err("sidecar_ssh needs the gateway's SSH port".into());
            }
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|error| format!("{address}: {error}"))?;
            tasks.push(tokio::spawn(circuits::sidecar::serve(
                Arc::clone(&front),
                listener,
                port,
            )));
        }
        return Ok(Served {
            circuits,
            caps,
            #[cfg(feature = "tor")]
            hosted: None,
            tasks,
        });
    }
    #[cfg(feature = "tor")]
    {
        let hosted = crate::onion::launch(onion, front).await?;
        Ok(Served {
            circuits,
            caps,
            hosted: Some(hosted),
            tasks,
        })
    }
    #[cfg(not(feature = "tor"))]
    {
        let _ = (front, tasks);
        Err("an onion in process needs a gateway built with the tor feature; or name a C tor's listeners (sidecar_ssh, sidecar_http)".into())
    }
}

/// The onion's own SSH server, taking the streams `listener` hands it.
#[cfg(feature = "ssh")]
fn ssh_server(
    config: &Config,
    gateway: &Arc<Gateway>,
    limits: &Arc<Limits>,
    caps: &Arc<Caps>,
    listener: circuits::OnionListener,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let port = crate::ssh::Port::new(
        Mark::Onion,
        Arc::clone(limits),
        Arc::clone(caps),
        crate::caps::bodies(),
    );
    let app = config
        .app_key
        .as_ref()
        .map(|path| config::seed(path))
        .transpose()?
        .map(|seed| {
            Arc::new(crate::app::AppClient::new(
                seed,
                Arc::clone(gateway),
                Mark::Onion,
            ))
        });
    crate::ssh::serve(config, Arc::clone(gateway), port, app, listener)
}
