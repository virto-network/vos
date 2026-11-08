//! The onion's ports (`light-node.md` §6.1): its own HTTP server and, with
//! an SSH port, its own SSH port on a loopback listener, both marking
//! onion, counting each circuit as an address and capping its calls; their
//! streams from arti in process (the `tor` feature) or from a C tor beside
//! the gateway ([`crate::circuits::sidecar`]).

use std::net::SocketAddr;
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
    /// The onion's SSH port's loopback address, if it serves SSH.
    pub ssh: Option<SocketAddr>,
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
/// its `vos-api` subsystem and no demo screens, whose host service would
/// answer a connection no stream carries.
pub async fn onion(
    config: &Config,
    onion: &config::Onion,
    gateway: Arc<Gateway>,
) -> Result<Served, String> {
    let circuits = Circuits::new(onion.per_circuit());
    let limits = Limits::new(onion.limits());
    let caps = Caps::new(onion.caps());
    let mut tasks = Vec::new();
    let ssh = ssh(config, &gateway, &circuits, &limits, &caps, &mut tasks)?;
    let (front, listener) = Onion::new(Arc::clone(&circuits), ssh);
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
            if port == circuits::SSH && ssh.is_none() {
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
            ssh,
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
            ssh,
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

/// The onion's own SSH port on a loopback listener, if the file names an
/// SSH port: its address.
fn ssh(
    config: &Config,
    gateway: &Arc<Gateway>,
    circuits: &Arc<Circuits>,
    limits: &Arc<Limits>,
    caps: &Arc<Caps>,
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
) -> Result<Option<SocketAddr>, String> {
    #[cfg(feature = "ssh")]
    if config.ssh.is_some() {
        use crate::ssh::{Peers, Port};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| {
                listener.set_nonblocking(true)?;
                tokio::net::TcpListener::from_std(listener)
            })
            .map_err(|error| format!("the onion's SSH port: {error}"))?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let port = Port {
            mark: Mark::Onion,
            limits: Arc::clone(limits),
            caps: Arc::clone(caps),
            bodies: crate::caps::bodies(),
            peers: Peers::Carried(Arc::clone(circuits)),
        };
        let path = config
            .ssh_host_key
            .clone()
            .ok_or("an SSH port needs ssh_host_key")?;
        let host_key = s4_server::load_or_create_host_key(&path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let server = crate::ssh::server(host_key, Arc::clone(gateway), port, None);
        tasks.push(tokio::spawn(async move {
            if let Err(error) = server.serve_on(listener).await {
                tracing::warn!(%error, "the onion's SSH port ended");
            }
        }));
        return Ok(Some(address));
    }
    let _ = (config, gateway, circuits, limits, caps, tasks);
    Ok(None)
}
