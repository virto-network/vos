//! The onion's ports (`light-node.md` §6.1), hosted by arti in process
//! ([`crate::onion`]): its own HTTP server and, with an SSH port, its own
//! SSH server (s4's screens, the demo's when the file names it, and the
//! `vos-api` subsystem), both served the onion's streams with their
//! circuits' addresses, marking onion, counting each circuit as an address
//! and capping its calls.

use std::sync::Arc;

use vos_api::Mark;

use crate::Gateway;
use crate::caps::Caps;
use crate::circuits::{Circuits, Onion, OnionListener};
use crate::config::{self, Config};
use crate::front::{self, Http};
use crate::limits::Limits;

/// The onion's servers, taking the streams handed to [`Front::onion`].
pub struct Front {
    pub onion: Arc<Onion>,
    pub circuits: Arc<Circuits>,
    pub caps: Arc<Caps>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Front {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// The onion, served: its servers and the service arti runs.
pub struct Served {
    pub front: Front,
    pub hosted: crate::onion::Hosted,
}

impl Drop for Served {
    fn drop(&mut self) {
        self.hosted.task.abort();
    }
}

/// The servers of the onion `onion` of the gateway the file `config`
/// describes, in front of `gateway`, on the runtime: SSH if the file names
/// an SSH port, as the gateway's SSH port serves it, its demo's claims
/// going as the app's key marked onion.
pub fn front(
    config: &Config,
    onion: &config::Onion,
    gateway: Arc<Gateway>,
) -> Result<Front, String> {
    let circuits = Circuits::new(onion.per_circuit());
    let limits = Limits::new(onion.limits());
    let caps = Caps::new(onion.caps());
    let (front, listener, ssh) = Onion::new(Arc::clone(&circuits), config.ssh.is_some());
    let mut tasks = Vec::new();
    if let Some(ssh) = ssh {
        tasks.push(ssh_server(config, &gateway, &limits, &caps, ssh)?);
    }
    let http = Http {
        tls: None,
        connections: config.connections.unwrap_or(1024),
        mark: Mark::Onion,
        caps: Arc::clone(&caps),
    };
    tasks.push(tokio::spawn(front::serve_on(
        gateway,
        limits,
        listener,
        http,
        std::future::pending(),
    )));
    Ok(Front {
        onion: front,
        circuits,
        caps,
        tasks,
    })
}

/// The onion `onion` of the gateway the file `config` describes, hosted by
/// arti in front of `gateway`, on the runtime.
pub async fn onion(
    config: &Config,
    onion: &config::Onion,
    gateway: Arc<Gateway>,
) -> Result<Served, String> {
    let front = front(config, onion, gateway)?;
    let hosted = crate::onion::launch(onion, Arc::clone(&front.onion)).await?;
    Ok(Served { front, hosted })
}

/// The onion's own SSH server, taking the streams `listener` hands it.
fn ssh_server(
    config: &Config,
    gateway: &Arc<Gateway>,
    limits: &Arc<Limits>,
    caps: &Arc<Caps>,
    listener: OnionListener,
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
