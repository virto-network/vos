//! The onion's port (`light-node.md` §6.1), hosted by arti in process
//! ([`crate::onion`]): its own SSH server (an [`App`]'s screens and the
//! `vos-api` subsystem), served the onion's streams with their circuits'
//! addresses, marking onion, counting each circuit as an address and
//! capping its calls.

use std::sync::Arc;

use vos_api::Mark;

use crate::Gateway;
use crate::caps::Caps;
use crate::circuits::{Circuits, Onion, OnionListener};
use crate::config::{self, Config};
use crate::limits::Limits;
use crate::ssh::App;

/// The onion's server, taking the streams handed to [`Front::onion`].
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
/// describes, in front of `gateway`, on the runtime: its SSH server,
/// serving `app`'s screens as the gateway's SSH port does, marked onion.
/// The file must name an SSH port.
pub fn front(
    config: &Config,
    onion: &config::Onion,
    gateway: Arc<Gateway>,
    app: &dyn App,
) -> Result<Front, String> {
    let circuits = Circuits::new(onion.per_circuit());
    let limits = Limits::new(onion.limits());
    let caps = Caps::new(onion.caps());
    let (front, listener) = Onion::new(Arc::clone(&circuits));
    let tasks = vec![ssh_server(config, &gateway, &limits, &caps, app, listener)?];
    Ok(Front {
        onion: front,
        circuits,
        caps,
        tasks,
    })
}

/// The onion `onion` of the gateway the file `config` describes, hosted by
/// arti in front of `gateway`, on the runtime, its SSH port serving
/// `app`'s screens.
pub async fn onion(
    config: &Config,
    onion: &config::Onion,
    gateway: Arc<Gateway>,
    app: &dyn App,
) -> Result<Served, String> {
    let front = front(config, onion, gateway, app)?;
    let hosted = crate::onion::launch(onion, Arc::clone(&front.onion)).await?;
    Ok(Served { front, hosted })
}

/// The onion's own SSH server, taking the streams `listener` hands it.
fn ssh_server(
    config: &Config,
    gateway: &Arc<Gateway>,
    limits: &Arc<Limits>,
    caps: &Arc<Caps>,
    app: &dyn App,
    listener: OnionListener,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let port = crate::ssh::Port::new(Mark::Onion, Arc::clone(limits), Arc::clone(caps))
        .with_connections(
            config
                .onion
                .as_ref()
                .and_then(|onion| onion.ssh_connections),
        );
    crate::ssh::serve(config, Arc::clone(gateway), port, app, listener)
}
