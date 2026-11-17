// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How the facility reaches its spaces (VOS's `light-node.md` §6.2, §6.5):
//! one `vos_light::tor::Client` for the process, every request under its
//! purpose, its own circuit and SSH key.
//!
//! - **Tor for every space** [E22]: each space's routes are its pinned
//!   onions, the clearnet port of the gateway it was enrolled through (if
//!   it pinned that port's host key) and whether it declared itself
//!   onion-only. Only key-signed calls may take the clearnet, and only for
//!   a space the user opted out of Tor after the plain warning
//!   ([`OPT_OUT_WARNING`]); a proof, a read that prepares one, the
//!   personal agent's and `Homes`' traffic never do (`vos_light::route`).
//! - **What is kept** beside the enrollments ([`FILE`]): each space's
//!   onion set as its registrar last served it, the user's opt-out, and
//!   the bridges pasted in the chrome. A space's enrollment pins its
//!   first set; a refresh's replaces it.
//! - **One arti a process** ([`Arti`]): its state in the app's private
//!   files, its bridges replaced by building it anew.
//! - **What a run read and wrote** ([`Count`]): every stream of the
//!   client's dial counts its bytes, so the background job's runs say what
//!   they cost whatever carried them.
//! - **A gateway spelled another way** ([`Net::onion_pinned`]): a host key
//!   a space pinned to its onion is that space's gateway however its name
//!   is written, so s4 never reaches it over the clearnet itself.
//! - **The rendezvous an hour** ([`RENDEZVOUS`]): the client's tally of
//!   the onion connections it opened, in the foreground and in the
//!   background, written beside the enrollments for PG5's bound and
//!   counted in again when the process starts anew.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use vos_abi::{Decode as _, Encode as _};
use vos_light::route::{Clearnet, Purpose, Refused, Routes};
use vos_light::tor::{BootstrapError, Circuit, Client, Config, Dial, Dialing, Registrar, Target};
use vos_light::tor::{Hour, Tor, TorConfig};
use vos_wire::credentials::Onion;

use crate::enrollment::{create_private, write_private};

pub use vos_light::route::OPT_OUT_WARNING;
pub use vos_light::tor::SpaceId;

/// The routes' file, beside the enrollments.
pub const FILE: &str = "routes.state";

/// The client's rendezvous, an hour a line, beside the enrollments.
pub const RENDEZVOUS: &str = "rendezvous.txt";

/// The same hours encoded, counted in again when the process starts anew.
const RENDEZVOUS_KEPT: &str = "rendezvous.state";

/// A space's routes as kept: its onion set, and the user's opt-out.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Kept {
    /// Each onion's key and its SSH host key, in hex.
    onions: Vec<(String, String)>,
    opted_out: bool,
    /// When the registrar's set was last read, by the device's clock.
    onions_ms: u64,
}

/// How often a space's onion set is read again from its registrar.
pub const ONIONS_EVERY_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// By the space's id, in hex.
    spaces: BTreeMap<String, Kept>,
    bridges: Vec<String>,
}

/// What a space pins: its onions, the gateway's clearnet port with its
/// host key if enrollment pinned one, and whether it is onion-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pinned {
    pub onions: Vec<Onion>,
    pub clearnet: Option<Clearnet>,
    pub onion_only: bool,
}

/// The contract's onions as the light node takes them.
pub fn onions(of: &[s4_credential_contract::Onion]) -> Vec<Onion> {
    of.iter()
        .map(|onion| Onion {
            key: onion.key,
            ssh_host_key: onion.ssh_host_key,
        })
        .collect()
}

fn onion_row(onion: &Onion) -> (String, String) {
    (hex::encode(onion.key), hex::encode(onion.ssh_host_key))
}

fn onion_of((key, ssh): &(String, String)) -> Option<Onion> {
    let decode = |text: &String| hex::decode(text).ok()?.try_into().ok();
    Some(Onion {
        key: decode(key)?,
        ssh_host_key: decode(ssh)?,
    })
}

/// The bytes the client's streams read and wrote.
#[derive(Clone, Default)]
pub struct Count {
    down: Arc<AtomicU64>,
    up: Arc<AtomicU64>,
}

impl Count {
    /// The bytes read, and written, so far.
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.down.load(Ordering::Relaxed),
            self.up.load(Ordering::Relaxed),
        )
    }
}

/// A dial whose every stream counts its bytes into one [`Count`].
struct Counted {
    dial: Arc<dyn Dial>,
    count: Count,
}

impl Dial for Counted {
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing {
        let (dialing, count) = (self.dial.dial(target, circuit), self.count.clone());
        Box::pin(async move {
            let stream = dialing.await?;
            Ok(Box::new(Counting { stream, count }) as vos_light::tor::Stream)
        })
    }

    fn set_dormant(&self, dormant: bool) {
        self.dial.set_dormant(dormant);
    }
}

struct Counting {
    stream: vos_light::tor::Stream,
    count: Count,
}

impl AsyncRead for Counting {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.stream).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        self.count.down.fetch_add(read, Ordering::Relaxed);
        polled
    }
}

impl AsyncWrite for Counting {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = polled {
            self.count.up.fetch_add(written as u64, Ordering::Relaxed);
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// The process's arti, built anew when the bridges change: every dial
/// goes through the one built last.
pub struct Arti {
    directory: PathBuf,
    tor: RwLock<Option<Tor>>,
    /// Whether the client is dormant, for an arti built anew.
    dormant: std::sync::atomic::AtomicBool,
}

impl Arti {
    /// Arti with its state and cache under `directory` (made `0700`),
    /// through `bridges` if any: built, not yet bootstrapped. On the
    /// runtime the client runs on.
    pub fn new(directory: PathBuf, bridges: &[String]) -> Result<Arc<Self>, BootstrapError> {
        let arti = Arc::new(Self {
            directory,
            tor: RwLock::new(None),
            dormant: Default::default(),
        });
        arti.rebuild(bridges)?;
        Ok(arti)
    }

    fn rebuild(&self, bridges: &[String]) -> Result<(), BootstrapError> {
        let tor = self.build(bridges)?;
        *self.tor.write().unwrap_or_else(|e| e.into_inner()) = Some(tor);
        Ok(())
    }

    fn build(&self, bridges: &[String]) -> Result<Tor, BootstrapError> {
        let mut config = TorConfig::new(&self.directory);
        config.bridges = bridges.to_vec();
        let tor = Tor::new(&config)?;
        // One built while the app is in the background starts dormant.
        tor.set_dormant(self.dormant.load(Ordering::SeqCst));
        Ok(tor)
    }

    /// An arti through `bridges`, bootstrapped, then the one every dial
    /// goes through; on a failure the one built before stays.
    async fn replace(&self, bridges: &[String]) -> Result<(), BootstrapError> {
        let candidate = self.build(bridges)?;
        candidate.bootstrap().await?;
        *self.tor.write().unwrap_or_else(|e| e.into_inner()) = Some(candidate);
        Ok(())
    }

    fn current(&self) -> Option<Tor> {
        self.tor.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Bootstrap the arti built last: its failure named (a wrong clock, a
    /// bridge that does not answer, a network that blocks Tor).
    pub async fn bootstrap(&self) -> Result<(), BootstrapError> {
        match self.current() {
            Some(tor) => tor.bootstrap().await,
            None => Err(BootstrapError::Tor("not built".into())),
        }
    }
}

impl Dial for Arti {
    fn dial(&self, target: &Target, circuit: Circuit) -> Dialing {
        match self.current() {
            Some(tor) => tor.dial(target, circuit),
            None => Box::pin(async { Err(io::Error::other("Tor is not built")) }),
        }
    }

    fn set_dormant(&self, dormant: bool) {
        self.dormant.store(dormant, Ordering::SeqCst);
        if let Some(tor) = self.current() {
            tor.set_dormant(dormant);
        }
    }
}

/// The facility's client of its spaces, and what it keeps of their routes.
pub struct Net {
    client: Client,
    /// What the client dials through, for a stream of the client's own.
    dial: Arc<dyn Dial>,
    /// The space a spare connection is kept for.
    spare: Mutex<Option<SpaceId>>,
    count: Count,
    file: PathBuf,
    state: Mutex<State>,
    arti: Option<Arc<Arti>>,
    /// Every space whose routes were pinned.
    pinned: Mutex<std::collections::BTreeSet<SpaceId>>,
}

/// Why a request got no answer, as the chrome is told.
pub type NetError = String;

impl Net {
    /// The client dialling through `dial`, its routes kept under
    /// `directory`. Made on the runtime it runs on.
    pub fn new(dial: Arc<dyn Dial>, directory: &Path) -> Self {
        Self::with(dial, directory, None)
    }

    /// The client over `arti`.
    pub fn over(arti: Arc<Arti>, directory: &Path) -> Self {
        Self::with(Arc::clone(&arti) as Arc<dyn Dial>, directory, Some(arti))
    }

    fn with(dial: Arc<dyn Dial>, directory: &Path, arti: Option<Arc<Arti>>) -> Self {
        let count = Count::default();
        let counted = Arc::new(Counted {
            dial,
            count: count.clone(),
        });
        let file = directory.join(FILE);
        let state = std::fs::read_to_string(&file)
            .ok()
            .and_then(|text| toml::from_str(&text).ok())
            .unwrap_or_default();
        let client = Client::new(Arc::clone(&counted) as Arc<dyn Dial>, Config::default());
        let kept = std::fs::read(directory.join(RENDEZVOUS_KEPT)).ok();
        if let Some(hours) = kept.and_then(|bytes| Vec::<Hour>::decode_exact(&bytes)) {
            client.restore_opened(&hours);
        }
        Self {
            client,
            dial: counted,
            spare: Mutex::new(None),
            count,
            file,
            state: Mutex::new(state),
            arti,
            pinned: Mutex::default(),
        }
    }

    /// The bridges kept, which the process's arti is built with.
    pub fn bridges_kept(directory: &Path) -> Vec<String> {
        std::fs::read_to_string(directory.join(FILE))
            .ok()
            .and_then(|text| toml::from_str::<State>(&text).ok())
            .map(|state| state.bridges)
            .unwrap_or_default()
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn keep(&self, state: &State) -> Result<(), NetError> {
        let text = toml::to_string(state).map_err(|error| error.to_string())?;
        if let Some(directory) = self.file.parent() {
            create_private(directory)?;
        }
        write_private(&self.file, text.as_bytes())
    }

    /// A stream to the onion service at `address`, `port`, on a circuit of
    /// its own: the s4 session's, to a gateway's onion.
    pub async fn onion_stream(
        &self,
        address: &str,
        port: u16,
    ) -> io::Result<vos_light::tor::Stream> {
        if vos_light::tor::onion_key(address).is_none() {
            return Err(io::Error::other("not an onion service's address"));
        }
        let target = Target::Onion {
            address: address.to_ascii_lowercase(),
            port,
        };
        self.dial.dial(&target, Circuit::new()).await
    }

    /// The client, for the requests the light node's flows make.
    pub fn client(&self) -> &Client {
        &self.client
    }

    pub fn count(&self) -> &Count {
        &self.count
    }

    /// `space`'s routes from what it pins, the onion set a refresh kept in
    /// place of the pinned one, and the user's opt-out re-applied.
    pub fn pin(&self, space: SpaceId, pinned: Pinned) {
        let kept = self.state().spaces.get(&hex::encode(space)).cloned();
        let mut routes = Routes::new(pinned.onions, pinned.clearnet, pinned.onion_only);
        if let Some(kept) = kept {
            let onions: Vec<Onion> = kept.onions.iter().filter_map(onion_of).collect();
            if !onions.is_empty() {
                routes.onions = onions;
            }
            if kept.opted_out {
                // Refused for an onion-only space or one with no clearnet
                // port: Tor then stays.
                let _ = routes.opt_out();
            }
        }
        self.client.set_space(space, routes);
        self.pinned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(space);
    }

    /// A space whose routes take its onion and which pinned `host_key` for
    /// its gateway, at an onion's port 22 or at the clearnet port it was
    /// enrolled through: s4's own connection to a gateway presenting that
    /// key, however its name or port is spelled, would carry over the
    /// clearnet what the space's routes keep on Tor.
    pub fn onion_pinned(&self, host_key: &[u8; 32]) -> Option<SpaceId> {
        let pinned = self
            .pinned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        pinned.into_iter().find(|space| {
            self.client.routes(space).is_some_and(|routes| {
                !routes.opted_out()
                    && !routes.onions.is_empty()
                    && (routes
                        .onions
                        .iter()
                        .any(|onion| onion.ssh_host_key == *host_key)
                        || routes
                            .clearnet
                            .as_ref()
                            .is_some_and(|clearnet| clearnet.ssh_host_key == *host_key))
            })
        })
    }

    /// The app came to the foreground, or left it: the client counts what
    /// it opens from now on as the foreground's, or the background's.
    pub fn set_foreground(&self, foreground: bool) {
        self.client.set_foreground(foreground);
    }

    /// The client's tally, an hour a line, written to [`RENDEZVOUS`].
    pub fn keep_rendezvous(&self) {
        let Some(directory) = self.file.parent() else {
            return;
        };
        let hours = self.client.opened();
        let lines: String = hours.iter().map(|hour| format!("{hour}\n")).collect();
        let _ = write_private(&directory.join(RENDEZVOUS_KEPT), &hours.encode());
        let _ = write_private(&directory.join(RENDEZVOUS), lines.as_bytes());
    }

    /// Send `request` to `space` under `purpose`: its answer's body.
    pub async fn request(
        &self,
        space: SpaceId,
        purpose: Purpose,
        request: &[u8],
    ) -> Result<Vec<u8>, NetError> {
        self.client
            .request(space, purpose, request)
            .await
            .map(|(_, body)| body)
            .map_err(|error| error.to_string())
    }

    /// Opt `space`'s key-signed calls out of Tor, the chrome having shown
    /// [`OPT_OUT_WARNING`]; or back on Tor. Kept.
    pub fn opt_out(&self, space: SpaceId, out: bool) -> Result<(), Refused> {
        let mut routes = self.client.routes(&space).ok_or(Refused::UnknownSpace)?;
        if out {
            routes.opt_out()?;
        } else {
            routes.opt_in();
        }
        let opted_out = routes.opted_out();
        self.client.set_space(space, routes);
        let mut state = self.state();
        state
            .spaces
            .entry(hex::encode(space))
            .or_default()
            .opted_out = opted_out;
        let _ = self.keep(&state);
        Ok(())
    }

    /// Whether the user opted `space` out of Tor.
    pub fn opted_out(&self, space: &SpaceId) -> bool {
        self.client
            .routes(space)
            .is_some_and(|routes| routes.opted_out())
    }

    /// The registrar's current onion set for `space`, read through its
    /// pinned set, kept in place of the pinned one.
    pub async fn refresh_onions(
        &self,
        space: SpaceId,
        registrar: &Registrar,
    ) -> Result<Vec<Onion>, NetError> {
        let onions = self
            .client
            .refresh_onions(space, registrar)
            .await
            .map_err(|error| error.to_string())?;
        let mut state = self.state();
        let kept = state.spaces.entry(hex::encode(space)).or_default();
        kept.onions = onions.iter().map(onion_row).collect();
        kept.onions_ms = crate::job::now_ms();
        self.keep(&state)?;
        Ok(onions)
    }

    /// The same once a day: whether it was read.
    pub async fn refresh_onions_due(
        &self,
        space: SpaceId,
        registrar: &Registrar,
        now_ms: u64,
    ) -> Result<bool, NetError> {
        let last = self
            .state()
            .spaces
            .get(&hex::encode(space))
            .map_or(0, |kept| kept.onions_ms);
        if now_ms.saturating_sub(last) < ONIONS_EVERY_MS {
            return Ok(false);
        }
        self.refresh_onions(space, registrar).await.map(|_| true)
    }

    /// Dormant (the app in the background, no job running) or awake.
    pub fn set_dormant(&self, dormant: bool) {
        self.client.set_dormant(dormant);
    }

    /// Keep a spare connection for `space`'s next proven call: the space
    /// the user is signed in to.
    pub fn keep_spare(&self, space: SpaceId) {
        *self.spare.lock().unwrap_or_else(|e| e.into_inner()) = Some(space);
        self.client.keep_spare(Some(space));
    }

    /// No spare for `space` any more: the last session there closed. A
    /// spare kept for another space stays.
    pub fn drop_spare(&self, space: SpaceId) {
        let mut spare = self.spare.lock().unwrap_or_else(|e| e.into_inner());
        if *spare == Some(space) {
            *spare = None;
            self.client.keep_spare(None);
        }
    }

    /// The bridges pasted in the chrome: arti built anew through them
    /// (none: the public relays), bootstrapped, and kept once it is.
    pub async fn bridges(&self, lines: Vec<String>) -> Result<(), String> {
        for line in &lines {
            vos_light::tor::bridge(line).map_err(|error| error.to_string())?;
        }
        let arti = self.arti.as_ref().ok_or("this facility does not run Tor")?;
        arti.replace(&lines)
            .await
            .map_err(|error| error.to_string())?;
        let mut state = self.state();
        state.bridges = lines;
        self.keep(&state)
    }

    /// Bootstrap the process's arti, if it runs one.
    pub async fn bootstrap(&self) -> Result<(), String> {
        match &self.arti {
            Some(arti) => arti.bootstrap().await.map_err(|error| error.to_string()),
            None => Ok(()),
        }
    }
}
