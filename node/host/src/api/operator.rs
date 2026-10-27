//! Operator requests: an `Operated` envelope checked (its node, its key,
//! its expiry, its signature, its body), a command's nonce recorded once
//! and synced before it runs, then the command.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use vos_api::{Kind, Operated};
use vos_wire::batch::Admin;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{Create, Grant, Install, OperatorRefusal, Rejection, Replace, Response};

use super::{Api, decode};
use crate::calls::answer_of;
use crate::lock;
use crate::node::{Inner, ReplaceError};
use crate::signature::verify;
use crate::store::{Fjall, PersistMode};

/// How far past the node's time an operator request may be good.
pub(crate) const HORIZON_MS: u64 = 120_000;

/// The operator's key in the node's data directory: its seed, in hex,
/// readable by its owner only.
pub const OPERATOR_KEY: &str = "operator.key";
/// The operator key's public half, in hex, beside it: what the node reads
/// to list it.
pub const OPERATOR_PUB: &str = "operator.pub";

/// An operator's command, its body decoded.
pub(super) enum Command {
    Stats,
    Status(AgentId),
    CreateAgent(Create),
    CreateRepresentative(Create),
    Install(AgentId, Install),
    Replace(AgentId, Replace),
    Grant(AgentId, Grant),
    Reports(AgentId, bool),
}

/// A `Create` from an operator's body: an empty one is the default.
fn create(body: &[u8]) -> Result<Create, Response> {
    if body.is_empty() {
        Ok(Create::default())
    } else {
        decode(body)
    }
}

/// The command of `kind` that `body` holds.
pub(super) async fn parse(inner: &Inner, kind: Kind, body: Vec<u8>) -> Result<Command, Response> {
    Ok(match kind {
        Kind::Stats => decode::<()>(&body).map(|()| Command::Stats)?,
        Kind::Status => Command::Status(decode(&body)?),
        Kind::CreateAgent => Command::CreateAgent(create(&body)?),
        Kind::CreateRepresentative => Command::CreateRepresentative(create(&body)?),
        Kind::Install => {
            // A package may be large: decode it off the leaders' thread.
            let decoded = inner
                .offload(move || decode::<(AgentId, Install)>(&body))
                .await
                .ok_or(Response::Unavailable)??;
            Command::Install(decoded.0, decoded.1)
        }
        Kind::Replace => {
            let (agent, replace) = decode(&body)?;
            Command::Replace(agent, replace)
        }
        Kind::Grant => {
            let (agent, grant): (AgentId, Grant) = decode(&body)?;
            // No role is ever granted to a credential's origin: a guard
            // admits it.
            if grant.principal.is_credential() {
                return Err(Response::Rejected(Rejection::Malformed));
            }
            Command::Grant(agent, grant)
        }
        Kind::Reports => {
            let (agent, every) = decode(&body)?;
            Command::Reports(agent, every)
        }
        _ => return Err(Response::Rejected(Rejection::Malformed)),
    })
}

/// Run `command`.
pub(super) async fn run(inner: &Arc<Inner>, command: Command) -> Response {
    let created = |created: Result<AgentId, crate::CallError>| match created {
        Ok(agent) => Response::Created(agent),
        Err(error) => error.into(),
    };
    match command {
        Command::Stats => Response::Stats(inner.stats()),
        Command::Status(agent) => inner.replica_status(agent),
        Command::CreateAgent(create) => created(inner.create_agent(create.replicas).await),
        Command::CreateRepresentative(create) => {
            created(inner.create_representative(create.replicas).await)
        }
        Command::Install(agent, install) => answer_of(
            inner
                .install(agent, install.instance, install.elf, install.roles)
                .await,
        ),
        Command::Replace(agent, Replace { remove, add }) => {
            match inner.replace(agent, remove, add).await {
                Ok(replicas) => Response::Placed(replicas),
                Err(ReplaceError::Unplaced(why)) => Response::Unplaced(why),
                Err(ReplaceError::TimedOut) => Response::TimedOut,
                Err(ReplaceError::Call(error)) => error.into(),
            }
        }
        Command::Grant(agent, grant) => answer_of(inner.admin(agent, Admin::SetRole(grant)).await),
        Command::Reports(agent, every) => {
            answer_of(inner.admin(agent, Admin::ReportEveryWindow(every)).await)
        }
    }
}

/// An operator's command's nonce: its key, and the nonce.
type Held = ([u8; 32], [u8; 16]);

/// The operators' commands' nonces, by key and nonce, each until its
/// expiry and a horizon past it: a command whose nonce is recorded never
/// runs again, across restarts too, and a clock stepped back by up to the
/// horizon still finds it.
pub(crate) struct Nonces {
    store: Fjall,
    recorded: Mutex<HashMap<Held, u64>>,
    /// The most kept at once: past them, a command is answered `Busy`.
    most: usize,
}

/// Whether a nonce expiring at `expires` may be forgotten at `now`: once
/// `now` is past its expiry by more than the horizon. A clock stepped back
/// by up to the horizon still finds it, and refuses its request as a
/// replay rather than running it again.
fn may_forget(expires: u64, now: u64) -> bool {
    expires.saturating_add(HORIZON_MS) < now
}

/// Why a nonce was not recorded.
enum Unrecorded {
    Replayed,
    Full,
}

impl Nonces {
    /// The nonces `store` holds, less those it may forget by `now`.
    pub(crate) fn load(store: &Fjall, now: u64, most: usize) -> crate::store::Result<Self> {
        let mut recorded = HashMap::new();
        let mut batch = store.batch();
        let mut expired = false;
        for (key, nonce, expires) in store.operator_nonces()? {
            if may_forget(expires, now) {
                batch.operator_nonce(&key, &nonce, None);
                expired = true;
            } else {
                recorded.insert((key, nonce), expires);
            }
        }
        if expired {
            batch.commit(PersistMode::SyncAll)?;
        }
        Ok(Self {
            store: store.clone(),
            recorded: Mutex::new(recorded),
            most,
        })
    }

    /// Record `key`'s `nonce` until `expires`, if it is not recorded:
    /// one step, so two copies of one request cannot both pass. Past the
    /// most kept, those it may forget by `now` go first; they are
    /// returned, to delete.
    fn insert(
        &self,
        key: [u8; 32],
        nonce: [u8; 16],
        expires: u64,
        now: u64,
    ) -> Result<Vec<Held>, Unrecorded> {
        let mut recorded = lock(&self.recorded);
        if recorded.contains_key(&(key, nonce)) {
            return Err(Unrecorded::Replayed);
        }
        let mut forgotten = Vec::new();
        if recorded.len() >= self.most {
            recorded.retain(|held, expires| {
                let keep = !may_forget(*expires, now);
                if !keep {
                    forgotten.push(*held);
                }
                keep
            });
        }
        if recorded.len() >= self.most {
            return Err(Unrecorded::Full);
        }
        recorded.insert((key, nonce), expires);
        Ok(forgotten)
    }
}

impl Api {
    /// An operator's request in its envelope: checked, its nonce recorded
    /// for a command, then run.
    pub(super) async fn operated(&self, kind: Kind, body: Vec<u8>) -> Response {
        match self.admit(kind, body).await {
            Ok(command) => run(&self.inner, command).await,
            Err(answer) => answer,
        }
    }

    async fn admit(&self, kind: Kind, body: Vec<u8>) -> Result<Command, Response> {
        let refused = |refusal| Response::Rejected(Rejection::Operator(refusal));
        // The envelope's fixed fields first, from its prefix: a body is
        // decoded, and its message built, only for a listed key's request
        // to this node within its time, and off the node's thread.
        let Some(prefix) = body.get(..88) else {
            return Err(Response::Rejected(Rejection::Malformed));
        };
        if prefix[..32] != self.inner.node_id.0 {
            return Err(refused(OperatorRefusal::OtherNode));
        }
        let key: [u8; 32] = prefix[32..64].try_into().expect("32 bytes");
        if !self.operators.contains(&key) {
            return Err(Response::Rejected(Rejection::Unauthorized));
        }
        let expires_ms = u64::from_le_bytes(prefix[80..88].try_into().expect("8 bytes"));
        let now = (self.inner.clock)();
        if expires_ms < now || expires_ms > now.saturating_add(HORIZON_MS) {
            return Err(refused(OperatorRefusal::Expiry { now }));
        }
        let checked = self
            .inner
            .offload({
                let stats = Arc::clone(&self.inner.stats);
                move || {
                    let operated: Operated = decode(&body)?;
                    let started = Instant::now();
                    let signed =
                        verify(&operated.key, &operated.message(kind), &operated.signature);
                    stats.verify.took(started.elapsed());
                    match signed {
                        true => Ok(operated),
                        false => Err(Response::Rejected(Rejection::BadSignature)),
                    }
                }
            })
            .await;
        let operated = match checked {
            Some(checked) => checked?,
            None => return Err(Response::Unavailable),
        };
        let command = parse(&self.inner, kind, operated.body).await?;
        if kind.records_nonce() {
            let now = (self.inner.clock)();
            let forgotten = match self
                .nonces
                .insert(key, operated.nonce, operated.expires_ms, now)
            {
                Ok(forgotten) => forgotten,
                Err(Unrecorded::Replayed) => return Err(refused(OperatorRefusal::Replayed)),
                Err(Unrecorded::Full) => return Err(Response::Busy),
            };
            // Synced before the command runs: a command that ran is refused
            // after a restart.
            let store = self.nonces.store.clone();
            let (nonce, expires) = (operated.nonce, operated.expires_ms);
            let written = self
                .inner
                .offload(move || {
                    let mut batch = store.batch();
                    for (key, nonce) in &forgotten {
                        batch.operator_nonce(key, nonce, None);
                    }
                    batch.operator_nonce(&key, &nonce, Some(expires));
                    batch.commit(PersistMode::SyncAll)
                })
                .await;
            if !matches!(written, Some(Ok(()))) {
                return Err(Response::Unavailable);
            }
        }
        Ok(command)
    }
}

/// The public key of the operator key in `data`: made at a node's first
/// start, with its public half beside it, which later starts read alone.
pub(crate) fn operator_key(data: &Path) -> Result<[u8; 32], String> {
    let public = data.join(OPERATOR_PUB);
    let failed = |path: &Path, error: std::io::Error| format!("{}: {error}", path.display());
    match std::fs::read_to_string(&public) {
        Ok(text) => {
            return crate::hex32(text.trim())
                .ok_or_else(|| format!("{}: not 64 hex digits", public.display()));
        }
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            return Err(failed(&public, error));
        }
        Err(_) => {}
    }
    let secret_path = data.join(OPERATOR_KEY);
    let secret = match std::fs::read_to_string(&secret_path) {
        Ok(text) => crate::hex32(text.trim())
            .ok_or_else(|| format!("{}: not 64 hex digits", secret_path.display()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let secret = crate::random();
            crate::node::write_private(&secret_path, &secret)
                .map_err(|error| failed(&secret_path, error))?;
            secret
        }
        Err(error) => return Err(failed(&secret_path, error)),
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&secret)
        .verifying_key()
        .to_bytes();
    // Whole or not at all: written beside it, then moved into place.
    let mut name = public.as_os_str().to_owned();
    name.push(".new");
    let written = std::path::PathBuf::from(name);
    std::fs::write(&written, hex::encode(key))
        .and_then(|()| std::fs::rename(&written, &public))
        .map_err(|error| failed(&public, error))?;
    Ok(key)
}

/// The keys a node lists: its configured operators, and its local key
/// unless told not to.
pub(crate) fn listed(
    data: &Path,
    operators: &[[u8; 32]],
    local: bool,
) -> Result<HashSet<[u8; 32]>, String> {
    let mut listed: HashSet<[u8; 32]> = operators.iter().copied().collect();
    if local {
        listed.insert(operator_key(data)?);
    }
    Ok(listed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_recorded_once_and_the_store_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let nonces = Nonces::load(&store, 0, 2).unwrap();
        assert!(nonces.insert([1; 32], [1; 16], 10, 0).is_ok());
        assert!(matches!(
            nonces.insert([1; 32], [1; 16], 10, 0),
            Err(Unrecorded::Replayed)
        ));
        assert!(nonces.insert([2; 32], [1; 16], 20, 0).is_ok());
        assert!(matches!(
            nonces.insert([3; 32], [1; 16], 30, 5),
            Err(Unrecorded::Full)
        ));
        // Expired, one is still kept for the horizon: a clock stepped back
        // within it refuses the replay.
        assert!(matches!(
            nonces.insert([3; 32], [1; 16], 30, 10 + HORIZON_MS),
            Err(Unrecorded::Full)
        ));
        // Past it, it is forgotten for a new one.
        let forgotten = nonces
            .insert([3; 32], [1; 16], 30, 11 + HORIZON_MS)
            .ok()
            .unwrap();
        assert_eq!(forgotten, [([1; 32], [1; 16])]);
    }
}
