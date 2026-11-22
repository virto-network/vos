// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the device keeps of an enrollment: the secret source's reference,
//! what the user confirmed in the chrome (the space's handle, the space, its
//! agents and the methods the device may prove for), and the member digest
//! the space's tree holds, public, so the path can be kept from a session's
//! start without asking the source, and the gateway it was made through, so
//! a sync reaches it with no session open; keyed by the verified SSH host
//! and the application that asked, a row each of the facility's database
//! ([`crate::kept`]). No secret, no source output and no proof is ever
//! written. Its types are the facility's: s4's are converted at the
//! boundary ([`Enrollment::pins`], the enroll).

use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};
use vos_abi::{Decode, Encode};

use crate::kept::Kept;
use crate::source::Reference;

pub use vos_wire::credentials::Onion;

/// A space's agent: its id and the identity calls to it are signed for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Agent {
    pub agent: u32,
    pub identity: [u8; 32],
}

/// An actor's place: its agent and instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Location {
    pub agent: u32,
    pub instance: u32,
}

/// What a pinned method's proof shows.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Guard {
    /// Membership, its nullifier in the scope `scope`; `once` admits each
    /// member once there.
    #[codec(index = 0)]
    Auth { scope: String, once: bool },
    /// Ownership of the ledger account the device's owner digest holds.
    #[codec(index = 1)]
    Owner,
}

/// A method the device may prove for: its place, its name, its guard.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Method {
    pub agent: u32,
    pub instance: u32,
    pub name: String,
    pub guard: Guard,
}

impl From<&s4_credential_contract::Agent> for Agent {
    fn from(agent: &s4_credential_contract::Agent) -> Self {
        Self {
            agent: agent.agent,
            identity: agent.identity,
        }
    }
}

impl From<s4_credential_contract::Location> for Location {
    fn from(location: s4_credential_contract::Location) -> Self {
        Self {
            agent: location.agent,
            instance: location.instance,
        }
    }
}

impl From<&s4_credential_contract::Method> for Method {
    fn from(method: &s4_credential_contract::Method) -> Self {
        Self {
            agent: method.agent,
            instance: method.instance,
            name: method.name.clone(),
            guard: match &method.guard {
                s4_credential_contract::Guard::Auth { scope, once } => Guard::Auth {
                    scope: scope.clone(),
                    once: *once,
                },
                s4_credential_contract::Guard::Owner => Guard::Owner,
            },
        }
    }
}

/// The contract's onions as the facility keeps them.
pub fn onions(of: &[s4_credential_contract::Onion]) -> Vec<Onion> {
    of.iter()
        .map(|onion| Onion {
            key: onion.key,
            ssh_host_key: onion.ssh_host_key,
        })
        .collect()
}

/// One enrollment, pinned at the user's confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Enrollment {
    pub handle: [u8; 32],
    pub space: [u8; 32],
    pub agents: Vec<Agent>,
    pub methods: Vec<Method>,
    /// The credential actor, whose tree the member's leaf is in.
    pub credentials: Location,
    pub source: Reference,
    /// The member digest, the leaf the device keeps the tree for.
    pub member: [u8; 32],
    /// The owner digest, public: the device's handle there, which the
    /// person's other devices name to enroll or revoke it.
    pub owner: [u8; 32],
    /// The gateway the enrollment was made through: where it is, its host
    /// key's fingerprint and the application its `ServerHello` named, the
    /// origin the enrollment is kept for.
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    pub application: String,
    /// The host key's ed25519 key, if the session verified one: the
    /// clearnet route key-signed calls may take once the user opts the
    /// space out of Tor.
    pub host_key: Option<[u8; 32]>,
    /// The space's onion set as enrollment pinned it; a refresh keeps the
    /// registrar's newer one beside it (`crate::net`).
    pub onions: Vec<Onion>,
    /// The space declared itself onion-only.
    pub onion_only: bool,
}

impl Enrollment {
    /// The pinned method `name` at `instance` of `agent`.
    pub fn method(&self, agent: u32, instance: u32, name: &str) -> Option<&Method> {
        self.methods.iter().find(|method| {
            method.agent == agent && method.instance == instance && method.name == name
        })
    }

    /// The pinned agent `agent`.
    pub fn agent(&self, agent: u32) -> Option<&Agent> {
        self.agents.iter().find(|pinned| pinned.agent == agent)
    }

    /// The key its space's routes are kept under in the client
    /// ([`vos_light::route::space`]), apart from every home's.
    pub fn routes(&self) -> [u8; 32] {
        vos_light::route::space(&self.handle)
    }

    /// Whether `request` names exactly what this enrollment pinned.
    pub fn pins(&self, request: &crate::Enroll) -> bool {
        self.handle == request.handle
            && self.space == request.space
            && self.agents == request.agents.iter().map(Agent::from).collect::<Vec<_>>()
            && self.methods == request.methods.iter().map(Method::from).collect::<Vec<_>>()
            && self.credentials == Location::from(request.credentials)
    }
}

/// The enrollments, a row each of the facility's database under
/// [`ENROLLMENT`], and each one's credential tree, a file beside it under
/// the facility's directory.
#[derive(Clone)]
pub struct Store {
    directory: PathBuf,
    kept: Result<Kept, String>,
}

/// The enrollments' rows' prefix, then the origin's digest.
const ENROLLMENT: &[u8] = b"enrollment/";
const PAYMENT: &[u8] = b"payment/";

/// A payment the user confirmed whose ledger answer the device has not
/// read: kept before its first proof leaves, so a lost answer, a restart
/// or an expiry is settled by the ledger's word (`Payments.paid`) and
/// never paid twice. Every proof made for it names its `key`.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Pending {
    /// The owner digest it pays from.
    pub owner: [u8; 32],
    pub key: [u8; 32],
    pub payee: String,
    pub amount: u64,
    /// Its last proof's expiry, by the node's clock.
    pub expires_ms: u64,
}

/// Where a server is: its verified SSH host key and the application that
/// asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// The host key's SHA-256 fingerprint, as the session pinned it.
    pub host: String,
    /// The application identity its `ServerHello` named.
    pub application: String,
}

impl Origin {
    fn digest(&self) -> [u8; 16] {
        let mut hash = Sha256::new();
        hash.update(self.host.as_bytes());
        hash.update([0]);
        hash.update(self.application.as_bytes());
        hash.finalize()[..16].try_into().expect("16 bytes")
    }
}

impl Store {
    /// The enrollments of the facility whose directory is `directory`.
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        let kept = Kept::open(&directory);
        Self { directory, kept }
    }

    /// The facility's database, or why it cannot be read.
    pub fn kept(&self) -> Result<&Kept, String> {
        self.kept.as_ref().map_err(Clone::clone)
    }

    fn key(origin: &Origin) -> Vec<u8> {
        [ENROLLMENT, &origin.digest()].concat()
    }

    /// Where `origin`'s credential tree is kept.
    pub fn tree_path(&self, origin: &Origin) -> PathBuf {
        self.directory
            .join(format!("{}.tree", hex::encode(origin.digest())))
    }

    /// The enrollment pinned for `origin`, if there is one.
    pub fn get(&self, origin: &Origin) -> Result<Option<Enrollment>, String> {
        self.kept()?.get(&Self::key(origin))
    }

    /// Pin `enrollment` for `origin`.
    pub fn put(&self, origin: &Origin, enrollment: &Enrollment) -> Result<(), String> {
        self.kept()?.put(&Self::key(origin), enrollment)
    }

    fn payments(origin: &Origin) -> Vec<u8> {
        [PAYMENT, &origin.digest()].concat()
    }

    /// The payments `origin`'s enrollment holds pending, oldest key first.
    pub fn pending(&self, origin: &Origin) -> Result<Vec<Pending>, String> {
        Ok(self
            .kept()?
            .under::<Pending>(&Self::payments(origin))?
            .into_iter()
            .map(|(_, pending)| pending)
            .collect())
    }

    /// Keep `pending` for `origin`, synced.
    pub fn keep_pending(&self, origin: &Origin, pending: &Pending) -> Result<(), String> {
        self.kept()?
            .put(&[Self::payments(origin), pending.key.to_vec()].concat(), pending)
    }

    /// The pending payment `key` of `origin`'s settled: forgotten.
    pub fn settled(&self, origin: &Origin, key: &[u8; 32]) -> Result<(), String> {
        self.kept()?
            .remove(&[Self::payments(origin), key.to_vec()].concat())
    }

    /// Whether any enrollment is kept: its source's key already exists.
    pub fn any(&self) -> bool {
        self.all().is_ok_and(|all| !all.is_empty())
    }

    /// Every enrollment kept for another origin than `origin`.
    pub fn others(&self, origin: &Origin) -> Result<Vec<Enrollment>, String> {
        let skip = Self::key(origin);
        Ok(self
            .kept()?
            .under::<Enrollment>(ENROLLMENT)?
            .into_iter()
            .filter(|(key, _)| *key != skip)
            .map(|(_, enrollment)| enrollment)
            .collect())
    }

    /// Every enrollment kept.
    pub fn all(&self) -> Result<Vec<Enrollment>, String> {
        Ok(self
            .kept()?
            .under::<Enrollment>(ENROLLMENT)?
            .into_iter()
            .map(|(_, enrollment)| enrollment)
            .collect())
    }

    /// Forget `origin`'s enrollment: the source's key is left as it is.
    #[cfg(test)]
    pub fn remove(&self, origin: &Origin) -> Result<(), String> {
        self.kept()?.remove(&Self::key(origin))
    }
}

pub(crate) fn create_private(directory: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))
}

/// The sibling `path` is written through: its whole name's, so two files
/// whose names differ by their extension alone write through two.
fn partial(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(".partial");
    path.with_file_name(name)
}

/// `bytes` at `path`, through a sibling file of its own renamed into
/// place, the file and its directory synced; one write at a time in the
/// process, so two threads writing one file never interleave in it.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    static WRITING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _writing = crate::lock(&WRITING);
    let partial = partial(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&partial).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    written
        .and_then(|()| std::fs::rename(&partial, path))
        // The rename itself kept across a power loss.
        .and_then(|()| match path.parent() {
            Some(directory) => std::fs::File::open(directory)?.sync_all(),
            None => Ok(()),
        })
        .map_err(|error| format!("{}: {error}", path.display()))
}

/// An enrollment of agent 7 pinning `methods`, for the tests.
#[cfg(test)]
pub(crate) fn fixture(methods: Vec<Method>) -> Enrollment {
    Enrollment {
        handle: [1; 32],
        space: [2; 32],
        agents: vec![Agent {
            agent: 7,
            identity: [3; 32],
        }],
        methods,
        credentials: Location {
            agent: 7,
            instance: 9,
        },
        source: Reference::Keystore {
            alias: "vos.device.1".into(),
        },
        member: [4; 32],
        owner: [8; 32],
        host: "gateway.example".into(),
        port: 2222,
        fingerprint: "SHA256:abc".into(),
        application: "vos.gateway".into(),
        host_key: None,
        onions: vec![Onion {
            key: [5; 32],
            ssh_host_key: [6; 32],
        }],
        onion_only: false,
    }
}

#[cfg(test)]
mod tests {
    /// Two files whose names differ by their extension alone are written
    /// through two siblings, and each holds what was written to it.
    #[test]
    fn two_files_write_through_siblings_of_their_own() {
        let dir = tempfile::tempdir().unwrap();
        let (state, text) = (
            dir.path().join("rendezvous.state"),
            dir.path().join("rendezvous.txt"),
        );
        assert_ne!(super::partial(&state), super::partial(&text));
        std::thread::scope(|scope| {
            for (path, byte) in [(&state, 1u8), (&text, 2u8)] {
                scope.spawn(move || {
                    for _ in 0..50 {
                        super::write_private(path, &[byte; 4096]).unwrap();
                    }
                });
            }
        });
        assert_eq!(std::fs::read(&state).unwrap(), vec![1; 4096]);
        assert_eq!(std::fs::read(&text).unwrap(), vec![2; 4096]);
    }

    use super::*;

    fn enrollment() -> Enrollment {
        fixture(vec![
            Method {
                agent: 7,
                instance: 3,
                name: "login".into(),
                guard: Guard::Auth {
                    scope: "login".into(),
                    once: false,
                },
            },
            Method {
                agent: 7,
                instance: 2,
                name: "transfer".into(),
                guard: Guard::Owner,
            },
        ])
    }

    #[test]
    fn an_enrollment_is_kept_per_host_and_application() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::new(directory.path().join("credentials"));
        let origin = Origin {
            host: "SHA256:abc".into(),
            application: "vos.gateway".into(),
        };
        assert_eq!(store.get(&origin).unwrap(), None);
        assert!(!store.any());
        store.put(&origin, &enrollment()).unwrap();
        assert!(store.any());
        assert_eq!(store.get(&origin).unwrap(), Some(enrollment()));
        let other = Origin {
            application: "vos.other".into(),
            ..origin.clone()
        };
        assert_eq!(store.get(&other).unwrap(), None);
        assert_eq!(store.others(&other).unwrap(), vec![enrollment()]);
        assert_eq!(store.others(&origin).unwrap(), Vec::new());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&directory.path().join("credentials")), 0o700);
            let kept = directory
                .path()
                .join("credentials")
                .join(crate::kept::DIRECTORY);
            assert_eq!(mode(&kept), 0o700);
        }
        store.remove(&origin).unwrap();
        assert_eq!(store.get(&origin).unwrap(), None);
    }

    #[test]
    fn a_method_is_found_only_as_pinned() {
        let pinned = enrollment();
        assert!(pinned.method(7, 3, "login").is_some());
        assert!(pinned.method(7, 3, "vote").is_none());
        assert!(pinned.method(8, 3, "login").is_none());
        assert!(pinned.method(7, 2, "login").is_none());
    }
}
