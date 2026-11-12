// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the device keeps of an enrollment: the secret source's reference,
//! what the user confirmed in the chrome (the space's handle, the space, its
//! agents and the methods the device may prove for), and the member digest
//! the space's tree holds, public, so the path can be kept from a session's
//! start without asking the source, and the gateway it was made through, so
//! a sync reaches it with no session open; keyed by the verified SSH host
//! and the application that asked. No secret, no source output and no proof is ever
//! written.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::source::Reference;

pub use s4_credential_contract::{Agent, Guard, Location, Method, Onion};

/// One enrollment, pinned at the user's confirmation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Enrollment {
    #[serde(with = "hex32")]
    pub handle: [u8; 32],
    #[serde(with = "hex32")]
    pub space: [u8; 32],
    pub agents: Vec<Agent>,
    pub methods: Vec<Method>,
    /// The credential actor, whose tree the member's leaf is in.
    pub credentials: Location,
    pub source: Reference,
    /// The member digest, the leaf the device keeps the tree for.
    #[serde(with = "hex32")]
    pub member: [u8; 32],
    /// The owner digest, public: the device's handle there, which the
    /// person's other devices name to enroll or revoke it.
    #[serde(with = "hex32")]
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
    #[serde(with = "hex32_option")]
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

    /// Whether `request` names exactly what this enrollment pinned.
    pub fn pins(&self, request: &crate::Enroll) -> bool {
        self.handle == request.handle
            && self.space == request.space
            && self.agents == request.agents
            && self.methods == request.methods
            && self.credentials == request.credentials
    }
}

/// The enrollments, a file each under one directory, private to the user.
#[derive(Clone, Debug)]
pub struct Store {
    directory: PathBuf,
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

impl Store {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn path(&self, origin: &Origin) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(origin.host.as_bytes());
        hash.update([0]);
        hash.update(origin.application.as_bytes());
        self.directory
            .join(format!("{}.toml", hex::encode(&hash.finalize()[..16])))
    }

    /// Where `origin`'s credential tree is kept, beside its enrollment.
    pub fn tree_path(&self, origin: &Origin) -> PathBuf {
        self.path(origin).with_extension("tree")
    }

    /// The directory the enrollments are kept under.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The enrollment pinned for `origin`, if there is one.
    pub fn get(&self, origin: &Origin) -> Result<Option<Enrollment>, String> {
        let path = self.path(origin);
        match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text)
                .map(Some)
                .map_err(|error| format!("{}: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    /// Pin `enrollment` for `origin`, written whole or not at all.
    pub fn put(&self, origin: &Origin, enrollment: &Enrollment) -> Result<(), String> {
        let text = toml::to_string(enrollment).map_err(|error| error.to_string())?;
        create_private(&self.directory)?;
        let path = self.path(origin);
        write_private(&path, text.as_bytes())
    }

    /// Whether any enrollment is kept: its source's key already exists.
    pub fn any(&self) -> bool {
        std::fs::read_dir(&self.directory).is_ok_and(|entries| {
            entries.flatten().any(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "toml")
            })
        })
    }

    /// Every enrollment kept for another origin than `origin`.
    pub fn others(&self, origin: &Origin) -> Result<Vec<Enrollment>, String> {
        self.read(Some(&self.path(origin)))
    }

    /// Every enrollment kept.
    pub fn all(&self) -> Result<Vec<Enrollment>, String> {
        self.read(None)
    }

    /// Every enrollment kept but the one at `skip`.
    fn read(&self, skip: Option<&Path>) -> Result<Vec<Enrollment>, String> {
        let entries = match std::fs::read_dir(&self.directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("{}: {error}", self.directory.display())),
        };
        let mut enrollments = Vec::new();
        for entry in entries {
            let path = entry.map_err(|error| error.to_string())?.path();
            if skip == Some(path.as_path())
                || path.extension().is_none_or(|extension| extension != "toml")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|error| format!("{}: {error}", path.display()))?;
            enrollments.push(
                toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))?,
            );
        }
        Ok(enrollments)
    }

    /// Forget `origin`'s enrollment: the source's key is left as it is.
    pub fn remove(&self, origin: &Origin) -> Result<(), String> {
        match std::fs::remove_file(self.path(origin)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
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

/// `bytes` at `path`, through a sibling file renamed into place, the file
/// and its directory synced.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let partial = path.with_extension("partial");
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

mod hex32_option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&bytes.map(hex::encode).unwrap_or_default())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty() {
            return Ok(None);
        }
        hex::decode(&text)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .map(Some)
            .ok_or_else(|| serde::de::Error::custom("32 bytes in hex, or none"))
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("32 bytes in hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enrollment() -> Enrollment {
        Enrollment {
            handle: [1; 32],
            space: [2; 32],
            agents: vec![Agent {
                agent: 7,
                identity: [3; 32],
            }],
            methods: vec![
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
            ],
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
            assert_eq!(mode(&store.path(&origin)), 0o600);
        }
        let text = std::fs::read_to_string(store.path(&origin)).unwrap();
        assert!(text.contains("vos.device.1") && text.contains(&hex::encode([1u8; 32])));
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
