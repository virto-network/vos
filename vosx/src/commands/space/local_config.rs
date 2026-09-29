//! Node-local space configuration.
//!
//! Daemon listeners, built-in ingress, native extension adapters and an optional
//! certified bootstrap input path. Replicated Agent lifecycle state does not
//! live in this file and has no compatibility CLI.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

const LOCAL_FILE: &str = "local.toml";
pub(crate) const IMAGE_LOCAL_HOST_DIRECTORY: &str = "local-agent-host";
pub(crate) const IMAGE_LOCAL_LIFECYCLE_DIRECTORY: &str = "local-agent-lifecycle";
pub(crate) const EXTERNAL_LOCAL_JOURNAL_DIRECTORY: &str = "local-agent-external";
pub(crate) const EXTERNAL_LOCAL_LIFECYCLE_DIRECTORY: &str = "local-agent-external-lifecycle";

/// Production Local is image-based. Keep the retired external-state spelling
/// recognizable so old experimental configurations fail explicitly, rather
/// than silently selecting image storage or reinterpreting an existing root.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAgentStorage {
    #[default]
    Image,
    /// Retired public experiment; accepted by decoding only for explicit refusal.
    ExternalState,
}

impl LocalAgentStorage {
    fn is_image(&self) -> bool {
        *self == Self::Image
    }

    pub(crate) fn require_supported(self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self == Self::Image,
            "external-state Local deployment is unsupported; preserve its roots and use a fresh image-based Local deployment (no in-place migration)",
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    /// Persistent libp2p listen addresses. `space up --listen` overrides these.
    #[serde(default)]
    pub listen: Vec<String>,
    /// Local storage format. Only `image` is supported, including candidate builds.
    #[serde(default, skip_serializing_if = "LocalAgentStorage::is_image")]
    pub local_agent_storage: LocalAgentStorage,
    /// Certified system bootstrap input. Relative paths resolve under the
    /// Space data directory. Optional on restart after durable publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_bootstrap_bundle: Option<std::path::PathBuf>,
    /// Built-in node-local ingress listeners.
    #[serde(default, skip_serializing_if = "IngressLocal::is_empty")]
    pub ingress: IngressLocal,
    /// Native `.so` extensions loaded at boot.
    #[serde(default, rename = "extension", skip_serializing_if = "Vec::is_empty")]
    pub extensions: Vec<ExtensionLocal>,
}

impl LocalConfig {
    /// Explicit defaults for newly created spaces; existing spaces keep their config.
    pub fn for_new_space() -> Self {
        Self {
            listen: vec!["/ip4/127.0.0.1/tcp/0".into()],
            local_agent_storage: LocalAgentStorage::Image,
            system_bootstrap_bundle: None,
            ingress: IngressLocal {
                http: vec![HttpIngressLocal {
                    name: "http".into(),
                    listen: "127.0.0.1:8080".into(),
                    tls_cert: None,
                    tls_key: None,
                    max_connections: default_http_max_connections(),
                }],
                ssh: vec![SshIngressLocal {
                    name: "ssh".into(),
                    listen: "127.0.0.1:2222".into(),
                    max_connections: default_ssh_max_connections(),
                    max_sessions_per_member: default_ssh_max_sessions_per_member(),
                }],
            },
            extensions: Vec::new(),
        }
    }
}

/// Reject a configuration change that would silently mix two Local formats
/// in one Space/Node deployment. This reads path metadata only: startup owns
/// creation of its selected fresh roots after the full lifecycle is ready.
pub(crate) fn validate_local_storage_roots(
    data_dir: &Path,
    selected: LocalAgentStorage,
) -> anyhow::Result<()> {
    selected.require_supported()?;
    let forbidden = [
        EXTERNAL_LOCAL_JOURNAL_DIRECTORY,
        EXTERNAL_LOCAL_LIFECYCLE_DIRECTORY,
    ];
    for name in forbidden {
        let path = data_dir.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => anyhow::bail!(
                "Local storage selection {selected:?} conflicts with existing root {}; use a fresh deployment root, not an in-place migration",
                path.display(),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(anyhow::anyhow!("inspect {}: {error}", path.display()));
            }
        }
    }
    Ok(())
}

/// Production Local Create/Install cannot write an external-state root.
/// Reject before the CLI reserves a credential or writes a request file.
pub(crate) fn require_image_local_lifecycle(data_dir: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        load(data_dir)?.local_agent_storage == LocalAgentStorage::Image,
        "image-format Local Create/Install cannot target external-state storage; no lifecycle request was retained",
    );
    validate_local_storage_roots(data_dir, LocalAgentStorage::Image)?;
    Ok(())
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IngressLocal {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http: Vec<HttpIngressLocal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh: Vec<SshIngressLocal>,
}

impl IngressLocal {
    fn is_empty(&self) -> bool {
        self.http.is_empty() && self.ssh.is_empty()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpIngressLocal {
    pub name: String,
    pub listen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<String>,
    #[serde(default = "default_http_max_connections")]
    pub max_connections: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshIngressLocal {
    pub name: String,
    pub listen: String,
    #[serde(default = "default_ssh_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_ssh_max_sessions_per_member")]
    pub max_sessions_per_member: usize,
}

fn default_http_max_connections() -> usize {
    1024
}

fn default_ssh_max_connections() -> usize {
    128
}

fn default_ssh_max_sessions_per_member() -> usize {
    4
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionLocal {
    pub name: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub intra_caps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tick_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub init: BTreeMap<String, toml::Value>,
}

pub fn path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(LOCAL_FILE)
}

pub fn load(data_dir: &Path) -> anyhow::Result<LocalConfig> {
    let config_path = path(data_dir);
    let bytes = match std::fs::read(&config_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LocalConfig::default());
        }
        Err(error) => {
            return Err(anyhow::anyhow!("read {}: {error}", config_path.display()));
        }
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|error| anyhow::anyhow!("{} is not UTF-8: {error}", config_path.display()))?;
    let config: LocalConfig = toml::from_str(text)
        .map_err(|error| anyhow::anyhow!("parse {}: {error}", config_path.display()))?;
    config.local_agent_storage.require_supported()?;
    Ok(config)
}

pub fn save(data_dir: &Path, config: &LocalConfig) -> anyhow::Result<()> {
    config.local_agent_storage.require_supported()?;
    let config_path = path(data_dir);
    let body = toml::to_string_pretty(config)
        .map_err(|error| anyhow::anyhow!("encode local.toml: {error}"))?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, body)
        .map_err(|error| anyhow::anyhow!("write {}: {error}", config_path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_space_listeners_roundtrip_without_changing_missing_config_defaults() {
        let config = LocalConfig::for_new_space();
        let encoded = toml::to_string_pretty(&config).unwrap();
        assert_eq!(toml::from_str::<LocalConfig>(&encoded).unwrap(), config);
        assert_eq!(config.ingress.http[0].listen, "127.0.0.1:8080");
        assert_eq!(config.ingress.ssh[0].listen, "127.0.0.1:2222");
        assert!(LocalConfig::default().ingress.is_empty());
        assert_eq!(
            LocalConfig::default().local_agent_storage,
            LocalAgentStorage::Image
        );
        assert!(!encoded.contains("local_agent_storage"));
    }

    #[test]
    fn rejects_retired_agent_policy_fields() {
        for text in [
            "subscriptions = ['counter']",
            "[agents.counter]\ndevice_secret = true",
        ] {
            assert!(toml::from_str::<LocalConfig>(text).is_err(), "{text}");
        }
    }

    #[test]
    fn bootstrap_bundle_path_is_explicit_and_optional() {
        let config: LocalConfig =
            toml::from_str("system_bootstrap_bundle = 'bootstrap/node.bundle'").unwrap();
        assert_eq!(
            config.system_bootstrap_bundle.as_deref(),
            Some(Path::new("bootstrap/node.bundle"))
        );
        assert_eq!(
            toml::from_str::<LocalConfig>(&toml::to_string(&config).unwrap()).unwrap(),
            config
        );
        assert!(LocalConfig::default().system_bootstrap_bundle.is_none());
        assert!(
            !toml::to_string(&LocalConfig::for_new_space())
                .unwrap()
                .contains("system_bootstrap_bundle")
        );
    }

    #[test]
    fn extension_and_ingress_policy_remain_local() {
        let config: LocalConfig = toml::from_str(
            "listen = ['/ip4/127.0.0.1/tcp/0']\n\
             [[extension]]\nname = 'prover'\npath = '/opt/vos/libprover.so'\n\
             [[ingress.http]]\nname = 'api'\nlisten = '127.0.0.1:8080'\n",
        )
        .expect("local platform configuration");
        assert_eq!(config.extensions[0].name, "prover");
        assert_eq!(config.ingress.http[0].name, "api");
    }

    #[test]
    fn retired_external_selection_fails_before_writes_and_never_reuses_roots() {
        let config: LocalConfig = toml::from_str("local_agent_storage = 'external-state'").unwrap();
        assert_eq!(config.local_agent_storage, LocalAgentStorage::ExternalState);
        assert!(
            toml::to_string(&config)
                .unwrap()
                .contains("local_agent_storage = \"external-state\"")
        );

        struct TestRoot(std::path::PathBuf);
        impl Drop for TestRoot {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target")
            });
        let scratch = target.join("test-tmp");
        std::fs::create_dir_all(&scratch).unwrap();
        let root = TestRoot(scratch.join(format!(
            "vosx-local-storage-{}-{suffix}",
            std::process::id()
        )));
        std::fs::create_dir(&root.0).unwrap();
        validate_local_storage_roots(&root.0, LocalAgentStorage::Image).unwrap();
        let error =
            validate_local_storage_roots(&root.0, LocalAgentStorage::ExternalState).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("external-state Local deployment is unsupported")
        );
        assert!(save(&root.0, &config).is_err());
        assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 0);
        // Model a config written by the retired experiment, not by this binary.
        let retired_config = b"local_agent_storage = 'external-state'\n";
        std::fs::write(path(&root.0), retired_config).unwrap();
        assert!(load(&root.0).is_err());
        assert!(require_image_local_lifecycle(&root.0).is_err());
        #[cfg(target_os = "linux")]
        {
            let operator = libp2p::identity::Keypair::ed25519_from_bytes([0x73; 32]).unwrap();
            let error = super::super::local_create::create_local(
                &root.0,
                "127.0.0.1:1".parse().unwrap(),
                &operator,
                vos::agent::sdk::SpaceId([1; 32]),
                [2; 32],
                false,
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("external-state Local deployment is unsupported")
            );
        }
        assert!(!root.0.join("agent-client").exists());
        assert_eq!(std::fs::read_dir(&root.0).unwrap().count(), 1);
        assert_eq!(std::fs::read(path(&root.0)).unwrap(), retired_config);
        save(&root.0, &LocalConfig::default()).unwrap();
        require_image_local_lifecycle(&root.0).unwrap();

        let image = root.0.join(IMAGE_LOCAL_LIFECYCLE_DIRECTORY);
        std::fs::create_dir(&image).unwrap();
        assert!(validate_local_storage_roots(&root.0, LocalAgentStorage::ExternalState).is_err());
        validate_local_storage_roots(&root.0, LocalAgentStorage::Image).unwrap();
        std::fs::remove_dir(&image).unwrap();

        let external = root.0.join(EXTERNAL_LOCAL_JOURNAL_DIRECTORY);
        std::fs::create_dir(&external).unwrap();
        assert!(validate_local_storage_roots(&root.0, LocalAgentStorage::Image).is_err());
        assert!(validate_local_storage_roots(&root.0, LocalAgentStorage::ExternalState).is_err());
        assert!(external.is_dir());
    }
}
