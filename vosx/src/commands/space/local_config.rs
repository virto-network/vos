//! Node-local space configuration.
//!
//! The clean cutover retains only daemon listeners, built-in ingress, and
//! native extension adapters. Replicated Agent lifecycle state does not live
//! in this file and has no compatibility CLI.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

const LOCAL_FILE: &str = "local.toml";
pub(crate) const IMAGE_LOCAL_HOST_DIRECTORY: &str = "local-agent-host";
pub(crate) const IMAGE_LOCAL_LIFECYCLE_DIRECTORY: &str = "local-agent-lifecycle";
pub(crate) const EXTERNAL_LOCAL_JOURNAL_DIRECTORY: &str = "local-agent-external";
pub(crate) const EXTERNAL_LOCAL_LIFECYCLE_DIRECTORY: &str = "local-agent-external-lifecycle";

/// Immutable-at-deployment Local persistence choice. Missing fields on older
/// nodes keep the existing image path; external-state never means an in-place
/// reinterpretation of either image root.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocalAgentStorage {
    #[default]
    Image,
    ExternalState,
}

impl LocalAgentStorage {
    fn is_image(&self) -> bool {
        *self == Self::Image
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    /// Persistent libp2p listen addresses. `space up --listen` overrides these.
    #[serde(default)]
    pub listen: Vec<String>,
    /// Explicit Local storage format. Existing configs default to `image`.
    #[serde(default, skip_serializing_if = "LocalAgentStorage::is_image")]
    pub local_agent_storage: LocalAgentStorage,
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
    let forbidden = match selected {
        LocalAgentStorage::Image => [
            EXTERNAL_LOCAL_JOURNAL_DIRECTORY,
            EXTERNAL_LOCAL_LIFECYCLE_DIRECTORY,
        ],
        LocalAgentStorage::ExternalState => {
            [IMAGE_LOCAL_HOST_DIRECTORY, IMAGE_LOCAL_LIFECYCLE_DIRECTORY]
        }
    };
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
    toml::from_str(text)
        .map_err(|error| anyhow::anyhow!("parse {}: {error}", config_path.display()))
}

pub fn save(data_dir: &Path, config: &LocalConfig) -> anyhow::Result<()> {
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
    fn explicit_external_selection_never_reuses_image_roots() {
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
        let root = TestRoot(std::env::temp_dir().join(format!(
            "vosx-local-storage-{}-{suffix}",
            std::process::id()
        )));
        std::fs::create_dir(&root.0).unwrap();
        validate_local_storage_roots(&root.0, LocalAgentStorage::Image).unwrap();
        validate_local_storage_roots(&root.0, LocalAgentStorage::ExternalState).unwrap();

        let image = root.0.join(IMAGE_LOCAL_LIFECYCLE_DIRECTORY);
        std::fs::create_dir(&image).unwrap();
        assert!(validate_local_storage_roots(&root.0, LocalAgentStorage::ExternalState).is_err());
        validate_local_storage_roots(&root.0, LocalAgentStorage::Image).unwrap();
        std::fs::remove_dir(&image).unwrap();

        let external = root.0.join(EXTERNAL_LOCAL_JOURNAL_DIRECTORY);
        std::fs::create_dir(&external).unwrap();
        assert!(validate_local_storage_roots(&root.0, LocalAgentStorage::Image).is_err());
        validate_local_storage_roots(&root.0, LocalAgentStorage::ExternalState).unwrap();
    }
}
