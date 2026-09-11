//! Node-local space configuration.
//!
//! The clean cutover retains only daemon listeners, built-in ingress, and
//! native extension adapters. Replicated Agent lifecycle state does not live
//! in this file and has no compatibility CLI.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

const LOCAL_FILE: &str = "local.toml";

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LocalConfig {
    /// Persistent libp2p listen addresses. `space up --listen` overrides these.
    #[serde(default)]
    pub listen: Vec<String>,
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
}
