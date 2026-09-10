//! Node-local native-extension registration.
//!
//! Recipe-driven service publication and installation belonged to the retired
//! compatibility CLI. The clean cutover retains only platform adapters read
//! from `local.toml` during `space up`.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use serde::Deserialize;
use vos::node::{ExtensionConfig, VosNode};
use vos::registry::{RegistryRef, Status};
use vos::value::Args;

use super::common::{instance_service_id, parse_instance_name};

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ExtensionDef {
    pub name: String,
    pub path: String,
    #[serde(default)]
    pub init: BTreeMap<String, toml::Value>,
    #[serde(default)]
    pub intra_caps: Vec<String>,
    pub tick_ms: Option<u64>,
}

pub(crate) fn register_extension(
    node: &mut VosNode,
    registry: &RegistryRef,
    extension: &ExtensionDef,
    data_dir: &Path,
    daemon_prefix: u16,
    space_id: &[u8; 32],
    known_names: &HashSet<String>,
    operator: Option<&libp2p::identity::Keypair>,
) -> anyhow::Result<Vec<String>> {
    parse_instance_name(&extension.name)
        .map_err(|error| anyhow::anyhow!("extension '{}': {error}", extension.name))?;
    let library = data_dir.join(&extension.path);
    if !library.exists() {
        anyhow::bail!(
            "extension '{}': library not found at {}",
            extension.name,
            library.display()
        );
    }

    let mut arguments = Args::new();
    for (name, value) in &extension.init {
        let value = resolve_env_indirection(&extension.name, name, value)?;
        arguments = match value {
            toml::Value::String(value) => arguments.with(name.clone(), value),
            toml::Value::Integer(value) => arguments.with(name.clone(), value as u32),
            toml::Value::Boolean(value) => arguments.with(name.clone(), value),
            other => anyhow::bail!(
                "extension '{}': init argument '{}' has unsupported type {}",
                extension.name,
                name,
                other.type_str(),
            ),
        };
    }

    // SAFETY: the operator explicitly selected this VOS extension library.
    // Loading it once validates its FFI metadata before the worker owns a
    // second handle.
    let plugin = unsafe { vos::extension::ExtensionPlugin::load(&library) }.map_err(|error| {
        anyhow::anyhow!(
            "extension '{}': load {}: {error}",
            extension.name,
            library.display(),
        )
    })?;
    let metadata = plugin.meta_bytes().to_vec();

    let caps = extension
        .intra_caps
        .iter()
        .map(|token| {
            vos::IntraCap::parse(token)
                .map_err(|error| anyhow::anyhow!("extension '{}': {error}", extension.name))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if let Some(warning) = intra_caps_wildcard_warning(&extension.name, &caps) {
        tracing::warn!("{warning}");
    }
    if let Some(warning) = unresolvable_cap_warning(&extension.name, &caps, known_names) {
        tracing::warn!("{warning}");
    }
    let effective = caps.iter().map(ToString::to_string).collect::<Vec<_>>();

    let config = if extension.init.is_empty() {
        ExtensionConfig::new(&library)
    } else {
        ExtensionConfig::with_args(&library, &arguments)
    }
    .with_name(extension.name.clone())
    .with_intra_caps(caps)
    .persist(data_dir);
    let config = match extension.tick_ms {
        Some(milliseconds) if milliseconds != 0 => config.with_tick_ms(milliseconds),
        _ => config,
    };
    let id = node
        .try_register_extension_at_id(config, instance_service_id(&extension.name, daemon_prefix))
        .map_err(|error| {
            anyhow::anyhow!("extension '{}': startup failed: {error}", extension.name)
        })?;
    tracing::info!(name = %extension.name, %id, "native extension loaded");

    if !metadata.is_empty() {
        let auth = operator
            .map(|operator| {
                super::op_sign::op_auth(
                    operator,
                    space_id,
                    "register_extension_meta",
                    &[extension.name.as_bytes(), &metadata],
                )
            })
            .transpose()?
            .unwrap_or_default();
        let status = vos::block_on(registry.register_extension_meta(
            &mut &*node,
            extension.name.clone(),
            metadata,
            auth,
        ))
        .map_err(|error| {
            anyhow::anyhow!(
                "registry.register_extension_meta('{}'): {error}",
                extension.name
            )
        })?;
        if status != Status::Ok {
            tracing::warn!(name = %extension.name, %status, "extension metadata was not accepted");
        }
    }
    drop(plugin);
    Ok(effective)
}

fn intra_caps_wildcard_warning(name: &str, caps: &[vos::IntraCap]) -> Option<String> {
    let full = caps.iter().any(vos::IntraCap::is_full_wildcard);
    let actor_wildcard = caps.iter().any(vos::IntraCap::is_actor_wildcard);
    let prefix_uncapped = caps
        .iter()
        .any(|cap| cap.is_actor_prefix() && cap.role.is_none());
    if !actor_wildcard && !prefix_uncapped {
        return None;
    }
    let detail = if full {
        "grants every role on every actor"
    } else if actor_wildcard {
        "grants one role on every actor"
    } else {
        "grants every role on every actor matching a prefix"
    };
    Some(format!(
        "extension '{name}': wildcard intra_cap {detail}; prefer explicit targets"
    ))
}

fn unresolvable_cap_warning(
    name: &str,
    caps: &[vos::IntraCap],
    known_names: &HashSet<String>,
) -> Option<String> {
    let known = known_names
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let mut unresolved = caps
        .iter()
        .filter(|cap| !cap.is_actor_wildcard() && !cap.is_actor_prefix())
        .filter_map(|cap| cap.actor_name.as_deref())
        .filter(|target| !known.contains(&target.to_ascii_lowercase()))
        .collect::<Vec<_>>();
    unresolved.sort_unstable();
    unresolved.dedup();
    (!unresolved.is_empty()).then(|| {
        format!(
            "extension '{name}': intra_caps target unknown local actors: {}",
            unresolved.join(", ")
        )
    })
}

fn resolve_env_indirection(
    extension: &str,
    key: &str,
    value: &toml::Value,
) -> anyhow::Result<toml::Value> {
    let toml::Value::String(text) = value else {
        return Ok(value.clone());
    };
    let Some(variable) = text.strip_prefix("$env:") else {
        return Ok(value.clone());
    };
    if variable.is_empty() {
        return Ok(value.clone());
    }
    std::env::var(variable)
        .map(toml::Value::String)
        .map_err(|_| {
            anyhow::anyhow!(
                "extension '{extension}': init argument '{key}' references unset environment variable {variable}"
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_definition_rejects_unknown_fields() {
        let error = toml::from_str::<ExtensionDef>(
            "name = 'prover'\npath = '/opt/prover.so'\nlegacy_service = true",
        )
        .expect_err("unknown policy must not be ignored");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn wildcard_caps_are_operator_visible() {
        let caps = [vos::IntraCap::parse("*:guest").unwrap()];
        assert!(intra_caps_wildcard_warning("bridge", &caps).is_some());
        assert!(intra_caps_wildcard_warning("bridge", &[]).is_none());
    }
}
