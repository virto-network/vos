//! `space call` — generic-purpose actor invoke against a
//! running daemon.
//!
//! The floor primitive that every `space *` command sits on:
//! `space publish`, `space install`, `space agents`, etc. are
//! typed sugar wrappers around the same `DaemonClient::invoke_dyn`
//! that this command exposes verbatim.
//!
//! Examples:
//!
//! ```text
//! # query the registry's catalog (same as `space programs`)
//! $ vosx space call demo registry programs
//!
//! # invoke an installed agent's method
//! $ vosx space call demo counter inc
//! $ vosx space call demo counter add a=2 b=3
//! ```

use vos::value::Msg;

use crate::commands::space::client::DaemonClient;
use crate::output;

pub struct Args {
    pub space: String,
    pub target: String,
    pub method: String,
    pub args: Vec<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    DaemonClient::with_connect(&args.space, |client| {
        let target_id = client.resolve_target(&args.target)?;

        // Validate the method against the schema when we have one.
        // `registry` and `0xHEX` targets don't have an instance-name
        // hook into `meta_for_instance`, so they fall through to the
        // wire (best-effort). Named agents/extensions always do —
        // and a typo gets rejected before it reaches the daemon
        // instead of silently returning `()`.
        if !is_raw_target(&args.target) {
            let meta_bytes = client.meta_for_instance(&args.target)?;
            if !meta_bytes.is_empty() {
                if let Some(meta) = vos::metadata::decode(&meta_bytes) {
                    if !meta.messages.iter().any(|m| m.name == args.method) {
                        let names = meta
                            .messages
                            .iter()
                            .map(|m| m.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        let hint = if names.is_empty() {
                            String::new()
                        } else {
                            format!(" (available: {names})")
                        };
                        anyhow::bail!(
                            "unknown method '{}' on '{}'{hint}",
                            args.method,
                            args.target,
                        );
                    }
                }
            }
        }

        let msg = build_msg(&args.method, &args.args)?;
        tracing::debug!("invoking {} on {target_id}", args.method);
        let reply = client.invoke_dyn(target_id, &msg)?;
        if output::is_json() {
            output::print_json(&output::value_to_json(&reply));
        } else {
            println!("{}", output::value_to_text(&reply));
        }
        Ok(())
    })
}

/// `registry` (special name) or `0xHEX` (raw ServiceId) skip the
/// `meta_for_instance` schema check because they don't go through
/// the instance-name table. Everything else gets validated.
fn is_raw_target(target: &str) -> bool {
    target == "registry" || target.starts_with("0x")
}

/// Parse `key=value` strings into a typed `Msg`. Heuristics:
/// numeric → u64, `true`/`false` → bool, otherwise string.
/// Same shape `space install --init` and the manifest
/// reconciler use.
fn build_msg(method: &str, args: &[String]) -> anyhow::Result<Msg> {
    let mut msg = Msg::new(method);
    for a in args {
        let (k, v) = a
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--arg '{a}' must be 'key=value'"))?;
        if let Ok(n) = v.parse::<u64>() {
            msg = msg.with(k, n);
        } else if let Ok(b) = v.parse::<bool>() {
            msg = msg.with(k, b);
        } else {
            msg = msg.with(k, v.to_string());
        }
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_msg_types_numbers_first() {
        let msg = build_msg("test", &["a=42".into(), "b=true".into(), "c=hi".into()]).unwrap();
        // We can't introspect Msg's internal Args easily without
        // depending on internal types, but the call shouldn't
        // panic and the typed dispatch is exercised in `with`.
        let _ = msg;
    }

    #[test]
    fn build_msg_rejects_missing_eq() {
        assert!(build_msg("test", &["bad-arg".into()]).is_err());
    }
}
