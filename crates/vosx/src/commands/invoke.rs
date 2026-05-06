//! `vosx call <target>.<msg> [args…] [--arg k=v]…` — send a typed
//! message to any actor in a hyperspace and print its reply.
//! Resolves names through the registry actor like everyone
//! else; for raw addressing pass `0xHEX`.

use std::path::Path;
use std::time::Duration;

use vos::abi::service::ServiceId;
use vos::value::{Msg, TAG_DYNAMIC};
use vos::Encode;

use crate::manifest::Manifest;
use crate::query::with_query_node;
use crate::util::die;

/// Entry point for `vosx call <agent>.<msg> [args...]`. Splits
/// the dotted target, then forwards to the shared invocation
/// flow. Accepts both forms inside `args`:
/// - **Positional**: `vosx call counter.inc 5` — types are
///   resolved from the actor's `Message::META` (loaded from the
///   manifest's blob).
/// - **Named** (legacy): `vosx call counter.inc n=5` — used
///   when the actor metadata isn't available (raw `0xHEX`
///   target) or to override types (`n=u64:42`).
pub fn run_call(
    manifest: &Manifest,
    dir: &Path,
    dotted: &str,
    args: &[String],
    connect: &[String],
    sync_timeout: u64,
) {
    let (target_str, msg_name) = dotted.split_once('.').unwrap_or_else(|| {
        die(&format!(
            "expected '<agent>.<msg>' (e.g. 'counter.inc'); got {dotted:?}",
        ))
    });
    let any_named = args.iter().any(|a| a.contains('='));
    if any_named {
        // Mixed / all-named: forward to the legacy path.
        run(manifest, dir, target_str, msg_name, args, connect, sync_timeout);
        return;
    }
    // Positional path — resolve types from actor metadata.
    let typed_args = match positional_to_typed(manifest, dir, target_str, msg_name, args) {
        Ok(named) => named,
        Err(e) => die(&format!("vosx call: {e}")),
    };
    run(manifest, dir, target_str, msg_name, &typed_args, connect, sync_timeout);
}

/// Look up the actor's metadata in the manifest, find the
/// message handler, and convert positional args to the
/// `key=value` form `run` expects. Each arg is prefixed with
/// the parameter's type so `parse_arg_value` picks the right
/// wire encoding (e.g. `u32:5`).
fn positional_to_typed(
    manifest: &Manifest,
    dir: &Path,
    target_str: &str,
    msg_name: &str,
    args: &[String],
) -> Result<Vec<String>, String> {
    if args.is_empty() {
        return Ok(Vec::new());
    }
    if target_str.starts_with("0x") {
        return Err(
            "positional args require a named target (e.g. 'counter.inc 5'); \
             with a 0xHEX target use the 'k=v' form so types are explicit"
                .into(),
        );
    }
    let agent = manifest
        .agent
        .iter()
        .find(|a| a.name == target_str)
        .ok_or_else(|| format!("agent '{target_str}' not found in manifest"))?;
    let path = crate::manifest::resolve_entry_path(&agent.name, &agent.path, &agent.service, dir);
    let elf = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let meta = vos::metadata::from_elf(&elf)
        .ok_or_else(|| format!("'{}': no .vos_meta section in actor blob", agent.name))?;
    let handler = meta
        .messages
        .iter()
        .find(|m| m.name == msg_name)
        .ok_or_else(|| {
            format!(
                "'{}': no handler named '{msg_name}'. Available: [{}]",
                agent.name,
                meta.messages.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", "),
            )
        })?;
    if args.len() != handler.fields.len() {
        return Err(format!(
            "'{}.{msg_name}' takes {} arg(s), got {}",
            agent.name,
            handler.fields.len(),
            args.len(),
        ));
    }
    let mut out = Vec::with_capacity(args.len());
    for (arg, field) in args.iter().zip(handler.fields.iter()) {
        // Map the metadata-recorded Rust type to the `parse_arg_value`
        // type prefix. Unknown types fall through to autotype.
        let prefix = match field.ty.as_str() {
            "u8" | "u16" | "u32" => Some("u32"),
            "u64" => Some("u64"),
            "bool" => Some("bool"),
            // String / &str / String-ish — fall through to str.
            t if t.contains("String") || t.contains("str") => Some("str"),
            _ => None,
        };
        let pair = match prefix {
            Some(p) => format!("{}={}:{}", field.name, p, arg),
            None => format!("{}={}", field.name, arg),
        };
        out.push(pair);
    }
    Ok(out)
}

pub fn run(
    manifest: &Manifest,
    dir: &Path,
    target_str: &str,
    msg_name: &str,
    args: &[String],
    connect: &[String],
    sync_timeout: u64,
) {
    // Argument parsing first so an obvious typo fails fast,
    // before we waste time spinning up the network.
    let msg = build_msg(msg_name, args);

    with_query_node(manifest, dir, connect, sync_timeout, |node| {
        let target = resolve_target(node, target_str);
        eprintln!("vosx: invoking {msg_name} on {target}");

        let encoded = msg.encode();
        let mut payload = Vec::with_capacity(1 + encoded.len());
        payload.push(TAG_DYNAMIC);
        payload.extend_from_slice(&encoded);
        let reply = node
            .invoke_with_timeout(target, payload, Duration::from_secs(10))
            .unwrap_or_else(|| {
                eprintln!("invoke: no reply (target unreachable or timed out)");
                std::process::exit(2);
            });

        // Unit-returning handlers reply with zero bytes — print
        // a placeholder so the user sees the call completed.
        if reply.is_empty() {
            println!("()");
        } else {
            let value: vos::value::Value = vos::Decode::decode(&reply);
            println!("{value:?}");
        }
    });
}

fn build_msg(name: &str, args: &[String]) -> Msg {
    let mut msg = Msg::new(name);
    for a in args {
        let (k, v) = a
            .split_once('=')
            .unwrap_or_else(|| die(&format!("--arg '{a}' must be 'key=value'")));
        msg = match parse_arg_value(v) {
            ParsedArg::U32(n) => msg.with(k, n),
            ParsedArg::U64(n) => msg.with(k, n),
            ParsedArg::Bool(b) => msg.with(k, b),
            ParsedArg::Str(s) => msg.with(k, s),
        };
    }
    msg
}

fn resolve_target(node: &vos::node::VosNode, target_str: &str) -> ServiceId {
    if let Some(hex) = target_str.strip_prefix("0x") {
        let raw = u32::from_str_radix(hex, 16)
            .unwrap_or_else(|e| die(&format!("invalid 0x ServiceId '{target_str}': {e}")));
        return ServiceId(raw);
    }
    // Resolve via the macro-generated `RegistryRef`. Returns
    // 0 when the name isn't registered; we surface that as
    // "not found" since the registry's own ID (also 0) is
    // never a useful resolution target.
    let reg = registry::RegistryRef::at(ServiceId::REGISTRY);
    let id = vos::block_on(reg.resolve(&mut &*node, target_str.to_string()))
        .unwrap_or_else(|e| die(&format!("resolve '{target_str}': {e}")));
    if id == 0 {
        eprintln!("'{target_str}' not registered");
        std::process::exit(1);
    }
    ServiceId(id)
}

enum ParsedArg {
    U32(u32),
    U64(u64),
    Bool(bool),
    Str(String),
}

/// Parse a `--arg key=value` value. Optional `type:` prefix
/// pins the wire type (`u32:42`, `u64:42`, `bool:true`,
/// `str:42`); without one we autotype: `true`/`false` → bool,
/// integer → u64, anything else → string. Use a prefix when
/// the actor's handler takes a narrower integer type — `u64`
/// will silently no-op against a `u32` handler.
fn parse_arg_value(v: &str) -> ParsedArg {
    if let Some((ty, rest)) = v.split_once(':') {
        match ty {
            "u8" | "u16" | "u32" => {
                return ParsedArg::U32(
                    rest.parse::<u32>()
                        .unwrap_or_else(|e| die(&format!("--arg {ty}:{rest}: {e}"))),
                );
            }
            "u64" => {
                return ParsedArg::U64(
                    rest.parse::<u64>()
                        .unwrap_or_else(|e| die(&format!("--arg u64:{rest}: {e}"))),
                );
            }
            "bool" => {
                return ParsedArg::Bool(
                    rest.parse::<bool>()
                        .unwrap_or_else(|e| die(&format!("--arg bool:{rest}: {e}"))),
                );
            }
            "str" => return ParsedArg::Str(rest.to_string()),
            _ => {} // unknown prefix → fall through to autotype
        }
    }
    if v.eq_ignore_ascii_case("true") {
        return ParsedArg::Bool(true);
    }
    if v.eq_ignore_ascii_case("false") {
        return ParsedArg::Bool(false);
    }
    if let Ok(n) = v.parse::<u64>() {
        return ParsedArg::U64(n);
    }
    ParsedArg::Str(v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{AgentDef, ConsistencyDef};
    use std::path::PathBuf;

    /// Build a minimal manifest pointing at a real ELF on disk so
    /// `positional_to_typed` can read its `.vos_meta` and resolve
    /// arg types. Skips the test if the example ELF isn't built.
    fn manifest_pointing_at(elf: &PathBuf) -> (Manifest, PathBuf) {
        let dir = elf.parent().unwrap().to_path_buf();
        let manifest = Manifest {
            space: "test".into(),
            version: None,
            hyperspace: None,
            registry_blob: None,
            heartbeat_interval_secs: None,
            agent: vec![AgentDef {
                name: "counter".into(),
                path: Some(elf.file_name().unwrap().into()),
                service: None,
                consistency: ConsistencyDef::Crdt,
                provides: vec![],
                init: Default::default(),
                replication_id: None,
                on_start: vec![],
                actors: vec![],
            }],
            worker: vec![],
            node: Default::default(),
        };
        (manifest, dir)
    }

    fn crdt_counter_elf() -> Option<PathBuf> {
        let workspace = env!("CARGO_MANIFEST_DIR");
        let path = PathBuf::from(format!(
            "{workspace}/../../examples/actors/crdt-counter/target/riscv64em-javm/release/crdt-counter.elf",
        ));
        path.exists().then_some(path)
    }

    #[test]
    fn positional_args_resolve_against_actor_metadata() {
        let Some(elf) = crdt_counter_elf() else {
            eprintln!("SKIP: crdt-counter not built");
            return;
        };
        let (manifest, dir) = manifest_pointing_at(&elf);
        // crdt-counter's `whois(name: String)` — the metadata
        // tags `name` as a String, so positional `alice` should
        // pack as `name=str:alice`.
        let typed = positional_to_typed(&manifest, &dir, "counter", "whois", &["alice".into()])
            .expect("positional_to_typed");
        assert_eq!(typed, vec!["name=str:alice".to_string()]);
    }

    #[test]
    fn positional_args_zero_arg_msg() {
        let Some(elf) = crdt_counter_elf() else {
            eprintln!("SKIP: crdt-counter not built");
            return;
        };
        let (manifest, dir) = manifest_pointing_at(&elf);
        // `inc` takes zero args. Zero positional args resolve to
        // an empty list (short-circuit before metadata lookup).
        let typed = positional_to_typed(&manifest, &dir, "counter", "inc", &[])
            .expect("positional_to_typed");
        assert!(typed.is_empty(), "expected empty list, got {typed:?}");
    }

    #[test]
    fn positional_args_arity_mismatch_errors() {
        let Some(elf) = crdt_counter_elf() else {
            eprintln!("SKIP: crdt-counter not built");
            return;
        };
        let (manifest, dir) = manifest_pointing_at(&elf);
        // `inc` takes zero args; passing one should fail with
        // a clear arity mismatch.
        let err = positional_to_typed(
            &manifest, &dir, "counter", "inc", &["nope".into()],
        )
        .expect_err("must fail arity check");
        assert!(err.contains("takes 0 arg"), "expected arity error, got: {err}");
    }

    #[test]
    fn positional_args_unknown_handler_errors() {
        let Some(elf) = crdt_counter_elf() else {
            eprintln!("SKIP: crdt-counter not built");
            return;
        };
        let (manifest, dir) = manifest_pointing_at(&elf);
        // Need at least one arg — zero args short-circuits to
        // Ok(Vec::new()) before the handler lookup runs.
        let err = positional_to_typed(
            &manifest, &dir, "counter", "nonsense", &["x".into()],
        )
        .expect_err("must fail unknown handler");
        assert!(err.contains("no handler named 'nonsense'"),
            "expected unknown-handler error, got: {err}");
    }
}
