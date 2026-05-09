//! `vosx invoke <target> <msg> [--arg k=v]…` — send a typed
//! message to any actor in a hyperspace and print its reply.
//! Resolves names through the registry actor like everyone
//! else; for raw addressing pass `0xHEX`.

use std::path::Path;
use std::time::Duration;

use vos::Encode;
use vos::abi::service::ServiceId;
use vos::value::{Msg, TAG_DYNAMIC};

use crate::manifest::Manifest;
use crate::query::with_query_node;
use crate::util::die;

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
    // Resolve via the macro-generated `RegistryClient`. Returns
    // 0 when the name isn't registered; we surface that as
    // "not found" since the registry's own ID (also 0) is
    // never a useful resolution target.
    let id = registry::RegistryClient::at(node, ServiceId::REGISTRY)
        .resolve(target_str.to_string())
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
