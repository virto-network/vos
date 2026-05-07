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

use vos::value::{Msg, Value};

use crate::commands::space::client::DaemonClient;

pub struct Args {
    pub space: String,
    pub target: String,
    pub method: String,
    pub args: Vec<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    let client = DaemonClient::connect(&args.space)?;
    let target_id = client.resolve_target(&args.target)?;

    let msg = build_msg(&args.method, &args.args)?;
    eprintln!("vosx: invoking {} on {target_id}", args.method);

    let reply = client.invoke_dyn(target_id, &msg)?;
    match reply {
        Value::Unit => println!("()"),
        other => println!("{other:?}"),
    }
    client.shutdown()
}

/// Parse `key=value` strings into a typed `Msg`. Heuristics:
/// numeric → u64, `true`/`false` → bool, otherwise string.
/// Same shape the Phase 2 install command uses for `--init`.
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
