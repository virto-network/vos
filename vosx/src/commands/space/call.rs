//! `space call` — generic actor invoke against a running daemon.
//!
//! A thin alias for the dynamic dispatcher: `vosx space call <space>
//! <target> <method> [k=v …]` forwards to the exact same path as
//! `vosx <target> <method> [k=v …] --space <space>`. The dynamic
//! surface is a strict superset — schema-aware arg coercion (typed
//! against the handler's declared arg types, not just the u64→bool→str
//! heuristic), `--out` reply diversion, `#[msg(job)]` job-driving,
//! per-handler timeouts, and the universal `__stop`/`__describe` verbs
//! — so `space call` keeps working for the docs/scripts that spell it
//! out while all the behaviour lives in one place.
//!
//! Examples:
//!
//! ```text
//! $ vosx space call demo registry programs
//! $ vosx space call demo counter add a=2 b=3
//! ```

use crate::commands::dynamic;

pub struct Args {
    pub space: String,
    pub target: String,
    pub method: String,
    pub args: Vec<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    // Reconstruct the dynamic-dispatch argv: `<target> <method> k=v…
    // --space <space>`. The global `--format` was already applied by
    // clap's top-level parse (output::set), so it doesn't need
    // threading here. `dispatch` re-derives the target/method/args and
    // dials the daemon exactly as the bare `vosx <target> …` form does.
    let mut argv: Vec<String> = Vec::with_capacity(args.args.len() + 4);
    argv.push(args.target);
    argv.push(args.method);
    argv.extend(args.args);
    argv.push("--space".to_string());
    argv.push(args.space);
    dynamic::dispatch(&argv)
}
