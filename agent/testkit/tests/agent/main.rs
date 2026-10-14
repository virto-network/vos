//! The default agent (`agent/default`, built by `just build-agent`) on the
//! node's refine and accumulate hosts, step by step against the testkit.
//! The tests fail, not skip, when the programs are missing.

mod common;
mod hosts;
mod messages;
mod pricing;
mod sessions;
mod steps;
