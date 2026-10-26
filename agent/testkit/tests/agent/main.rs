//! The default agent (`agent/default`, built by `just build-agent`) on the
//! node's refine and accumulate hosts, step by step against the testkit.
//! The tests fail, not skip, when the programs are missing.

mod common;
mod credentials;
mod hosts;
mod jam;
mod limits;
mod messages;
mod pricing;
mod reads;
mod representative;
mod sessions;
mod steps;
mod tracking;
mod workflows;
