//! Dev extension — compiles + publishes PVM actors from a
//! dev-project actor's tree.
//!
//! Bridges two parts of the VOS toolchain that today require an
//! out-of-band scripting step:
//!
//! 1. **dev-project actor** (PVM, `actors/dev-project/`) — a
//!    content-addressed object store + commit DAG that holds
//!    each project's source as blobs.
//! 2. **space-registry actor** (PVM, `actors/space-registry/`) —
//!    the catalog of programs an agent can install and run.
//!
//! Agents put source code into a dev-project, hand the project's
//! commit to `compile()`, and either pick up the resulting ELF
//! blob hash or pass it directly through `publish()` to land in
//! the space registry. Both calls record a commit on the project
//! so the build / publish history is auditable from the same DAG
//! as the source edits.
//!
//! ## Lifecycle
//!
//! Plain **actor-mode** extension (`#[actor]` / `#[messages]`) — request-driven,
//! no `run()` loop. The host drives one invoke (`compile` / `publish`) to
//! completion at a time on this agent's thread; each handler `ctx.ask_dispatch`s
//! the dev-project + registry actors over the host invoke path (reaches the PVM
//! actors, status-framed so a failed ask is distinguishable from an empty
//! reply). There is no `run()` loop and no `stop` handler — the host's generic
//! `__stop` (`vosx dev stop`) quiesces this one agent — and no shared state: the
//! handlers reach the host purely through their `&mut Context`.

use vos::prelude::*;

mod compile;
mod deps;
mod publish;

#[actor(caps = ["fs.cache", "fs.tempdir", "net.libp2p.dial", "process.spawn"])]
pub struct DevExtension {}

#[messages]
impl DevExtension {
    pub fn new() -> Self {
        DevExtension {}
    }

    /// Compile a project commit → PVM ELF, persist it to the blob cache, and
    /// record a build commit on the project's `builds` branch. Replies with the
    /// rkyv-encoded [`dev_project::HashResult`] (build commit hash on success,
    /// or a `COMPILE_STATUS_*` code) — `Value::Bytes` on the wire, as the
    /// `vosx dev compile` command decodes.
    #[msg(cli)]
    async fn compile(
        &mut self,
        project_id: u32,
        commit: Vec<u8>,
        ctx: &mut Context<Self>,
    ) -> Vec<u8> {
        let result = compile::compile_and_record(ctx, project_id, commit).await;
        result.encode()
    }

    /// Publish a build commit's ELF to the space registry + record an
    /// INTENT_PUBLISH commit on the project's `publishes` branch. Replies with
    /// the rkyv-encoded [`dev_project::HashResult`] (publish commit hash on
    /// success, or a `PUBLISH_STATUS_*` code).
    #[msg(cli)]
    async fn publish(
        &mut self,
        project_id: u32,
        build_commit: Vec<u8>,
        name: String,
        version: String,
        ctx: &mut Context<Self>,
    ) -> Vec<u8> {
        let result = publish::publish(ctx, project_id, build_commit, name, version).await;
        result.encode()
    }
}

/// The dev extension's actor [`vos::Context`] — the handle every helper threads
/// through to reach the dev-project + space-registry actors via
/// `ctx.ask_dispatch` (the host invoke path).
pub(crate) type DevCtx = vos::Context<DevExtension>;

pub use compile::{
    COMPILE_STATUS_BAD_PATH, COMPILE_STATUS_BAD_REPLY, COMPILE_STATUS_BLOB_NOT_FOUND,
    COMPILE_STATUS_CARGO_FAILED, COMPILE_STATUS_COMMIT_NOT_FOUND, COMPILE_STATUS_ELF_NOT_FOUND,
    COMPILE_STATUS_IO, COMPILE_STATUS_RECORD_FAILED, COMPILE_STATUS_TRANSPILE_FAILED,
    COMPILE_STATUS_TRANSPORT,
};
pub use publish::{
    PUBLISH_STATUS_BAD_BUILD_TAG, PUBLISH_STATUS_BAD_INTENT, PUBLISH_STATUS_BLOB_NOT_FOUND,
    PUBLISH_STATUS_BUILD_FAILED, PUBLISH_STATUS_BUILD_NOT_FOUND, PUBLISH_STATUS_RECORD_FAILED,
    PUBLISH_STATUS_REGISTRY_REJECTED,
};
