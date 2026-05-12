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
//! Service-mode extension — `run()` idles in a shutdown poll,
//! every actual work item is driven through
//! `vos_service_handle_invoke` from the registry-driven CLI
//! dispatch path. v1 of `run()` is a sleep loop; once an actual
//! background task arrives (cache eviction, dep prefetch, …),
//! it'll claim ownership of `run()` instead.

mod compile;
mod ext;
mod publish;

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

vos::service_main!(
    ext::DevExtension,
    caps = ["fs.tempdir", "process.spawn", "tokio-runtime",],
    cli = [stop],
);
