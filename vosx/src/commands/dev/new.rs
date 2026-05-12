//! `vosx dev new` — provision a dev-project actor instance.
//!
//! Two steps under the hood:
//!
//! 1. Make sure the `dev-project` *program* exists in the
//!    space-registry catalog. If a (name, version) pair already
//!    matches the bundled hash, we skip; otherwise we publish
//!    the bundled blob (which `vosx/build.rs` baked from the
//!    working-tree actor build, falling back to
//!    `vosx/blobs/dev_project.elf`).
//!
//! 2. Install an instance under the operator-supplied name with
//!    `consistency = Crdt` (matching how `space *` provisions
//!    other agents). Init args are empty in v1 — the project's
//!    `new(name)` constructor just records the display name.

use serde::Serialize;
use space_registry::{STATUS_INSTANCE_EXISTS, STATUS_OK, STATUS_TAG_CONFLICT};

use crate::blob_store::{self, BlobHash};
use crate::bundled;
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::auto_replication_id;
use crate::output;
use crate::paths;

/// Catalog identity for the dev-project program. Stays fixed so
/// `dev new` runs idempotently and `space programs` listings
/// stay stable across daemon restarts.
const DEV_PROJECT_NAME: &str = "dev-project";
const DEV_PROJECT_VERSION: &str = "0.1.0";
/// Mirror of `vos::node::Consistency::Crdt`. Inlined so this
/// crate doesn't need to drag in the runtime's enum just for a
/// discriminant value.
const CONSISTENCY_CRDT: u8 = 2;

#[derive(Serialize)]
struct CreatedView<'a> {
    name: &'a str,
    program_name: &'a str,
    program_version: &'a str,
    program_hash: String,
    replication_id: String,
}

pub struct Args {
    pub space: String,
    pub name: String,
    pub replication_id: Option<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    // ── 1. Resolve the dev-project program bytes. The bundled
    //    blob is preferred — both `cargo install vosx` and the
    //    working-tree path go through this fall-through.
    let elf_bytes = bundled::dev_project_elf().ok_or_else(|| {
        anyhow::anyhow!(
            "no bundled dev-project ELF — rebuild vosx with the actor present \
             (cd actors/dev-project && cargo actor)"
        )
    })?;
    // Cache locally so `space install` resolves the hash later.
    let cached_hash =
        blob_store::cache_put(elf_bytes).map_err(|e| anyhow::anyhow!("cache dev-project: {e}"))?;

    DaemonClient::with_connect(&args.space, |client| {
        // ── 2. Publish if not already present.
        let existing = client.program(DEV_PROJECT_NAME, DEV_PROJECT_VERSION)?;
        let program_hash: BlobHash = match existing {
            Some(p) => {
                let on_disk = BlobHash(p.hash);
                if on_disk != cached_hash {
                    anyhow::bail!(
                        "{DEV_PROJECT_NAME}:{DEV_PROJECT_VERSION} already exists with a \
                         different hash ({on_disk}); bundled blob has hash {cached_hash}. \
                         Tags are immutable — bump the version, or unpublish first."
                    );
                }
                on_disk
            }
            None => {
                let status = client.publish(
                    DEV_PROJECT_NAME.to_string(),
                    DEV_PROJECT_VERSION.to_string(),
                    cached_hash.0.to_vec(),
                )?;
                match status {
                    STATUS_OK => cached_hash,
                    STATUS_TAG_CONFLICT => anyhow::bail!(
                        "{DEV_PROJECT_NAME}:{DEV_PROJECT_VERSION} TAG_CONFLICT mid-publish — \
                         race with another vosx? Retry.",
                    ),
                    other => anyhow::bail!("registry.publish returned status {other}"),
                }
            }
        };

        // ── 3. Install the instance.
        let replication_id = match args.replication_id.as_deref() {
            Some(hex) => {
                BlobHash::from_hex(hex)
                    .map_err(|_| anyhow::anyhow!("--replication-id must be 64 hex chars"))?
                    .0
            }
            None => auto_replication_id(&args.name, &program_hash.0),
        };

        let status = client.install(
            args.name.clone(),
            DEV_PROJECT_NAME.to_string(),
            DEV_PROJECT_VERSION.to_string(),
            program_hash.0.to_vec(),
            replication_id.to_vec(),
            CONSISTENCY_CRDT,
            Vec::new(),
            Vec::new(),
        )?;

        match status {
            STATUS_OK => {
                if output::is_json() {
                    output::print_json(&CreatedView {
                        name: &args.name,
                        program_name: DEV_PROJECT_NAME,
                        program_version: DEV_PROJECT_VERSION,
                        program_hash: program_hash.to_hex(),
                        replication_id: hex::encode(replication_id),
                    });
                } else {
                    println!("provisioned dev-project '{}'", args.name);
                    println!("  program        = {DEV_PROJECT_NAME}:{DEV_PROJECT_VERSION}");
                    println!("  program_hash   = {}", program_hash.to_hex());
                    println!("  replication_id = {}", hex::encode(replication_id));
                    println!();
                    println!(
                        "next: write source via the dev-project actor, then \
                         `vosx dev compile --space {} {}`",
                        args.space, args.name,
                    );
                }
                Ok(())
            }
            STATUS_INSTANCE_EXISTS => anyhow::bail!(
                "a project named '{}' is already installed in space '{}'; \
                 pick a different name or `vosx space uninstall {} {}` first",
                args.name,
                args.space,
                args.space,
                args.name,
            ),
            other => anyhow::bail!("registry.install returned status {other}"),
        }
    })
}

/// Touch the bundled paths so build.rs's `rerun-if-changed`
/// catches them — keeps `cargo install vosx` rebuilding when a
/// new blob is shipped under `blobs/`. Used only at workspace
/// build time; runtime callers go through `bundled::*`.
#[allow(dead_code)]
fn _bundled_paths_hint() -> Vec<std::path::PathBuf> {
    vec![paths::cache_root().join("blobs").join("dev_project.elf")]
}
