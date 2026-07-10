//! `space publish` — add a program to the catalog.

use serde::Serialize;
use space_registry::Status;

use crate::blob_store::{self, BlobHash, BlobSource};
use crate::bundled;
use crate::commands::space::client::DaemonClient;
use crate::commands::space::common::parse_program_ref;
use crate::output;

#[derive(Serialize)]
struct PublishedView {
    name: String,
    version: String,
    hash: String,
    /// `true` when the (name, version) was already in the catalog with
    /// this exact hash — a no-op re-publish (only reachable via
    /// `--bundled`, whose idempotency makes the provisioning flow safe
    /// to re-run).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    already_present: bool,
}

pub struct Args {
    pub space: String,
    /// `name` or `name:version`. `None` only when `--bundled` supplies
    /// its own catalog identity.
    pub program_ref: Option<String>,
    /// Blob source: file path, hash, ipfs:<cid>, or URL. `None` only
    /// when `--bundled` supplies the bytes.
    pub source: Option<String>,
    /// Publish a blob baked into this `vosx` binary instead of a
    /// `<source>`. The name selects the bundled program and its fixed
    /// catalog identity; the publish is idempotent (re-running with the
    /// same bytes is a no-op) so provisioning flows can call it freely.
    pub bundled: Option<String>,
}

pub fn run(args: Args) -> anyhow::Result<()> {
    if let Some(name) = args.bundled.as_deref() {
        return run_bundled(&args.space, name);
    }

    let program_ref = args.program_ref.ok_or_else(|| {
        anyhow::anyhow!("`space publish` needs a program ref (or `--bundled <name>`)")
    })?;
    let source = args.source.ok_or_else(|| {
        anyhow::anyhow!("`space publish` needs a blob source (or `--bundled <name>`)")
    })?;
    let (name, version) = parse_program_ref(&program_ref)?;

    // Resolve and cache the blob bytes locally.
    let source = BlobSource::parse(&source);
    let (hash, bytes) = blob_store::resolve(&source).map_err(|e| anyhow::anyhow!("blob: {e}"))?;

    DaemonClient::with_connect(&args.space, |client| {
        let status = client.publish(name.clone(), version.clone(), hash.0.to_vec())?;
        match status {
            Status::Ok => {
                forward_meta(client, &hash, &bytes);
                emit(&name, &version, &hash, false);
                Ok(())
            }
            Status::TagConflict => anyhow::bail!(
                "{name}:{version} already exists in the catalog with a different hash; \
                 tags are immutable",
            ),
            other => anyhow::bail!("publish returned status {other}"),
        }
    })
}

/// Catalog identity + ELF resolver for each bundled program. The tuple
/// is `(program_name, version, elf-getter)`; keep it in sync with the
/// blobs `vosx/build.rs` bakes.
fn bundled_program(
    name: &str,
) -> anyhow::Result<(&'static str, &'static str, Option<&'static [u8]>)> {
    match name {
        "dev-project" => Ok(("dev-project", "0.1.0", bundled::dev_project_elf())),
        other => anyhow::bail!("unknown bundled program '{other}' (known: dev-project)"),
    }
}

/// `--bundled` path: publish a baked-in program under its fixed
/// `(name, version)`, idempotently. Re-running with the same bytes is a
/// no-op; a stale catalog entry (same tag, different hash) is a hard
/// error since tags are immutable. This is the provisioning step
/// `space install <name>` builds on.
fn run_bundled(space: &str, bundled_name: &str) -> anyhow::Result<()> {
    let (prog_name, version, elf) = bundled_program(bundled_name)?;
    let elf = elf.ok_or_else(|| {
        anyhow::anyhow!(
            "no bundled {bundled_name} ELF — rebuild vosx with the actor present \
             (cd actors/{bundled_name} && cargo actor)"
        )
    })?;
    let cached_hash =
        blob_store::cache_put(elf).map_err(|e| anyhow::anyhow!("cache {bundled_name}: {e}"))?;

    DaemonClient::with_connect(space, |client| {
        let already_present = match client.program(prog_name, version)? {
            Some(existing) => {
                let on_disk = BlobHash(existing.hash);
                if on_disk != cached_hash {
                    anyhow::bail!(
                        "{prog_name}:{version} already exists with a different hash ({on_disk}); \
                         bundled blob has hash {cached_hash}. Tags are immutable — bump the \
                         version, or unpublish first."
                    );
                }
                true
            }
            None => {
                let status = client.publish(
                    prog_name.to_string(),
                    version.to_string(),
                    cached_hash.0.to_vec(),
                )?;
                match status {
                    Status::Ok => {}
                    Status::TagConflict => anyhow::bail!(
                        "{prog_name}:{version} TAG_CONFLICT mid-publish — race with another \
                         vosx? Retry.",
                    ),
                    other => anyhow::bail!("registry.publish returned status {other}"),
                }
                false
            }
        };
        // Forward the schema (idempotent) so dynamic dispatch resolves
        // types for the installed instance — even if a prior run
        // published this program without it.
        forward_meta(client, &cached_hash, elf);
        emit(prog_name, version, &cached_hash, already_present);
        Ok(())
    })
}

/// Best-effort: forward a program's `.vos_meta` schema blob to the
/// registry (keyed by program hash) so `meta_for_instance` resolves for
/// agents installed off it — the precondition for schema-aware dynamic
/// dispatch. A blob with no meta section, or a non-admin node, is a
/// no-op (the row arrives via sync / coercion falls back to the
/// heuristic), so failure never blocks the publish.
fn forward_meta(client: &DaemonClient, hash: &BlobHash, elf_bytes: &[u8]) {
    let Some(meta_blob) = vos::metadata::raw_section_from_elf(elf_bytes) else {
        return;
    };
    if let Err(e) = client.register_meta(hash.0.to_vec(), meta_blob) {
        tracing::debug!("register_meta for bundled/published program skipped: {e}");
    }
}

fn emit(name: &str, version: &str, hash: &BlobHash, already_present: bool) {
    if output::is_json() {
        output::print_json(&PublishedView {
            name: name.to_string(),
            version: version.to_string(),
            hash: hash.to_hex(),
            already_present,
        });
    } else if already_present {
        println!("{name}:{version} already published");
        println!("  hash = {hash}");
    } else {
        println!("published {name}:{version}");
        println!("  hash = {hash}");
    }
}
