//! Bounded database inspection without opening or repairing the source file.
//! This disposable private copy is never a destination seed or admission proof.

use std::fs;
use std::io::{Read as _, Seek as _};
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::sync::Arc;

const MAX_AUDIT_DATABASE_BYTES: u64 = 64 * 1024 * 1024;

pub(crate) fn with_registry_audit_copy<T>(
    source: &Path,
    audit_parent: &Path,
    expected_hash: Option<[u8; 32]>,
    audit: impl FnOnce(Arc<redb::Database>) -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let mut file = super::open_regular_file_nofollow(source)?;
    let before = file.metadata()?;
    anyhow::ensure!(
        before.len() != 0 && before.len() <= MAX_AUDIT_DATABASE_BYTES,
        "registry audit source exceeds its nonempty 64 MiB bound"
    );
    let original_hash = bounded_hash(&mut file, before.len())?;
    anyhow::ensure!(
        expected_hash.is_none_or(|hash| hash == original_hash),
        "registry audit source differs from its verified manifest"
    );
    fs::create_dir_all(audit_parent)?;
    let directory = super::temporary_sibling(&audit_parent.join("registry-seed"), "audit")?;
    fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let mut cleanup = super::PartialDirectory::new(directory.clone());
    let database_path = directory.join("registry.redb");
    let mut copy = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&database_path)?;
    file.rewind()?;
    anyhow::ensure!(
        std::io::copy(
            &mut std::io::Read::by_ref(&mut file).take(MAX_AUDIT_DATABASE_BYTES + 1),
            &mut copy,
        )? == before.len()
            && super::hash_file(&database_path)? == original_hash,
        "registry changed while copying for audit"
    );
    copy.sync_all()?;
    drop(copy);
    // redb opens/drop write bookkeeping even when callers issue only reads.
    // Those writes and any allocator activity are confined to this exact copy.
    let mut builder = redb::Database::builder();
    builder.set_cache_size(8 * 1024 * 1024);
    builder.set_repair_callback(|session| session.abort());
    let result = audit(Arc::new(builder.open(&database_path)?));
    // Recheck source identity and bytes even when the semantic audit refuses.
    let named = fs::symlink_metadata(source)?;
    let after = file.metadata()?;
    anyhow::ensure!(
        named.is_file()
            && !named.file_type().is_symlink()
            && named.dev() == before.dev()
            && named.ino() == before.ino()
            && named.len() == before.len()
            && after.dev() == before.dev()
            && after.ino() == before.ino()
            && after.len() == before.len()
            && bounded_hash(&mut file, before.len())? == original_hash,
        "registry audit source changed during verification"
    );
    fs::remove_file(&database_path)?;
    fs::remove_dir(&directory)?;
    cleanup.disarm();
    result
}

fn bounded_hash(file: &mut fs::File, expected_bytes: u64) -> anyhow::Result<[u8; 32]> {
    file.rewind()?;
    let mut input = std::io::Read::by_ref(file).take(MAX_AUDIT_DATABASE_BYTES + 1);
    let mut hash = blake2b_simd::Params::new().hash_length(32).to_state();
    let mut buffer = [0u8; 64 * 1024];
    let mut bytes = 0u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        anyhow::ensure!(
            bytes <= expected_bytes,
            "registry grew during bounded audit"
        );
        hash.update(&buffer[..read]);
    }
    anyhow::ensure!(
        bytes == expected_bytes,
        "registry shrank during bounded audit"
    );
    Ok(hash
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32-byte digest"))
}
