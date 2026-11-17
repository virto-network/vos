//! The personal space's directories, the owner's alone.

use std::path::Path;

/// `directory` and its parents made, the owner's alone.
pub(super) fn create_private(directory: &Path) -> Result<(), String> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))
}
