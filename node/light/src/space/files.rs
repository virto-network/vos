//! The personal space's files: its directories and its state file, the
//! owner's alone, each write whole or not at all.

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

/// `bytes` at `path`, through a sibling file renamed into place, the file
/// and its directory synced.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let partial = path.with_extension("partial");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let written = options.open(&partial).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()
    });
    written
        .and_then(|()| std::fs::rename(&partial, path))
        // The rename itself kept across a power loss.
        .and_then(|()| match path.parent() {
            Some(directory) => std::fs::File::open(directory)?.sync_all(),
            None => Ok(()),
        })
        .map_err(|error| format!("{}: {error}", path.display()))
}
