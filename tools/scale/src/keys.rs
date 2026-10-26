//! The harness's keys, kept on the coordinator beside what a deploy
//! shipped: its operator's, which every node lists, and its drivers',
//! which every node's API admits over QUIC as a transport, no authority.

use std::path::Path;

/// The operator key's seed file: the coordinator's alone.
pub const OPERATOR: &str = "operator.key";
/// The drivers' QUIC key's seed file, which their plans carry.
pub const DRIVER: &str = "driver.key";

/// The seed in the file at `path`, in hex; made at random, readable by its
/// owner only, if there is none.
pub fn seed(path: &Path) -> Result<[u8; 32], String> {
    let at = |error: std::io::Error| format!("{}: {error}", path.display());
    match std::fs::read_to_string(path) {
        Ok(text) => hex32(&text),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut seed = [0u8; 32];
            getrandom(&mut seed)?;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(at)?;
            file.write_all(hex::encode(seed).as_bytes()).map_err(at)?;
            Ok(seed)
        }
        Err(error) => Err(at(error)),
    }
}

/// 32 bytes from 64 hex digits.
pub fn hex32(text: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(text.trim(), &mut bytes).map_err(|error| format!("{text}: {error}"))?;
    Ok(bytes)
}

/// Bytes from the operating system's randomness.
fn getrandom(bytes: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(bytes))
        .map_err(|error| format!("/dev/urandom: {error}"))
}
