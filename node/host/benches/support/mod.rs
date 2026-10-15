//! What the log, store and tree benches share; each uses a part.
#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

/// The bench's arguments, without the `--bench` cargo adds.
pub fn args() -> Vec<String> {
    std::env::args()
        .skip(1)
        .filter(|arg| arg != "--bench")
        .collect()
}

/// Where the bench `name` keeps its data in this process: under `target/`,
/// since on the reference laptop `/tmp` is tmpfs.
pub fn data_dir(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("{name}-{}", std::process::id()))
}

/// Microseconds each of `count` operations took, `elapsed` in all.
pub fn us(elapsed: Duration, count: u64) -> f64 {
    elapsed.as_secs_f64() * 1e6 / count as f64
}
