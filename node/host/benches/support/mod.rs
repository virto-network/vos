//! What the benches share; each uses a part.
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

/// The number the environment variable `name` holds, if it holds one.
pub fn count(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

/// The process's CPU time so far: user and system, in clock ticks.
pub fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    // The command may hold spaces: fields count from after its `)`.
    let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 2..].split(' ').collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

/// Microseconds each of `count` operations took, `elapsed` in all.
pub fn us(elapsed: Duration, count: u64) -> f64 {
    elapsed.as_secs_f64() * 1e6 / count as f64
}
