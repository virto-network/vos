//! The tests' wrap files: a final wrap's proof, its format (a little-endian
//! `u32`) and its public words (24 little-endian `u32`s), under the target's
//! tmp directory as `wrap/<name>.{proof,format,words}`, the Wasm harness's
//! input (`final-verifier/wasm/run`) and the fuzz targets'
//! `format::MASKED_WRAP` golden. Shared by the suites that write them, each
//! including this file; `recursion`'s `wrap_files` checks what they wrote.

use vos_pvm_final_verifier::PUBLIC_WORDS;

/// The directory the suites write their wraps under.
pub fn directory() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("wrap")
}

/// `proof`, its `format` and its public `words`, as `wrap/<name>.*`.
pub fn write(name: &str, format: u32, proof: &[u8], words: &[u32; PUBLIC_WORDS]) {
    let directory = directory();
    std::fs::create_dir_all(&directory).expect("the wrap's directory");
    let words: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    for (extension, bytes) in [
        ("proof", proof),
        ("format", &format.to_le_bytes()[..]),
        ("words", &words),
    ] {
        std::fs::write(directory.join(format!("{name}.{extension}")), bytes).expect("writes");
    }
}
