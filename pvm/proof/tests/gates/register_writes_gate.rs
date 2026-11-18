//! The multiply, divide and compare chips take their operands' bytes as
//! bytes without checking them: an operand is a register's value, read
//! through the register ledger, which holds a read to the last write, so
//! the chips rest on every write of a register being bytes. Each AIR source
//! that emits into the register relation is listed here with what holds its
//! values to bytes; a new one fails this test until it is listed, with its
//! own reason.

use std::path::{Path, PathBuf};

/// Every AIR source (not a prover's fill or interaction trace) emitting
/// into the register relation, how often it names the relation (so an
/// emission added to a listed file fails too), and what holds the bytes it
/// writes.
const REGISTER_RELATION: &[(&str, usize, &str)] = &[
    (
        "cpu/constraints/registers.rs",
        7,
        "a step's write is its Result, each byte Range256-checked (`memory::result_bytes`)",
    ),
    ("cpu/constraints/host_call.rs", 7, "reads alone"),
    (
        "cpu/constraints/mod.rs",
        3,
        "the relation's elements, no emission",
    ),
    (
        "register_memory_boundary.rs",
        3,
        "the initial writes, the verifier's boundary binding recomputing them from the public u64 registers",
    ),
    ("register_memory_closing.rs", 3, "reads alone"),
    (
        "device_boundary.rs",
        2,
        "the initial writes, preprocessed constants of the program's layout; the closing reads",
    ),
    ("register_memory.rs", 3, "the ledger, consuming"),
];

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the chips' sources") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_register_write_is_bytes() {
    let chips = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/chips");
    let mut files = Vec::new();
    sources(&chips, &mut files);
    let mentions = |text: &str| {
        text.matches("reg_lookup").count() + text.matches("RegisterMemoryLookupElements").count()
    };
    let mut emitting: Vec<(String, usize)> = files
        .iter()
        .filter(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            let prover = name == "fill.rs"
                || path
                    .components()
                    .any(|part| part.as_os_str() == "interaction")
                || name == "columns.rs";
            !prover
        })
        .filter_map(|path| {
            let text = std::fs::read_to_string(path).expect("a source");
            let relative = path
                .strip_prefix(&chips)
                .expect("under the chips")
                .to_string_lossy()
                .replace('\\', "/");
            Some((relative, mentions(&text))).filter(|(_, n)| *n > 0)
        })
        .collect();
    emitting.sort();
    let mut listed: Vec<(String, usize)> = REGISTER_RELATION
        .iter()
        .map(|&(path, n, _)| (path.to_string(), n))
        .collect();
    listed.sort();
    assert_eq!(
        emitting, listed,
        "the register relation's AIR sources changed: a new producer of a register \
         write must keep every byte it writes below 256 (the multiply, divide and \
         compare chips take operands unchecked) and be listed with its reason"
    );
}
