//! The guest programs this repository builds: the agent's programs, by
//! their names in `programs.toml` (`just build-programs`), and the test
//! actors (`just build-test-actors`); linked or derived as an install
//! derives them, and their methods by name: for the tests and benches of
//! the testkit and of the node.
//!
//! A guest workspace whose sources changed since its recipe last built it
//! is refused: a test never runs a program the tree no longer builds.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use vos_abi::ids::{MethodId, ProgramHash};
use vos_abi::records::Derivation;
use vos_abi::schema::Schema;
use vos_pvm_compiler::Derived;

/// The repository's root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The agent's guest programs' names, as `programs.toml` lists them.
fn listed() -> &'static [String] {
    static LISTED: OnceLock<Vec<String>> = OnceLock::new();
    LISTED.get_or_init(|| {
        include_str!("../../../programs.toml")
            .lines()
            .filter_map(|line| line.strip_prefix("name = \""))
            .map(|name| name.trim_end_matches('"').to_string())
            .collect()
    })
}

/// A guest workspace's sources: the newest change of its manifest, its
/// lock file and its toolchain file, of the guests' target specification,
/// and of each of its packages and their path dependencies, every one
/// inside the repository (a package's manifest, its build script and its
/// `src`). One `cargo metadata` a workspace, a process.
fn newest_source(workspace: &'static str) -> SystemTime {
    static NEWEST: Mutex<BTreeMap<&'static str, SystemTime>> = Mutex::new(BTreeMap::new());
    let mut newest = NEWEST
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *newest.entry(workspace).or_insert_with(|| {
        let root = root().canonicalize().expect("the repository's root");
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let output = std::process::Command::new(cargo)
            .args([
                "metadata",
                "--format-version",
                "1",
                "--offline",
                "--manifest-path",
            ])
            .arg(root.join(workspace).join("Cargo.toml"))
            .output()
            .expect("cargo metadata runs");
        assert!(
            output.status.success(),
            "cargo metadata of {workspace}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Each package's manifest: the path dependencies are those under
        // the repository's root and outside any target directory.
        let metadata = String::from_utf8(output.stdout).expect("UTF-8");
        let mut time = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"]
            .iter()
            .map(|file| modified(&root.join(workspace).join(file)))
            .chain([modified(&root.join("pvm/guest/riscv64em-vos.json"))])
            .max()
            .expect("the workspace's files");
        for manifest in metadata
            .split("\"manifest_path\":\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .map(PathBuf::from)
            .filter(|manifest| manifest.starts_with(&root))
        {
            let package = manifest.parent().expect("a manifest's directory");
            time = time.max(modified(&manifest));
            time = time.max(modified(&package.join("build.rs")));
            time = time.max(newest_under(&package.join("src")));
        }
        time
    })
}

fn modified(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// The newest change of a file under `directory`.
fn newest_under(directory: &Path) -> SystemTime {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return SystemTime::UNIX_EPOCH;
    };
    entries
        .flatten()
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => newest_under(&entry.path()),
            _ => modified(&entry.path()),
        })
        .max()
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

/// The stamp a guest workspace's build recipe leaves beside its ELFs once
/// every one is built.
const STAMP: &str = ".built";

/// Guest `name`'s ELF in `workspace`'s target, built by `recipe`: there,
/// and the workspace built since its sources last changed (the recipe's
/// stamp no older than them).
fn guest(workspace: &'static str, name: &str, recipe: &str) -> PathBuf {
    let built = root().join(workspace).join("target/riscv64em-vos/release");
    let path = built.join(format!("{name}.elf"));
    assert!(path.exists(), "{}: run `just {recipe}`", path.display());
    assert!(
        modified(&built.join(STAMP)) >= newest_source(workspace),
        "{} is older than its sources: run `just {recipe}`",
        path.display()
    );
    path
}

/// The ELF of the agent's guest program `name`, a name of
/// `programs.toml`: `vos-agent`, `vos-credentials`, ...
pub fn program_elf(name: &str) -> PathBuf {
    assert!(
        listed().iter().any(|listed| listed == name),
        "{name} is no program of programs.toml"
    );
    guest("agent/programs", name, "build-programs")
}

/// The agent's guest program `name`'s ELF, its package, as its crate
/// builds it.
pub fn program_package(name: &str) -> Vec<u8> {
    read(&program_elf(name))
}

/// The agent's guest program `name`, linked.
pub fn program(name: &str) -> Vec<u8> {
    link(&program_elf(name))
}

/// The default agent, linked.
pub fn agent() -> Vec<u8> {
    program("vos-agent")
}

/// Test actor `name`'s ELF.
pub fn actor_elf(name: &str) -> PathBuf {
    guest("agent/test-actors", name, "build-test-actors")
}

fn read(elf: &Path) -> Vec<u8> {
    std::fs::read(elf).unwrap_or_else(|error| panic!("{}: {error}", elf.display()))
}

fn link(elf: &Path) -> Vec<u8> {
    vos_pvm_compiler::link_elf_spi(&read(elf)).expect("links")
}

/// Test actor `name`'s ELF, its package, as a crate builds it.
pub fn package(name: &str) -> Vec<u8> {
    read(&actor_elf(name))
}

/// Test actor `name`, derived from its ELF as an install derives it: its
/// program, its kernels by method, and its schema. Derived once a process.
pub fn derived(name: &str) -> Derived {
    derived_once(actor_elf(name))
}

/// The agent's guest program `name`, derived from its ELF as an install
/// derives it. Derived once a process.
pub fn program_derived(name: &str) -> Derived {
    derived_once(program_elf(name))
}

/// The ELF at `elf`, derived once a process.
fn derived_once(elf: PathBuf) -> Derived {
    static DERIVED: Mutex<BTreeMap<PathBuf, Derived>> = Mutex::new(BTreeMap::new());
    let mut derived = DERIVED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    derived
        .entry(elf)
        .or_insert_with_key(|elf| vos_pvm_compiler::derive(&read(elf)).expect("derives"))
        .clone()
}

/// The derivation of an actor program a test holds alone, linked or built:
/// no kernels, and no ELF it names.
pub fn bare(program: ProgramHash) -> Derivation {
    Derivation {
        program,
        kernels: Vec::new(),
        elf: [0; 32],
        transpiler: vos_pvm_compiler::TRANSPILER_VERSION,
        heap: 0,
        references: Vec::new(),
    }
}

/// The kernel of test actor `name`'s attestable method `method`.
pub fn kernel(name: &str, method: &str) -> Vec<u8> {
    let derived = derived(name);
    let id = self::method(&derived.actor, method);
    derived
        .kernels
        .into_iter()
        .find(|(bound, _)| *bound == id.0)
        .map(|(_, kernel)| kernel)
        .unwrap_or_else(|| panic!("{name} has no attestable {method}"))
}

/// Test actor `name`, linked.
pub fn actor(name: &str) -> Vec<u8> {
    link(&actor_elf(name))
}

/// The default agent, linked, and the counter actor, linked and as its
/// package, the ELF an install takes.
pub struct Programs {
    pub agent: Vec<u8>,
    pub counter: Vec<u8>,
    pub counter_elf: Vec<u8>,
}

impl Programs {
    pub fn load() -> Self {
        Self {
            agent: agent(),
            counter: actor("counter"),
            counter_elf: package("counter"),
        }
    }

    /// The counter's method `name`.
    pub fn method(&self, name: &str) -> MethodId {
        method(&self.counter, name)
    }
}

/// The tag of an actor's table or committed map named `name`, as
/// `#[actor]` derives it.
pub fn table_tag(name: &str) -> u32 {
    vos_abi::ids::derive_id("vos/table/", name)
}

/// The schema `program` carries.
pub fn schema(program: &[u8]) -> Schema {
    let parsed = vos_pvm::spi::parse_standard_program(program).expect("a standard program");
    Schema::read(&parsed.ro_data).expect("its schema")
}

/// The id of `program`'s method `name`.
pub fn method(program: &[u8], name: &str) -> MethodId {
    schema(program)
        .method_id(name)
        .unwrap_or_else(|| panic!("no method {name}"))
}

/// A standard program of exactly `len` bytes, its code one trap and its
/// read-write data the rest: a service's code at a size bound.
pub fn sized(len: usize) -> Vec<u8> {
    let code = [0, 1, 1, 0, 1];
    let rw = len - 15 - code.len();
    assert!(rw < 1 << 24, "read-write data past 2^24 bytes");
    let mut blob = vec![0, 0, 0];
    blob.extend_from_slice(&(rw as u32).to_le_bytes()[..3]);
    blob.extend_from_slice(&[0, 0, 0x00, 0x10, 0x00]);
    blob.resize(blob.len() + rw, 0);
    blob.extend_from_slice(&(code.len() as u32).to_le_bytes());
    blob.extend_from_slice(&code);
    debug_assert_eq!(blob.len(), len);
    blob
}
