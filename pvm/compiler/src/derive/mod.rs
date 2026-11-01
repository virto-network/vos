//! One ELF in, programs out: from the ELF an actor's crate builds, the
//! actor's program and one kernel per attestable method.
//!
//! - **The actor's program** is the ELF linked from its entry, `_start`, as
//!   [`crate::link_elf_spi`] links it. Its workflows are in it, routed by
//!   method.
//! - **A kernel** is the ELF linked from one attestable method's entry
//!   alone: the code its relocations reach from the entry (calls, PC-relative
//!   pairs, absolute data relocations, switch tables) and direct branches,
//!   and the data they reach, with an instruction-0 prologue: it reads the
//!   method's arguments through the witness input into pages of its own,
//!   calls the entry on them, and returns to the halt address with the
//!   output in φ7 and φ8 and the io-hash in φ9 to φ12. The entries are the
//!   ELF's table `VOS_ATTEST`, each an attestable method's id and its entry.
//!
//! **A kernel's memory starts the same for every run:** its arguments are
//! read, not laid out, so the loader maps none and leaves φ8 at 0, and the
//! root of its initial memory is a constant of the kernel.
//!
//! **Reachability follows relocations,** so an ELF without them, or with a
//! relocation type the linker does not follow, is refused, as is one whose
//! code lies in more than one section. The heuristic scan for code-like
//! values in data may add targets, never prune one. A code pointer whose
//! target was pruned becomes an address no jump table reaches, and a branch
//! to pruned code reaches a trap: a missed target can only trap, never run
//! something else. A data object reached is kept whole, from the symbol at
//! or before its address to the next, or as far as a sized symbol covering
//! it reaches, and so is the object of the symbol a relocation names, where
//! its addend points elsewhere; data no reachable code names is zeros in
//! the kernel, its addresses unchanged.
//!
//! **A heap per kind of invocation:** an ELF's heap arena, its `.vos_heap`
//! section, ends its read-write data. The actor's program and each kernel
//! hold its first [`INVOCATION_HEAP`] bytes, all a handler or a kernel
//! maps; the pages past them, [`Derived::heap`], a workflow's machine maps
//! past its program's. So a kernel's memory, laid out by its program
//! alone, is the same whatever heap its actor declares.
//!
//! **A kernel makes no host call but the precompiles and its witness
//! input:** one whose reachable code does is refused, naming the chain of
//! functions from the entry to the call. A node's kernel may call BLAKE2b's
//! precompile and Poseidon2's; a **device kernel** (`#[attestable(device)]`,
//! its table entry marked) calls Poseidon2's and never BLAKE2b's, so its
//! shape holds neither BLAKE2b nor its AND table.
//! Its schema kind is `Device`, and an auth guard's `device = "..."` must
//! name one.
//!
//! **A step's pages fit a class:** a node cuts a kernel's run before a
//! step, never inside one, so a step touching more pages than the shape's
//! largest class (24, or 17 for a kernel holding the Poseidon2 chip,
//! [`crate::shape::POSEIDON2_CLASSES`]) has no proof: a witness-input call
//! writing more than about 64 KiB at once (`vos_wire::abi::precompile::
//! WITNESS_INPUT`). The derivation does not see a run's calls; a kernel
//! reads a larger input in several.
//!
//! **A kernel's leaf fits the recursion:** each class of its shape gives a
//! leaf whose rows, bounded from the shape alone ([`crate::leaf`]), fit the
//! recursion AIR's padded shape; a kernel past it is refused, naming the
//! class and the rows.
//!
//! **Bounded work:** every lookup is logarithmic, and a kernel is built
//! from what its entry reaches alone, so a derivation's work grows with the
//! ELF once and with each kernel's reach and size, whatever the ELF claims.
//!
//! **Bit-reproducible:** the output's order comes from sorted sections,
//! symbols and addresses, never from a map's iteration, so the same ELF and
//! [`TRANSPILER_VERSION`] give the same bytes on any machine.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use crate::TranspileError;
use crate::linker::{
    Link, LinkedElf, STT_FUNC, Z_Z, direct_targets, in_ranges, merge_ranges, name_at, name_is,
    parse_linked_elf, range_at, raw_code_pointers, spi_blob, transpile_with, zone_round,
};
use crate::riscv::rv::{add, addi, auipc, b_type, jal, jalr, ld, lui, sub};
use crate::riscv::{self, decode_b_imm, decode_j_imm, op};

mod graph;
mod kernel;
mod prologue;

use graph::Graph;
use kernel::kernel;

/// The derivation's version: it changes whenever the bytes it derives from
/// the same ELF may, so a derived program's hash is pinned per version.
pub const TRANSPILER_VERSION: u32 = 3;

/// The bytes of its actor's heap arena a handler's or a kernel's program
/// holds, [`vos_wire::abi::INVOCATION_HEAP`], the most the SDK's allocator
/// gives one: a workflow's machine maps the rest.
pub const INVOCATION_HEAP: u64 = vos_wire::abi::INVOCATION_HEAP as u64;

/// A page of the PVM's memory.
const PAGE: u64 = vos_pvm::PVM_PAGE_SIZE as u64;

/// The most bytes a kernel's arguments hold: an attest's, at most a
/// request's.
const ARGUMENTS: u64 = vos_wire::abi::cap::REQUEST as u64;

/// The most bytes the input of a kernel that reads at a window's cut
/// holds: its arguments, then the served rows.
const SERVED_INPUT: u64 = ARGUMENTS + vos_wire::abi::cap::SERVED as u64;

/// What one witness-input call of a kernel that reads at a window's cut
/// asks for at most: a request's bytes, as any kernel's whole arguments,
/// so a segment holding the call touches no more pages than the shapes'
/// classes give one reading its arguments at once.
const SERVED_CHUNK: u64 = ARGUMENTS;

/// The `VOS_ATTEST` entry's method word: the method's id in its low 32
/// bits, and this bit for a `&self` method, whose kernel reads, after its
/// arguments, the rows a node serves it at a window's cut.
const READS_SERVED: u64 = 1 << 32;

/// The `VOS_ATTEST` entry's bit for a device kernel's method
/// (`vos_sdk::runtime::DEVICE`).
const DEVICE: u64 = 1 << 33;

/// The largest ELF a derivation reads: an install's body.
pub use vos_wire::abi::cap::MAX_ELF;

/// The most attestable methods an actor may have: a schema's methods.
const MAX_ATTESTABLES: usize = 1024;

/// A `VOS_ATTEST` entry's length: a method's id, then its entry's address,
/// eight bytes each.
const ATTEST_ENTRY: u64 = 16;

/// What an ELF derives: its actor's program, a kernel per attestable
/// method by its id in ascending order, the schema's section as the ELF's
/// `.vos_schema` holds it, the pages of its heap the programs leave out,
/// and the version that derived them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub actor: Vec<u8>,
    pub kernels: Vec<(u32, Vec<u8>)>,
    /// Each kernel's shape, by its position in `kernels`: the node's
    /// segment shape. A device kernel's is recorded alike but never proved,
    /// and not held to the recursion's leaves: a device proves it under its
    /// device profile, whose chips its code gives
    /// (`vos_pvm_proof::device::device_chips_of_code`).
    pub shapes: Vec<vos_wire::records::Shape>,
    /// The device kernels' methods (`#[attestable(device)]`), ascending.
    pub devices: Vec<u32>,
    pub schema: Vec<u8>,
    /// The pages of the actor's heap past its program's read-write data,
    /// which a workflow's machine maps there.
    pub heap: u32,
    pub transpiler_version: u32,
}

impl Derived {
    /// The derivation an install of the package `elf`, derived as this,
    /// names.
    pub fn derivation(&self, elf: &[u8]) -> vos_wire::records::Derivation {
        vos_wire::records::Derivation::new(
            elf,
            &self.actor,
            &self.kernels,
            &self.shapes,
            self.transpiler_version,
            self.heap,
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeriveError {
    #[error("the ELF holds {0} bytes, past {MAX_ELF}")]
    TooLarge(usize),
    #[error(transparent)]
    Transpile(#[from] TranspileError),
    #[error("the ELF holds no relocations: link it with `--emit-relocs`")]
    NoRelocations,
    #[error("the ELF holds relocation type {0}, which a derivation does not follow")]
    Relocation(u32),
    #[error("the ELF's code lies in {0} sections, not one")]
    CodeSections(usize),
    #[error("the ELF has no `.vos_schema` section")]
    NoSchema,
    #[error("the attestable methods' table: {0}")]
    Table(String),
    #[error(
        "the heap's arena, `.vos_heap`, at {start:#x} for {size:#x} bytes, does not end the \
         read-write data at {end:#x} from a page: build with the guest's linker script"
    )]
    Heap { start: u64, size: u64, end: u64 },
    #[error("a kernel's instruction at {0:#x} jumps statically to the halt address")]
    HaltTarget(u64),
    #[error("a kernel reaches code from {0:#x} to {1:#x}, which no code section holds whole")]
    Unreadable(u64, u64),
    #[error(
        "attestable method {method:#010x} makes host call {id:#x}, no precompile, through {}",
        chain.join(" -> ")
    )]
    HostCall {
        method: u32,
        id: u64,
        chain: Vec<String>,
    },
    #[error(
        "device kernel {method:#010x} reaches the BLAKE2b precompile through {}: its io-hash \
         and its shape hold no BLAKE2b",
        chain.join(" -> ")
    )]
    DeviceBlake2b { method: u32, chain: Vec<String> },
    #[error(
        "attestable method {method:#010x}'s kernel's class {class} leaf takes {rows:?} rows, \
         past the recursion's padded shape {:?}",
        crate::leaf::PADDED
    )]
    Leaf {
        method: u32,
        class: usize,
        rows: [usize; 3],
    },
}

/// Derive an actor's program and its kernels from its ELF.
pub fn derive(elf: &[u8]) -> Result<Derived, DeriveError> {
    if elf.len() > MAX_ELF {
        return Err(DeriveError::TooLarge(elf.len()));
    }
    let mut linked = parse_linked_elf(elf)?;
    if linked.relocations == 0 {
        return Err(DeriveError::NoRelocations);
    }
    if let Some(kind) = linked.unknown_relocation {
        return Err(DeriveError::Relocation(kind));
    }
    if linked.code_sections.len() > 1 {
        return Err(DeriveError::CodeSections(linked.code_sections.len()));
    }
    let schema = linked.schema.take().ok_or(DeriveError::NoSchema)?;
    let heap = invocation_heap(&mut linked)?;
    let actor = spi_blob(transpile_with(&linked, Link::Whole)?)?;
    let graph = Graph::new(&linked);
    let entries = attestables(&linked)?;
    kinds_as_declared(&schema, &entries)?;
    let devices: Vec<u32> = entries
        .iter()
        .filter(|entry| entry.device)
        .map(|entry| entry.method)
        .collect();
    let kernels: Vec<(u32, Vec<u8>)> = entries
        .into_iter()
        .map(|entry| Ok((entry.method, kernel(&graph, &entry)?)))
        .collect::<Result<_, DeriveError>>()?;
    let shapes = kernels
        .iter()
        .map(|(method, kernel)| {
            let shape = crate::shape::kernel_shape(kernel).expect("a kernel is a standard program");
            // No node cuts a device kernel into segments: its leaves are
            // never proved.
            if devices.contains(method) {
                return Ok(shape);
            }
            match crate::leaf::oversized_leaves(&shape).first() {
                Some(&(class, rows)) => Err(DeriveError::Leaf {
                    method: *method,
                    class,
                    rows,
                }),
                None => Ok(shape),
            }
        })
        .collect::<Result<_, DeriveError>>()?;
    Ok(Derived {
        actor,
        kernels,
        shapes,
        devices,
        schema,
        heap,
        transpiler_version: TRANSPILER_VERSION,
    })
}

/// Leave the heap's arena past [`INVOCATION_HEAP`] out of the read-write
/// data the ELF's programs hold: the pages left out, which a workflow's
/// machine maps. An arena that does not end that data, from a page, is
/// refused: its programs would not hold its first bytes alone.
fn invocation_heap(elf: &mut LinkedElf) -> Result<u32, DeriveError> {
    let Some((start, size)) = elf.heap else {
        return Ok(0);
    };
    let end = elf.rw_base + elf.rw_len;
    if start.saturating_add(size) != end || !start.is_multiple_of(PAGE) {
        return Err(DeriveError::Heap { start, size, end });
    }
    if size <= INVOCATION_HEAP {
        return Ok(0);
    }
    let kept = start + INVOCATION_HEAP;
    elf.rw_len = kept - elf.rw_base;
    Ok(((end.next_multiple_of(PAGE) - kept) / PAGE) as u32)
}

/// Whether each attestable entry reads the rows served at a window's cut
/// exactly when the schema, its section's bytes `schema`, declares its
/// method `Reading`, and is a device kernel's exactly when it declares it
/// `Device`; and whether each auth guard's device kernel names an entry
/// marked a device kernel's. An ELF with attestable entries and a schema
/// that does not read is refused.
fn kinds_as_declared(schema: &[u8], entries: &[AttestEntry]) -> Result<(), DeriveError> {
    use vos_wire::abi::Kind;
    let table = |why: String| DeriveError::Table(why);
    let schema = match vos_wire::schema::Schema::read(schema) {
        Ok(schema) => schema,
        // An ELF of no attestable method needs no schema that reads.
        Err(_) if entries.is_empty() => return Ok(()),
        Err(error) => return Err(table(format!("the schema does not read: {error:?}"))),
    };
    for entry in entries {
        let method = entry.method;
        let kind = schema
            .method(vos_wire::ids::MethodId(method))
            .map(|method| method.kind);
        if (kind == Some(Kind::Reading)) != (entry.input == Input::Served) {
            return Err(table(format!(
                "method {method:#010x}'s entry and its schema disagree on whether it reads \
                 the rows served at a window's cut"
            )));
        }
        if (kind == Some(Kind::Device)) != entry.device {
            return Err(table(format!(
                "method {method:#010x}'s entry and its schema disagree on whether it is a \
                 device kernel's"
            )));
        }
    }
    if let Some(method) = schema.methods.iter().find(|method| {
        method.kind == Kind::Device && !entries.iter().any(|entry| entry.method == method.id.0)
    }) {
        return Err(table(format!(
            "device kernel {:#010x} has no entry",
            method.id.0
        )));
    }
    devices_as_named(&schema, entries)
}

/// Whether each auth guard's `device = "..."` names a method whose entry
/// is marked a device kernel's.
fn devices_as_named(
    schema: &vos_wire::schema::Schema,
    entries: &[AttestEntry],
) -> Result<(), DeriveError> {
    for guarded in &schema.methods {
        let Some(vos_wire::schema::CredentialGuard::Auth {
            device: Some(device),
            ..
        }) = guarded.credential.as_deref()
        else {
            continue;
        };
        let named = core::str::from_utf8(device)
            .ok()
            .and_then(|name| schema.method_id(name));
        if !named.is_some_and(|id| {
            entries
                .iter()
                .any(|entry| entry.method == id.0 && entry.device)
        }) {
            return Err(DeriveError::Table(format!(
                "method {:#010x}'s auth guard names device kernel {:?}, which is no method's \
                 marked a device kernel's",
                guarded.id.0,
                String::from_utf8_lossy(device)
            )));
        }
    }
    Ok(())
}

/// An attestable method's entry in `VOS_ATTEST`: its id, its entry's
/// address, what its kernel reads, and whether it is a device kernel's.
#[derive(Clone, Copy, Debug)]
struct AttestEntry {
    method: u32,
    entry: u64,
    input: Input,
    device: bool,
}

/// What a kernel reads through its witness input: its arguments alone, or
/// after them the rows a node serves it at a window's cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Input {
    Arguments,
    Served,
}

impl Input {
    /// The most bytes its prologue reads.
    const fn most(self) -> u64 {
        match self {
            Input::Arguments => ARGUMENTS,
            Input::Served => SERVED_INPUT,
        }
    }

    /// The pages its prologue reads into, past the kernel's read-write
    /// data: room for one byte more than [`Input::most`], so an input that
    /// fills them is too long, and the prologue traps.
    const fn pages(self) -> u64 {
        (self.most() + 1).div_ceil(PAGE)
    }

    /// What one witness-input call asks for at most, where it is bounded.
    const fn chunk(self) -> Option<u64> {
        match self {
            Input::Arguments => None,
            Input::Served => Some(SERVED_CHUNK),
        }
    }
}

/// The ELF's attestable methods, their entries, what their kernels read and
/// which are device kernels', from its `VOS_ATTEST` table, by method id:
/// none without the table.
fn attestables(elf: &LinkedElf) -> Result<Vec<AttestEntry>, DeriveError> {
    let table = |why: &str| DeriveError::Table(why.to_string());
    let Some(symbol) = elf
        .symbols
        .iter()
        .find(|symbol| name_is(&elf.names, symbol.name, b"VOS_ATTEST"))
    else {
        return Ok(Vec::new());
    };
    if !symbol.size.is_multiple_of(ATTEST_ENTRY) {
        return Err(table("its size is no whole number of entries"));
    }
    if symbol.size / ATTEST_ENTRY > MAX_ATTESTABLES as u64 {
        return Err(table(&format!(
            "{} entries, past {MAX_ATTESTABLES}",
            symbol.size / ATTEST_ENTRY
        )));
    }
    let start = symbol
        .value
        .checked_sub(elf.ro_base)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| table("it lies outside the read-only data"))?;
    let bytes = start
        .checked_add(symbol.size as usize)
        .and_then(|end| elf.ro_data.get(start..end))
        .ok_or_else(|| table("it lies outside the read-only data"))?;
    let entry_at = |index: usize| symbol.value + index as u64 * ATTEST_ENTRY + 8;
    let count = bytes.len() / ATTEST_ENTRY as usize;
    let relocated: HashMap<u64, u64> = elf
        .data_relocs
        .iter()
        .copied()
        .filter(|&(at, _)| (entry_at(0)..entry_at(count)).contains(&at))
        .collect();
    let mut entries = BTreeMap::new();
    for (index, entry) in bytes.chunks_exact(ATTEST_ENTRY as usize).enumerate() {
        let word = u64::from_le_bytes(entry[..8].try_into().expect("eight bytes"));
        let raw = u64::from_le_bytes(entry[8..].try_into().expect("eight bytes"));
        let address = relocated.get(&entry_at(index)).copied().unwrap_or(raw);
        let (input, device) = match word & !u64::from(u32::MAX) {
            0 => (Input::Arguments, false),
            READS_SERVED => (Input::Served, false),
            DEVICE => (Input::Arguments, true),
            _ => {
                return Err(table(
                    "a method word past its id and one of its served and device bits",
                ));
            }
        };
        let method = word as u32;
        if !in_ranges(&elf.code_ranges, address) {
            return Err(table(&format!("method {method:#010x}'s entry is no code")));
        }
        if entries.insert(method, (address, input, device)).is_some() {
            return Err(table(&format!("method {method:#010x} has two entries")));
        }
    }
    Ok(entries
        .into_iter()
        .map(|(method, (entry, input, device))| AttestEntry {
            method,
            entry,
            input,
            device,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry that marks its next `ecall` and makes host call `id`, then
    /// returns.
    fn calling(id: i32) -> Vec<u8> {
        const CSRRW_MARK: u32 = 0x801 << 20 | 1 << 12 | 0x73;
        let li_t0 = ((id as u32) << 20) | 5 << 7 | op::OP_IMM;
        const ECALL: u32 = 0x73;
        const RET: u32 = 1 << 15 | op::JALR;
        [CSRRW_MARK, li_t0, ECALL, RET]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }

    /// Ids 110 to 114 are no precompile: a kernel that reaches one is
    /// refused, naming it, as one reaching any host call but a kernel's
    /// is; one reaching BLAKE2b's, Poseidon2's or its witness input derives.
    #[test]
    fn a_kernel_reaching_an_unknown_id_is_refused() {
        const ENTRY: u64 = 0x10_0000;
        let derived = |id| {
            let elf = LinkedElf::text(ENTRY, calling(id));
            kernel(&Graph::new(&elf), &entry(ENTRY, false))
        };
        for id in 110..=114 {
            match derived(id) {
                Err(DeriveError::HostCall {
                    method, id: called, ..
                }) => {
                    assert_eq!((method, called), (7, id as u64));
                }
                other => panic!("host call {id}: {:?}", other.map(|kernel| kernel.len())),
            }
        }
        for admitted in [
            vos_pvm::precompile::BLAKE2B_COMPRESS,
            vos_pvm::precompile::POSEIDON2,
            vos_pvm::precompile::WITNESS_INPUT,
        ] {
            assert!(derived(admitted as i32).is_ok(), "{admitted:#x}");
        }
    }

    /// A device kernel makes Poseidon2's call and its witness input's, and
    /// one that reaches BLAKE2b's precompile is refused, naming it, as one
    /// reaching an unknown id is.
    #[test]
    fn a_device_kernel_calls_poseidon2_and_never_blake2b() {
        const ENTRY: u64 = 0x10_0000;
        let derived = |id: u64| {
            let elf = LinkedElf::text(ENTRY, calling(id as i32));
            kernel(&Graph::new(&elf), &entry(ENTRY, true))
        };
        for admitted in [
            vos_pvm::precompile::POSEIDON2,
            vos_pvm::precompile::WITNESS_INPUT,
        ] {
            assert!(derived(admitted).is_ok(), "{admitted:#x}");
        }
        match derived(vos_pvm::precompile::BLAKE2B_COMPRESS) {
            Err(DeriveError::DeviceBlake2b { method, .. }) => assert_eq!(method, 7),
            other => panic!("{:?}", other.map(|kernel| kernel.len())),
        }
        match derived(110) {
            Err(DeriveError::HostCall { method, id, .. }) => assert_eq!((method, id), (7, 110)),
            other => panic!("{:?}", other.map(|kernel| kernel.len())),
        }
    }

    /// An entry's device mark agrees with its schema kind, `Device`, and an
    /// auth guard's `device = "..."` names a method whose entry is marked.
    #[test]
    fn a_device_kernels_mark_is_its_schemas() {
        use vos_wire::abi::Kind;
        use vos_wire::ids::MethodId;
        use vos_wire::schema::{CredentialGuard, MethodSchema, Schema};
        let method = |id: u32, name: &str, kind: Kind| MethodSchema {
            id: MethodId(id),
            name: name.as_bytes().to_vec(),
            kind,
            role: None,
            gas: None,
            linearizable: false,
            credential: None,
        };
        let guarded = |device: &str| MethodSchema {
            credential: Some(Box::new(CredentialGuard::Auth {
                name: b"login".to_vec(),
                device: Some(device.as_bytes().to_vec()),
                once: false,
            })),
            ..method(8, "login", Kind::Command)
        };
        let section = |kind: Kind, device: &str| {
            Schema {
                methods: vec![method(7, "auth", kind), guarded(device)],
                credentials: false,
            }
            .section()
        };
        let marked = [entry(0x1000, true)];
        let unmarked = [entry(0x1000, false)];
        assert!(kinds_as_declared(&section(Kind::Device, "auth"), &marked).is_ok());
        for (schema, entries) in [
            (section(Kind::Device, "auth"), &unmarked),
            (section(Kind::Stating, "auth"), &marked),
            (section(Kind::Stating, "auth"), &unmarked),
            (section(Kind::Device, "other"), &marked),
        ] {
            assert!(
                matches!(
                    kinds_as_declared(&schema, entries),
                    Err(DeriveError::Table(_))
                ),
                "{entries:?}"
            );
        }
        // An ELF with no kernel at all: a guard naming a device kernel, and
        // a device method of no entry.
        for kind in [Kind::Command, Kind::Device] {
            assert!(matches!(
                kinds_as_declared(&section(kind, "auth"), &[]),
                Err(DeriveError::Table(_))
            ));
        }
    }

    /// Method 7's entry at `at`, a device kernel's or a node's.
    fn entry(at: u64, device: bool) -> AttestEntry {
        AttestEntry {
            method: 7,
            entry: at,
            input: Input::Arguments,
            device,
        }
    }
}
