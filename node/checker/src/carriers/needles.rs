//! The needles: what a run must not show, each in every form a carrier
//! would hold it in.
//!
//! - bytes: as they are, in hex (lower and upper case, and its first 16
//!   characters in the carriers that leave) and as a `Debug` list;
//! - 32 bytes of M31 limbs (a Poseidon2-M31 root or digest): also the
//!   limbs' decimal list, as `P2Hash`'s and an array's `Debug` print them,
//!   the `M31(…)` list, and postcard's varint encoding;
//! - a number, in the carriers that leave: its decimal digits, its little-
//!   and big-endian bytes, and its `0x` hex;
//! - a register file: its values' little-endian bytes, their `Debug` list
//!   and hex;
//! - a debug output's text, in the carriers that leave.
//!
//! "The carriers that leave" are `Reach::Leaves`'s: a venue's own record
//! (`Reach::Recorded`) is searched in the other forms alone, the full ones
//! (a needle's `forms`, not its `leaving`).

use std::fmt;

use vos_node_prover::Internals;
use vos_wire::Decode;
use vos_wire::result::Attest;
use vos_wire::served::Served;

use super::{Kind, Reach};

/// The text each debug output prints, which a production build never does:
/// the PVM's instruction trace, the recompiler's registers at a run's entry
/// and exit and its native code's dump, `CPU_DUMP`'s rows,
/// `CPU_EXPR_DUMP`'s constraints and a segment's profile (`ZKPVM_PROFILE`).
pub const DEBUG_OUTPUTS: [&str; 7] = [
    "pvm-inst",
    "recompiler::run() entry",
    "recompiler::run() exit",
    "DUMP row ",
    "constraint #",
    "wrote native code to /tmp/pvm_native.bin",
    "trace_gen:",
];

/// The shortest bytes a needle is made of, and the fewest distinct bytes
/// among them: a shorter or plainer value (a small integer's eight bytes)
/// appears by chance. A row of such a value is still searched by its salt.
pub const SHORTEST: usize = 8;
pub const DISTINCT: usize = 4;

/// The domains `vos-wire` and its venues hash under, each a prefix of the
/// hashed bytes: a private value hashed under any of them is a needle too.
const DOMAINS: [&[u8]; 11] = [
    b"vos/call/1",
    b"vos/query/1",
    b"vos/workflow/1",
    b"vos/space/id",
    b"vos/space/v1",
    b"vos/anchor/v1",
    b"vos/space/register",
    b"vos/venue/jam",
    b"vos/io/v1",
    b"vos/statement/v1",
    b"vos/space/migrate",
];

/// M31's modulus: 32 bytes whose eight little-endian words are all below it
/// may be a Poseidon2-M31 hash.
const M31: u32 = (1 << 31) - 1;

/// A value a carrier must not hold, in each form it may take.
#[derive(Clone, Debug)]
pub struct Needle {
    pub kind: Kind,
    pub name: String,
    /// Searched in every carrier its kind reaches.
    forms: Vec<Vec<u8>>,
    /// Searched in the carriers that leave only: forms too short or too
    /// common to look for in a replica's own bytes.
    leaving: Vec<Vec<u8>>,
    /// The number it is, for a number's needle.
    value: Option<u64>,
}

/// How many distinct values `bytes` holds.
fn distinct(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

/// `values` as `Debug` lists them, without the brackets.
fn listed<T: fmt::Display>(values: &[T]) -> Vec<u8> {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
        .into_bytes()
}

/// `value` as postcard's varint lays it out.
fn varint(mut value: u32, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

impl Needle {
    /// `bytes`, as they are, in hex, and as a `Debug` list.
    pub fn bytes(kind: Kind, name: impl Into<String>, bytes: &[u8]) -> Option<Self> {
        if bytes.len() < SHORTEST || distinct(bytes) < DISTINCT {
            return None;
        }
        let lower = hex::encode(bytes);
        let upper = lower.to_uppercase();
        let mut leaving = Vec::new();
        if bytes.len() > 8 {
            leaving.push(lower.as_bytes()[..16].to_vec());
            leaving.push(upper.as_bytes()[..16].to_vec());
        }
        Some(Self {
            kind,
            name: name.into(),
            forms: vec![
                bytes.to_vec(),
                lower.into_bytes(),
                upper.into_bytes(),
                listed(bytes),
            ],
            leaving,
            value: None,
        })
    }

    /// [`Needle::bytes`], and, when its eight little-endian words are M31
    /// limbs, their decimal list, their `M31(…)` list and their postcard
    /// varints.
    pub fn field(kind: Kind, name: impl Into<String>, bytes: &[u8; 32]) -> Option<Self> {
        let mut needle = Self::bytes(kind, name, bytes)?;
        let limbs: Vec<u32> = bytes
            .chunks_exact(4)
            .map(|word| u32::from_le_bytes(word.try_into().expect("four bytes")))
            .collect();
        if limbs.iter().all(|&limb| limb < M31) {
            let wrapped: Vec<String> = limbs.iter().map(|limb| format!("M31({limb})")).collect();
            let mut varints = Vec::new();
            for &limb in &limbs {
                varint(limb, &mut varints);
            }
            needle.forms.push(listed(&limbs));
            needle.forms.push(wrapped.join(", ").into_bytes());
            needle.forms.push(varints);
        }
        Some(needle)
    }

    /// `value`'s decimal digits, its `0x` hex, and its little- and
    /// big-endian bytes, as eight and as four, in the carriers that leave:
    /// each byte form of at least [`DISTINCT`] distinct bytes, as a plainer
    /// one (a small count's, a run of `0xff`'s) is in any binary carrier by
    /// chance.
    pub fn number(kind: Kind, name: impl Into<String>, value: u64) -> Self {
        let mut leaving = vec![
            value.to_string().into_bytes(),
            format!("{value:#x}").into_bytes(),
            format!("{value:#X}").into_bytes(),
        ];
        let mut binary = vec![value.to_le_bytes().to_vec(), value.to_be_bytes().to_vec()];
        if let Ok(value) = u32::try_from(value) {
            binary.push(value.to_le_bytes().to_vec());
            binary.push(value.to_be_bytes().to_vec());
        }
        leaving.extend(
            binary
                .into_iter()
                .filter(|bytes| distinct(bytes) >= DISTINCT),
        );
        Self {
            kind,
            name: name.into(),
            forms: Vec::new(),
            leaving,
            value: Some(value),
        }
    }

    /// A register file's values, in order: their little-endian bytes and
    /// their `Debug` list, and their hex in the carriers that leave.
    pub fn registers(name: impl Into<String>, values: &[u64]) -> Self {
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        Self {
            kind: Kind::Register,
            name: name.into(),
            forms: vec![bytes.clone(), listed(values)],
            leaving: vec![hex::encode(&bytes).into_bytes()],
            value: None,
        }
    }

    /// A debug output's text, in the carriers that leave.
    pub fn text(kind: Kind, name: impl Into<String>, text: &str) -> Self {
        Self {
            kind,
            name: name.into(),
            forms: Vec::new(),
            leaving: vec![text.as_bytes().to_vec()],
            value: None,
        }
    }

    /// Whether its kind is searched in a carrier of `reach`.
    pub(super) fn reaches(&self, reach: Reach) -> bool {
        reach != Reach::Role || self.kind.nowhere() || self.kind == Kind::Register
    }

    /// Its forms searched in a carrier of `reach`.
    pub(super) fn forms(&self, reach: Reach) -> impl Iterator<Item = &Vec<u8>> {
        let leaves = reach == Reach::Leaves;
        self.forms
            .iter()
            .chain(self.leaving.iter().filter(move |_| leaves))
    }
}

/// The needles of a run.
#[derive(Clone, Debug, Default)]
pub struct Needles(pub Vec<Needle>);

impl Needles {
    pub fn push(&mut self, needle: Option<Needle>) {
        self.0.extend(needle);
    }

    /// Drop every number's needle whose value is one of `public`: a
    /// venue's layout constants, which its storage holds and any run's
    /// numbers may equal, as a register's needle drops what the run's
    /// entry state holds.
    pub fn except(&mut self, public: &[u64]) {
        self.0
            .retain(|needle| needle.value.is_none_or(|value| !public.contains(&value)));
    }

    /// The needles of `kind` whose name holds `naming`.
    pub fn named<'a>(&'a self, kind: Kind, naming: &'a str) -> impl Iterator<Item = &'a Needle> {
        self.0
            .iter()
            .filter(move |needle| needle.kind == kind && needle.name.contains(naming))
    }

    /// What a statement's proof was built from ([`Internals`]): its node
    /// proofs, step counts and the gas its re-run had left, memory roots,
    /// registers and the wrap's randomness. A step count of a power of two is a class's budget,
    /// the kernel's public shape, and is not searched; nor a register below
    /// 2^24, whose digits a log line holds by chance, nor one the run's
    /// entry state holds.
    pub fn internals(&mut self, statement: &str, internals: &Internals) {
        for proof in &internals.proofs {
            let name = |what: &str| format!("{statement}: {}'s {what}", proof.name);
            for (tree, root) in proof.roots.iter().enumerate() {
                self.push(Needle::field(
                    Kind::NodeProof,
                    name(&format!("tree {tree}")),
                    root,
                ));
            }
            for (at, digest) in proof.digests.iter().enumerate() {
                self.push(Needle::field(
                    Kind::NodeProof,
                    name(&format!("digest {at}")),
                    digest,
                ));
            }
            // Three windows of its encoding: its start, middle and end.
            let encoding = &proof.encoding;
            let window = 64.min(encoding.len());
            for at in [0, encoding.len() / 2, encoding.len() - window] {
                let at = at.min(encoding.len() - window);
                self.push(Needle::bytes(
                    Kind::NodeProof,
                    name(&format!("encoding at {at}")),
                    &encoding[at..at + window],
                ));
            }
        }
        for &steps in internals.steps.iter().chain([&internals.run_steps]) {
            if !steps.is_power_of_two() && steps > 0xff {
                self.0.push(Needle::number(
                    Kind::StepCount,
                    format!("{statement}: {steps} steps"),
                    steps,
                ));
            }
        }
        self.0.push(Needle::number(
            Kind::StepCount,
            format!("{statement}: the gas its re-run left"),
            vos_node_prover::RERUN_GAS.saturating_sub(internals.run_steps),
        ));
        for root in &internals.memory_roots {
            self.push(Needle::field(
                Kind::MemoryRoot,
                format!("{statement}: a memory root"),
                root,
            ));
        }
        for (at, (what, bytes)) in internals.wrap_randomness.iter().enumerate() {
            self.push(Needle::bytes(
                Kind::WrapRandomness,
                format!("{statement}: the wrap's {what} ({at})"),
                bytes,
            ));
        }
        let private = Internals::PRIVATE_REGISTERS;
        // The run's entry state is its program's: a value it holds (the
        // halt address, the stack's top) is public wherever it recurs.
        let entry = internals
            .registers
            .first()
            .map_or(&[][..], |registers| &registers[private.clone()]);
        for (boundary, registers) in internals.registers.iter().enumerate() {
            let file = &registers[private.clone()];
            self.0.push(Needle::registers(
                format!("{statement}: boundary {boundary}'s φ0..φ8"),
                file,
            ));
            for (index, &value) in file.iter().enumerate() {
                if value >= 1 << 24 && !entry.contains(&value) {
                    self.0.push(Needle::number(
                        Kind::Register,
                        format!("{statement}: boundary {boundary}'s φ{index}"),
                        value,
                    ));
                }
            }
        }
    }

    /// What `attest`'s record holds privately, its witness its kernel's
    /// `arguments` bytes and then, for a statement at a window's cut, the
    /// rows served: the rows, their salts and the cut's roots and paths, each
    /// part of its arguments that is not a public argument's encoding, and
    /// the plain and domain-prefixed hashes of each. A rootless statement's
    /// witness is its arguments alone. Fails if the rows do not decode
    /// where the arguments end, or a rootless witness runs past them.
    pub fn attest(&mut self, statement: &str, attest: &Attest, arguments: usize) {
        let witness = &attest.witness_input;
        let (arguments, rows) = witness.split_at(arguments);
        let mut private: Vec<(String, Vec<u8>)> = vec![("the witness".into(), witness.clone())];
        if attest.window.is_none() {
            assert!(
                rows.is_empty(),
                "{statement}: a rootless witness past its arguments"
            );
        } else {
            let served = Served::decode_exact(rows)
                .unwrap_or_else(|| panic!("{statement}: no rows served after its arguments"));
            private.push(("the served rows".into(), rows.to_vec()));
            self.served(statement, &served, &mut private);
        }
        for (at, part) in unpublished(arguments, &attest.public_args).enumerate() {
            let name = format!("argument part {at}");
            self.push(Needle::bytes(
                Kind::ServedRow,
                format!("{statement}: {name}"),
                part,
            ));
            private.push((name, part.to_vec()));
        }
        self.hashes(statement, private);
    }

    /// The needles of the rows `served` for `statement`, each row's value
    /// pushed onto `private` to be hashed.
    fn served(&mut self, statement: &str, served: &Served, private: &mut Vec<(String, Vec<u8>)>) {
        let cut = [
            ("the agent's root at the cut", served.agent_root.to_vec()),
            ("the representative's root", served.rep_root.to_vec()),
            ("the representative's salt", served.rep_salt.to_vec()),
            ("the space path", served.space_path.clone()),
            ("the rows' proof", served.rows_proof.clone()),
        ];
        for (what, bytes) in cut {
            self.push(Needle::bytes(
                Kind::ServedRow,
                format!("{statement}: {what}"),
                &bytes,
            ));
        }
        for (row, (_, value)) in served.rows.iter().enumerate() {
            let Some((salt, value)) = value else {
                continue;
            };
            self.push(Needle::bytes(
                Kind::ServedRow,
                format!("{statement}: row {row}'s salt"),
                salt,
            ));
            let name = format!("{statement}: row {row}'s value");
            self.push(Needle::bytes(Kind::ServedRow, &name, value));
            if let Some(number) = u64::decode_exact(value).filter(|&number| number >= 1 << 24) {
                self.0.push(Needle::number(Kind::ServedRow, &name, number));
            }
            private.push((format!("row {row}'s value"), value.clone()));
        }
    }

    /// The plain and domain-prefixed hashes of each of `private`.
    fn hashes(&mut self, statement: &str, private: Vec<(String, Vec<u8>)>) {
        for (what, bytes) in private {
            let mut hashes = vec![
                (
                    "BLAKE2b-256".to_string(),
                    vos_wire::vos_anchor::blake2b_256(&[&bytes]),
                ),
                ("BLAKE3".to_string(), *blake3::hash(&bytes).as_bytes()),
            ];
            for domain in DOMAINS {
                let named = String::from_utf8_lossy(domain);
                hashes.push((
                    format!("BLAKE2b-256 under {named}"),
                    vos_wire::vos_anchor::blake2b_256(&[domain, &bytes]),
                ));
            }
            for (hash, digest) in hashes {
                self.push(Needle::bytes(
                    Kind::PrivateHash,
                    format!("{statement}: {hash} of {what}"),
                    &digest,
                ));
            }
        }
    }

    /// The debug outputs' markers ([`DEBUG_OUTPUTS`]).
    pub fn debug_outputs(&mut self) {
        for marker in DEBUG_OUTPUTS {
            self.0.push(Needle::text(
                Kind::DebugOutput,
                format!("the debug output {marker:?}"),
                marker,
            ));
        }
    }
}

/// The runs of `arguments` no stretch of `public`, the public arguments'
/// encodings, covers: `public` matched against the arguments in turn, the
/// longest stretch found first, at least [`SHORTEST`] bytes at a time (or
/// all that is left of it, when less).
fn unpublished<'a>(arguments: &'a [u8], public: &[u8]) -> impl Iterator<Item = &'a [u8]> {
    let mut covered = vec![false; arguments.len()];
    // Each suffix of the public bytes that is found in the arguments, the
    // longest first, marks what it covers.
    let mut from = 0;
    while from < public.len() {
        let rest = &public[from..];
        let found = (SHORTEST.min(rest.len())..=rest.len())
            .rev()
            .find_map(|len| {
                arguments
                    .windows(len)
                    .position(|window| window == &rest[..len])
                    .map(|at| (at, len))
            });
        match found {
            Some((at, len)) => {
                covered[at..at + len]
                    .iter_mut()
                    .for_each(|byte| *byte = true);
                from += len;
            }
            None => from += 1,
        }
    }
    let mut parts = Vec::new();
    let mut start = None;
    for (at, &is_covered) in covered.iter().chain([&true]).enumerate() {
        match (is_covered, start) {
            (false, None) => start = Some(at),
            (true, Some(begun)) => {
                parts.push(&arguments[begun..at]);
                start = None;
            }
            _ => {}
        }
    }
    parts.into_iter()
}
