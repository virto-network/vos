//! The carrier audit: the bytes of every carrier a run produced, searched
//! for what must never leave the prover role (`proving.md` A.5).
//!
//! A run knows what it must not show: the segment, leaf and fold proofs it
//! built, the rows it served, the plain hashes of its private arguments,
//! its step counts, its memory roots and its registers past the io-hash's
//! φ9..φ12. [`Needles`] holds them, from the prover's [`Internals`] and
//! each statement's [`Attest`]; [`Audit`] holds the carriers, each as it
//! [`Reach`]es: out of the role (a venue's call, a log line, a client's
//! answer) or within the agent's replicas (its log, its blobs, its peers'
//! frames). Every needle is searched in every carrier that leaves; the
//! proofs, memory roots and register files, which no carrier may hold, in
//! those that stay too.
//!
//! Each needle is searched in the forms a carrier would hold it in: its
//! bytes, their hex, their `Debug` list; a number's little-endian bytes and
//! its decimal digits.
//!
//! [`Logs`] captures every tracing event of the process as text, at every
//! level: install it before the run, alone in its process.

use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

use vos_node_prover::Internals;
use vos_statement_service::item::Item;
use vos_venue::kreivo;
use vos_venue::vos_statement::{Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, NotAccepted, Status, VenueClient};
use vos_wire::Decode;
use vos_wire::result::Attest;
use vos_wire::served::Served;
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};

/// What a needle is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A segment, leaf or fold proof: its trees' roots, its encoding, the
    /// digests its output states.
    NodeProof,
    /// A served row: its value, its salt, the cut's roots and paths.
    ServedRow,
    /// A plain hash of the private arguments or of the served rows.
    PrivateHash,
    /// A step count: a segment's, a boundary's index, the run's.
    StepCount,
    /// A memory root, or the commitment of an image.
    MemoryRoot,
    /// A register past φ9..φ12, or the file φ0..φ8.
    Register,
    /// A debug output's own text, which only `debug-internals` builds
    /// print: each instruction a run steps through, the recompiler's
    /// registers, a trace's rows.
    DebugOutput,
}

impl Kind {
    /// Whether no carrier at all may hold it, the role's own included.
    fn nowhere(self) -> bool {
        matches!(self, Self::NodeProof | Self::MemoryRoot)
    }
}

/// How far a carrier reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    /// Out of the prover role: a venue, a log, a client.
    Leaves,
    /// Within the agent's replicas, which hold its rows and run its
    /// kernels.
    Role,
}

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
}

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

fn hex(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| format!("{byte:02x}").into_bytes())
        .collect()
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

impl Needle {
    /// `bytes`, as they are, in hex, and as a `Debug` list.
    pub fn bytes(kind: Kind, name: impl Into<String>, bytes: &[u8]) -> Option<Self> {
        let distinct = bytes
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len();
        (bytes.len() >= SHORTEST && distinct >= DISTINCT).then(|| Self {
            kind,
            name: name.into(),
            forms: vec![bytes.to_vec(), hex(bytes), listed(bytes)],
            leaving: Vec::new(),
        })
    }

    /// `value`'s little-endian bytes, and its decimal digits in the
    /// carriers that leave.
    pub fn number(kind: Kind, name: impl Into<String>, value: u64) -> Self {
        let mut leaving = vec![value.to_string().into_bytes(), value.to_le_bytes().to_vec()];
        if let Ok(value) = u32::try_from(value) {
            leaving.push(value.to_le_bytes().to_vec());
        }
        Self {
            kind,
            name: name.into(),
            forms: Vec::new(),
            leaving,
        }
    }

    /// A register file's values, in order: their little-endian bytes and
    /// their `Debug` list.
    pub fn registers(name: impl Into<String>, values: &[u64]) -> Self {
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect();
        Self {
            kind: Kind::Register,
            name: name.into(),
            forms: vec![bytes.clone(), listed(values)],
            leaving: vec![hex(&bytes)],
        }
    }

    /// Whether its kind is searched in a carrier of `reach`.
    fn reaches(&self, reach: Reach) -> bool {
        reach == Reach::Leaves || self.kind.nowhere() || self.kind == Kind::Register
    }

    /// Its forms searched in a carrier of `reach`.
    fn forms(&self, reach: Reach) -> impl Iterator<Item = &Vec<u8>> {
        let leaves = reach == Reach::Leaves;
        self.forms
            .iter()
            .chain(self.leaving.iter().filter(move |_| leaves))
    }
}

/// Whether the match of `len` bytes at `at` is a whole run of digits in
/// `haystack`, or no run of digits at all.
fn whole(haystack: &[u8], at: usize, len: usize) -> bool {
    let digits = haystack[at..at + len].iter().all(u8::is_ascii_digit);
    !digits
        || (haystack
            .get(at.wrapping_sub(1))
            .is_none_or(|b| !b.is_ascii_digit())
            && haystack.get(at + len).is_none_or(|b| !b.is_ascii_digit()))
}

/// The needles of a run.
#[derive(Clone, Debug, Default)]
pub struct Needles(pub Vec<Needle>);

impl Needles {
    pub fn push(&mut self, needle: Option<Needle>) {
        self.0.extend(needle);
    }

    /// What a statement's proof was built from ([`Internals`]): its node
    /// proofs, step counts, memory roots and registers. A step count of a
    /// power of two is a class's budget, the kernel's public shape, and is
    /// not searched; nor a register below 2^24, whose digits a log line holds
    /// by chance.
    pub fn internals(&mut self, statement: &str, internals: &Internals) {
        for proof in &internals.proofs {
            let name = |what: &str| format!("{statement}: {}'s {what}", proof.name);
            for (tree, root) in proof.roots.iter().enumerate() {
                self.push(Needle::bytes(
                    Kind::NodeProof,
                    name(&format!("tree {tree}")),
                    root,
                ));
            }
            for (at, digest) in proof.digests.iter().enumerate() {
                self.push(Needle::bytes(
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
        for &steps in &internals.steps {
            if !steps.is_power_of_two() && steps > 0xff {
                self.0.push(Needle::number(
                    Kind::StepCount,
                    format!("{statement}: {steps} steps"),
                    steps,
                ));
            }
        }
        for root in &internals.memory_roots {
            self.push(Needle::bytes(
                Kind::MemoryRoot,
                format!("{statement}: a memory root"),
                root,
            ));
        }
        let private = Internals::PRIVATE_REGISTERS;
        for (boundary, registers) in internals.registers.iter().enumerate() {
            let file = &registers[private.clone()];
            self.0.push(Needle::registers(
                format!("{statement}: boundary {boundary}'s φ0..φ8"),
                file,
            ));
            for (index, &value) in file.iter().enumerate() {
                if value >= 1 << 24 {
                    self.0.push(Needle::number(
                        Kind::Register,
                        format!("{statement}: boundary {boundary}'s φ{index}"),
                        value,
                    ));
                }
            }
        }
    }

    /// The debug outputs' markers ([`DEBUG_OUTPUTS`]).
    pub fn debug_outputs(&mut self) {
        for marker in DEBUG_OUTPUTS {
            self.0.push(Needle {
                kind: Kind::DebugOutput,
                name: format!("the debug output {marker:?}"),
                forms: Vec::new(),
                leaving: vec![marker.as_bytes().to_vec()],
            });
        }
    }

    /// What `attest`'s record holds privately: the rows it served, their
    /// salts and the cut's roots and paths, its arguments not among its
    /// public ones, and the plain hashes of each.
    pub fn attest(&mut self, statement: &str, attest: &Attest) {
        let witness = &attest.witness_input;
        let (arguments, served) = split(witness);
        let mut private: Vec<(String, Vec<u8>)> = vec![("the witness".into(), witness.clone())];
        if !contains(&attest.public_args, arguments) {
            self.push(Needle::bytes(
                Kind::ServedRow,
                format!("{statement}: the arguments"),
                arguments,
            ));
            private.push(("the arguments".into(), arguments.to_vec()));
        }
        if let Some((bytes, served)) = served {
            private.push(("the served rows".into(), bytes.to_vec()));
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
                self.push(Needle::bytes(
                    Kind::ServedRow,
                    format!("{statement}: row {row}'s value"),
                    value,
                ));
                private.push((format!("row {row}'s value"), value.clone()));
            }
        }
        for (what, bytes) in private {
            let hashes: [(&str, [u8; 32]); 2] = [
                ("BLAKE2b-256", vos_wire::vos_anchor::blake2b_256(&[&bytes])),
                ("BLAKE3", *blake3::hash(&bytes).as_bytes()),
            ];
            for (hash, digest) in hashes {
                self.push(Needle::bytes(
                    Kind::PrivateHash,
                    format!("{statement}: {hash} of {what}"),
                    &digest,
                ));
            }
        }
    }
}

/// `witness` split at its served rows: the call's arguments, and the rows'
/// encoding with the rows, if the witness ends in some.
fn split(witness: &[u8]) -> (&[u8], Option<(&[u8], Served)>) {
    (0..witness.len())
        .find_map(|at| {
            let served = Served::decode_exact(&witness[at..])?;
            Some((&witness[..at], Some((&witness[at..], served))))
        })
        .unwrap_or((witness, None))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// A carrier's bytes.
#[derive(Clone, Debug)]
pub struct Carrier {
    pub name: String,
    pub reach: Reach,
    pub bytes: Vec<u8>,
}

/// A needle found in a carrier.
#[derive(Clone, Debug)]
pub struct Finding {
    pub kind: Kind,
    pub needle: String,
    pub carrier: String,
    pub at: usize,
    /// The form found: 0 its bytes, then hex, `Debug`, or a number's forms.
    pub form: usize,
    /// The carrier's bytes around it, as text.
    pub context: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {} in {} at byte {} (form {}): {:?}",
            self.kind, self.needle, self.carrier, self.at, self.form, self.context
        )
    }
}

/// The carriers of a run, searched for its needles.
#[derive(Default)]
pub struct Audit {
    pub carriers: Vec<Carrier>,
    pub needles: Needles,
}

impl Audit {
    /// Add a carrier's bytes; an empty one is kept, so the report counts
    /// it.
    pub fn carrier(&mut self, name: impl Into<String>, reach: Reach, bytes: Vec<u8>) {
        self.carriers.push(Carrier {
            name: name.into(),
            reach,
            bytes,
        });
    }

    /// Every needle found in a carrier its kind reaches: the first place
    /// of each, in one pass over each carrier.
    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        for reach in [Reach::Leaves, Reach::Role] {
            let mut patterns: Vec<&[u8]> = Vec::new();
            let mut of: Vec<(usize, usize)> = Vec::new();
            for (index, needle) in self.needles.0.iter().enumerate() {
                if !needle.reaches(reach) {
                    continue;
                }
                for (form, bytes) in needle.forms(reach).enumerate() {
                    patterns.push(bytes);
                    of.push((index, form));
                }
            }
            if patterns.is_empty() {
                continue;
            }
            let automaton = aho_corasick::AhoCorasick::new(&patterns).expect("the needles");
            for carrier in self
                .carriers
                .iter()
                .filter(|carrier| carrier.reach == reach)
            {
                let mut found = vec![false; self.needles.0.len()];
                for hit in automaton.find_overlapping_iter(&carrier.bytes) {
                    let (index, form) = of[hit.pattern().as_usize()];
                    if found[index] || !whole(&carrier.bytes, hit.start(), hit.len()) {
                        continue;
                    }
                    found[index] = true;
                    let needle = &self.needles.0[index];
                    findings.push(Finding {
                        kind: needle.kind,
                        needle: needle.name.clone(),
                        carrier: carrier.name.clone(),
                        at: hit.start(),
                        form,
                        context: context(&carrier.bytes, hit.start(), hit.end()),
                    });
                }
            }
        }
        findings
    }

    /// What was searched: each carrier's reach and size, and the needles
    /// by kind.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for carrier in &self.carriers {
            out += &format!(
                "{:?} {}: {} bytes\n",
                carrier.reach,
                carrier.name,
                carrier.bytes.len()
            );
        }
        let mut kinds: Vec<Kind> = self.needles.0.iter().map(|needle| needle.kind).collect();
        kinds.sort();
        kinds.dedup();
        for kind in kinds {
            let count = self
                .needles
                .0
                .iter()
                .filter(|needle| needle.kind == kind)
                .count();
            out += &format!("{kind:?}: {count} needles\n");
        }
        out
    }

    /// Fails unless the run made needles of each of `kinds`, and each
    /// needle, put in a carrier that leaves, is found there: a run whose
    /// needles could not be found would pass the audit for nothing.
    pub fn assert_searchable(&self, kinds: &[Kind]) {
        for kind in kinds {
            assert!(
                self.needles.0.iter().any(|needle| needle.kind == *kind),
                "no {kind:?} needle"
            );
        }
        for needle in &self.needles.0 {
            let form = needle.forms(Reach::Leaves).next().expect("a form");
            let mut planted = Audit::default();
            planted.carrier("planted", Reach::Leaves, [b" ", &form[..], b" "].concat());
            planted.needles.0.push(needle.clone());
            assert_eq!(planted.findings().len(), 1, "{} is not found", needle.name);
        }
    }

    /// Fails, naming each finding, unless no carrier holds a needle.
    pub fn assert_clean(&self) {
        let findings = self.findings();
        assert!(
            findings.is_empty(),
            "{} needles found:\n{}",
            findings.len(),
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

/// The bytes of a line's length around `start..end`, as text.
fn context(bytes: &[u8], start: usize, end: usize) -> String {
    let from = start.saturating_sub(160);
    let to = (end + 160).min(bytes.len());
    String::from_utf8_lossy(&bytes[from..to]).into_owned()
}

/// A venue's client, every anchor and submission it is sent kept: the
/// carriers a node sends its venue.
pub struct Tapped {
    inner: Arc<dyn VenueClient>,
    anchors: Mutex<Vec<Anchor>>,
    submitted: Mutex<Vec<(Statement, Vec<u8>)>>,
}

impl Tapped {
    pub fn new(inner: Arc<dyn VenueClient>) -> Self {
        Self {
            inner,
            anchors: Mutex::default(),
            submitted: Mutex::default(),
        }
    }

    /// The anchors sent so far.
    pub fn anchors(&self) -> Vec<Anchor> {
        lock(&self.anchors).clone()
    }

    /// The statements submitted so far, each with its final proof.
    pub fn submitted(&self) -> Vec<(Statement, Vec<u8>)> {
        lock(&self.submitted).clone()
    }

    /// Every carrier the venue was sent, in each venue's layout
    /// ([`anchor_carriers`], [`submission_carriers`]), into `audit`.
    pub fn carriers(&self, audit: &mut Audit) {
        for anchor in self.anchors() {
            for (name, bytes) in anchor_carriers(&anchor) {
                audit.carrier(
                    format!("window {}: {name}", anchor.window),
                    Reach::Leaves,
                    bytes,
                );
            }
        }
        for (statement, proof) in self.submitted() {
            for (name, bytes) in submission_carriers(&statement, &proof) {
                audit.carrier(name, Reach::Leaves, bytes);
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl VenueClient for Tapped {
    fn id(&self) -> VenueId {
        self.inner.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        lock(&self.anchors).push(*anchor);
        self.inner.anchor(anchor)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        lock(&self.submitted).push((statement.clone(), proof.to_vec()));
        self.inner.submit(statement, proof)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.inner.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.inner.anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.inner.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.inner.time()
    }
}

/// What a venue is sent for `anchor`, as each venue's client lays it out:
/// Kreivo's call and the JAM statements service's work item.
pub fn anchor_carriers(anchor: &Anchor) -> Vec<(String, Vec<u8>)> {
    vec![
        ("the anchor".into(), anchor.encode()),
        (
            "Kreivo's anchor call".into(),
            kreivo::calls::Call::anchor(anchor).bytes(),
        ),
        ("JAM's anchor item".into(), Item::Anchor(*anchor).encode()),
    ]
}

/// What a venue is sent for `statement` and its final `proof`: the
/// statement, the proof, Kreivo's call and JAM's work item and extrinsic.
pub fn submission_carriers(statement: &Statement, proof: &[u8]) -> Vec<(String, Vec<u8>)> {
    let encoded = statement.encode();
    vec![
        ("the statement".into(), encoded.clone()),
        ("the final proof".into(), proof.to_vec()),
        (
            "Kreivo's submit call".into(),
            kreivo::calls::Call::Submit {
                payer: [0; 32],
                statement: encoded.clone(),
                proof: proof.to_vec(),
            }
            .bytes(),
        ),
        ("JAM's submit item".into(), Item::Submit(encoded).encode()),
        ("JAM's submit extrinsic".into(), proof.to_vec()),
    ]
}

/// Every file under `dir`, read whole, in path order: what a node wrote
/// to its disk.
pub fn directory(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                files.push((path.display().to_string(), bytes));
            }
        }
    }
    files.sort();
    files
}

/// The environment that turns every debug output on, in a build that has
/// them: a run under it shows the outputs [`DEBUG_OUTPUTS`] names unless
/// they are compiled out.
pub const DEBUG_ENVIRONMENT: [&str; 4] = [
    "GREY_PVM_DEBUG",
    "CPU_DUMP",
    "CPU_EXPR_DUMP",
    "ZKPVM_PROFILE",
];

/// The process's standard error, written to a file from [`Stderr::capture`]
/// until [`Stderr::finish`]: what a debug output prints there. The test
/// harness keeps its own capture of a test's prints unless run with
/// `--nocapture`.
pub struct Stderr {
    saved: i32,
    path: std::path::PathBuf,
}

impl Stderr {
    /// The process's standard error, from now on, into a new file in `dir`.
    pub fn capture(dir: &std::path::Path) -> Self {
        use std::os::fd::AsRawFd;
        let path = dir.join("stderr");
        let file = std::fs::File::create(&path).expect("the capture's file");
        // SAFETY: `dup` and `dup2` on the process's standard error and an
        // open file; the saved descriptor is restored by `finish`.
        let saved = unsafe { libc::dup(2) };
        assert!(saved >= 0, "standard error duplicated");
        assert!(
            unsafe { libc::dup2(file.as_raw_fd(), 2) } >= 0,
            "standard error redirected"
        );
        Self { saved, path }
    }

    /// Standard error restored: what was written to it meanwhile.
    pub fn finish(self) -> Vec<u8> {
        // SAFETY: the descriptor `capture` saved, put back.
        unsafe {
            libc::dup2(self.saved, 2);
            libc::close(self.saved);
        }
        std::fs::read(&self.path).unwrap_or_default()
    }
}

/// Every tracing event of the process, formatted, at every level.
#[derive(Clone, Default)]
pub struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    /// The process's capture, installed as its global subscriber on the
    /// first call. Fails if another subscriber is installed already.
    pub fn install() -> Self {
        static LOGS: OnceLock<Logs> = OnceLock::new();
        LOGS.get_or_init(|| {
            let logs = Logs::default();
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .without_time()
                .with_writer(logs.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("the process's only subscriber");
            logs
        })
        .clone()
    }

    /// What was captured so far.
    pub fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Logs;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn audit(reach: Reach, bytes: &[u8], needle: Needle) -> Vec<Finding> {
        let mut audit = Audit::default();
        audit.carrier("carrier", reach, bytes.to_vec());
        audit.needles.0.push(needle);
        audit.findings()
    }

    #[test]
    fn a_needle_is_found_in_each_of_its_forms() {
        let secret: Vec<u8> = (1..=16).collect();
        let needle = || Needle::bytes(Kind::ServedRow, "secret", &secret).unwrap();
        for carrier in [
            [b"x".as_slice(), &secret, b"y"].concat(),
            format!("value={}", String::from_utf8(hex(&secret)).unwrap()).into_bytes(),
            format!("value={secret:?}").into_bytes(),
        ] {
            assert_eq!(audit(Reach::Leaves, &carrier, needle()).len(), 1);
        }
        assert!(audit(Reach::Leaves, &secret[1..], needle()).is_empty());
    }

    #[test]
    fn a_number_is_found_whole_in_the_carriers_that_leave() {
        let steps = || Needle::number(Kind::StepCount, "steps", 123_457);
        assert_eq!(audit(Reach::Leaves, b"took 123457 steps", steps()).len(), 1);
        assert!(audit(Reach::Leaves, b"took 1234570 steps", steps()).is_empty());
        assert_eq!(
            audit(Reach::Leaves, &123_457u32.to_le_bytes(), steps()).len(),
            1
        );
        assert!(audit(Reach::Role, b"took 123457 steps", steps()).is_empty());
    }

    #[test]
    fn proofs_and_registers_are_searched_within_the_role_too() {
        let root: Vec<u8> = (100..132).collect();
        let proof = Needle::bytes(Kind::NodeProof, "root", &root).unwrap();
        assert_eq!(audit(Reach::Role, &root, proof).len(), 1);
        let row = Needle::bytes(Kind::ServedRow, "row", &root).unwrap();
        assert!(audit(Reach::Role, &root, row).is_empty());
        let file = [1u64 << 40, 7, 9];
        let bytes: Vec<u8> = file.iter().flat_map(|value| value.to_le_bytes()).collect();
        assert_eq!(
            audit(Reach::Role, &bytes, Needle::registers("file", &file)).len(),
            1
        );
        let debug = format!("{:?}", [1u64 << 40, 7, 9, 3]).into_bytes();
        assert_eq!(
            audit(Reach::Leaves, &debug, Needle::registers("file", &file)).len(),
            1
        );
    }

    #[test]
    fn a_short_or_constant_value_is_no_needle() {
        assert!(Needle::bytes(Kind::ServedRow, "short", &[1, 2, 3]).is_none());
        assert!(Needle::bytes(Kind::ServedRow, "zeros", &[0; 32]).is_none());
        assert!(Needle::bytes(Kind::ServedRow, "a small integer", &21u64.to_le_bytes()).is_none());
    }

    #[test]
    fn served_rows_are_split_off_their_witness() {
        let served = Served {
            space: vos_wire::SpaceId([3; 32]),
            window: 4,
            agent: vos_wire::ids::AgentId(5),
            instance: vos_wire::ids::InstanceId(6),
            agent_root: [7; 32],
            rep_root: [8; 32],
            rep_salt: [9; 16],
            space_path: vec![1, 2, 3],
            rows: vec![(vec![1], Some(([4; 16], vec![5; 20])))],
            rows_proof: vec![6; 40],
        };
        let arguments = vec![42u8; 12];
        let witness = [arguments.clone(), vos_wire::Encode::encode(&served)].concat();
        let (split_arguments, rows) = split(&witness);
        assert_eq!(split_arguments, &arguments[..]);
        assert_eq!(rows.unwrap().1, served);
    }
}
