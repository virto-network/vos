//! The node side's helpers: the run's tallies by kind of proof, the
//! machine's load and resident peak, and a root's masked wrap verified
//! natively and on the JAM-only host, over the prover's own test helpers
//! (`pvm/proof/tests/common`), which this module re-exports.

#[path = "../../../../../pvm/proof/tests/common/mod.rs"]
mod pvm;
pub use pvm::*;

/// The wraps' files, read by `vos-pvm-recair`'s `wrap_files` check.
#[path = "../../../../../pvm/proof/recair/tests/common/wrap_files.rs"]
mod wrap_files;

/// Proofs of one kind in a run: how many, their proving time summed and
/// the largest peak heap among them (MiB).
#[derive(Default)]
pub struct Tally {
    pub count: usize,
    pub proving: std::time::Duration,
    pub peak_mib: u64,
}

impl Tally {
    pub fn add(&mut self, proving: std::time::Duration, peak_mib: u64) {
        self.count += 1;
        self.proving += proving;
        self.peak_mib = self.peak_mib.max(peak_mib);
    }
}

/// A run's proofs end to end, by kind: its segments, leaves, folds and wrap.
#[derive(Default)]
pub struct Totals {
    pub segments: Tally,
    pub leaves: Tally,
    pub folds: Tally,
    pub wrap: Tally,
}

impl Totals {
    /// Prints each kind's tally, and the recursion (the leaves, folds and
    /// wrap) as a share of the segments' proving.
    pub fn report(&self, name: &str) {
        let recursion = self.leaves.proving + self.folds.proving + self.wrap.proving;
        for (kind, tally) in [
            ("segments", &self.segments),
            ("leaves", &self.leaves),
            ("folds", &self.folds),
            ("wrap", &self.wrap),
        ] {
            eprintln!(
                "{name}: {} {kind} proved in {:.2}s, the largest peak heap {} MiB",
                tally.count,
                tally.proving.as_secs_f64(),
                tally.peak_mib
            );
        }
        eprintln!(
            "{name}: the recursion proved in {:.2}s, {:.1}% of the segments' {:.2}s",
            recursion.as_secs_f64(),
            100.0 * recursion.as_secs_f64() / self.segments.proving.as_secs_f64(),
            self.segments.proving.as_secs_f64()
        );
    }
}

/// `root`, the root of a whole run of `program`, wrapped within 2^17 rows,
/// proved masked under `format::MASKED_WRAP` ([`masked_wrap`]) and verified
/// by `vos-pvm-final-verifier`, its statement the program's id and the
/// root's io-hash: its public words and the proof's bytes, the fixed
/// layout; its proving time and peak heap added to `wrap`.
pub fn wrap_root(
    name: &str,
    program: &vos_pvm_proof::program_id::KernelProgram,
    root: &NodeRun,
    wrap: &mut Tally,
) -> ([u32; vos_pvm_final_verifier::PUBLIC_WORDS], Vec<u8>) {
    use vos_pvm_recair::wrap::{self, WrapCircuit};

    let circuit = WrapCircuit::get();
    let (values, statement) = circuit
        .values(root.node.proved(), &program.id_preimage())
        .expect("the root's values");
    let finalized = circuit
        .build(&values)
        .finalize()
        .expect("the wrap's wiring checks");
    let log_sizes = finalized.circuit.log_sizes();
    assert_eq!(log_sizes, vos_pvm_final_verifier::LOG_SIZES);
    assert!(log_sizes.iter().all(|&log| log <= 17));
    let words = wrap::public_words(&finalized);
    assert_eq!(words, statement.words());
    assert_eq!(statement.program, program.id());
    assert_eq!(statement.io_hash, root.node.output.io_hash);
    let (bytes, proving, peak_mib) = masked_wrap(name, &finalized, &words);
    wrap.add(proving, peak_mib);
    (words, bytes)
}

/// The machine's load averages, as `/proc/loadavg` gives them: empty
/// where it gives none.
pub fn load() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// The process's peak resident set (`VmHWM`) in MiB, reset to the present
/// one first when `reset`.
pub fn resident_peak_mib(reset: bool) -> u64 {
    if reset {
        // Writing 5 resets this process's peak resident set.
        std::fs::write("/proc/self/clear_refs", "5").expect("the peak resets");
    }
    let status = std::fs::read_to_string("/proc/self/status").expect("the process's status");
    let kib: u64 = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|rest| rest.trim().trim_end_matches("kB").trim().parse().ok())
        .expect("VmHWM");
    kib >> 10
}

/// A finalized wrap circuit's witness proved masked under
/// `format::MASKED_WRAP` (`vos_pvm_recair::wrap::prove`), within 4.5 GiB of
/// heap and 8 GiB of resident memory, its revealed functionals within the
/// format's count, its bytes the fixed layout, and verified by the final
/// verifier's masked verifier at the preprocessed root the format pins: its
/// proving time and R1's printed with the load average, and its bytes
/// written for the Wasm harness as `wrap/<name>-39.{proof,format,words}`:
/// the bytes, the proving time and the peak heap.
fn masked_wrap(
    name: &str,
    finalized: &vos_pvm_recair::Finalized<stwo::core::fields::qm31::SecureField>,
    words: &[u32; vos_pvm_final_verifier::PUBLIC_WORDS],
) -> (Vec<u8>, std::time::Duration, u64) {
    use stwo::core::vcs::blake2b_hash::Blake2bHash;
    use vos_pvm_final_verifier::masked;
    use vos_pvm_recair::masked::MaskRng;

    let load = load();
    resident_peak_mib(true);
    let ((proof, stats), proving, peak_mib) = measured(|| {
        vos_pvm_recair::wrap::prove_masked(finalized, MaskRng::default())
            .expect("the masked wrap proves")
    });
    let resident_mib = resident_peak_mib(false);
    let bytes = vos_pvm_recair::wrap::proof_bytes(&proof).expect("format 39's bytes");
    eprintln!(
        "{name}'s masked wrap (format 39): proved in {:.2}s, its peak heap {peak_mib} MiB, the \
         process's peak resident {resident_mib} MiB, {} bytes (fixed layout); R1 {:.1} ms, {} \
         rows revealed of h = 256, {} attempt(s); load {}",
        proving.as_secs_f64(),
        bytes.len(),
        stats.rank_check.as_secs_f64() * 1e3,
        stats.revealed_rows,
        stats.attempts,
        load,
    );
    assert!(peak_mib <= 4608, "{peak_mib} MiB of heap");
    assert!(resident_mib <= 8 << 10, "{resident_mib} MiB resident");
    // Pin A's count of the revealed functionals: `2(4|O| + q(|O| + 1))`
    // at `q = 24` and `|O| = 2`, the budget `h = 256` covers twice.
    assert!(stats.revealed_rows <= 160, "{stats:?}");
    assert_eq!(proof.format_version, masked::FORMAT);
    assert_eq!(
        proof.stark_proof.commitments[0],
        Blake2bHash(vos_pvm_final_verifier::PREPROCESSED_ROOT_39)
    );
    let verified = masked::verify_bytes(&bytes, words).expect("the masked wrap verifies");
    assert_eq!(verified.words(), *words);
    wrap_files::write(&format!("{name}-39"), masked::FORMAT, &bytes, words);
    (bytes, proving, peak_mib)
}

/// A `format::MASKED_WRAP` wrap's `proof`, verified against its public
/// `words` natively and on the JAM-only host by the venue's refine program
/// (`final-verify.elf`), and written under the target's tmp directory as
/// `wrap/<name>.{proof,format,words}` for the Wasm harness.
pub fn verified_wrap(
    name: &str,
    proof: &[u8],
    words: &[u32; vos_pvm_final_verifier::PUBLIC_WORDS],
) {
    let format = vos_pvm_final_verifier::masked::FORMAT;
    vos_pvm_final_verifier::verify(format, &[format], proof, words)
        .expect("the wrap verifies natively");
    let (program, _) = jam::program();
    let (gas, report) = jam::run(&program, &jam::words_request(format, words), proof);
    eprintln!(
        "verified on the JAM-only host: {gas} gas ({:.1}M); heap peak {} KiB",
        gas as f64 / 1e6,
        report.peak_live >> 10,
    );
    assert_eq!(report.verdict, jam::ACCEPT, "{}", report.error);
    jam::pinned(
        &jam::root().join("node/kernel-tests/tests/counts.txt"),
        "predicate-wrap-verify-gas",
        gas,
        2,
    );
    wrap_files::write(name, format, proof, words);
}
