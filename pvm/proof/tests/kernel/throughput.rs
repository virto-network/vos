//! The prover worker's throughput gate: at the default window length
//! (L = 10 min), one prover keeps up with three window statements a window
//! and the `balance` statements.
//!
//! Each statement is proved as the worker proves it: its kernel re-run on
//! its record's witness, its program recomputed from the kernel's blob,
//! the run proved to its final proof (`vos_pvm_recair::tree::prove_final`,
//! which the worker's masked prover calls), and the proof judged accepted
//! at the model venue holding the space's root anchored. Each statement's
//! whole proving time, and the process's peak resident memory, are
//! printed, and how many `balance` statements a window fits beside three
//! window statements.

use std::time::{Duration, Instant};

use vos_pvm_proof::format::SEGMENT;
use vos_statement::ProgramId;
use vos_wire::result::Attest;
use vos_wire::vos_anchor::{VenueId, WindowClock};

use crate::balance;
use crate::common;
use crate::cut::{self, Venue, genesis};
use crate::window_kernel;

/// The window statements a window brings.
const WINDOW_STATEMENTS: u32 = 3;

/// A prover's memory.
const PROVER_MIB: u64 = 16 << 10;

/// What one statement's proof took, by stage, its peak heap and the
/// process's peak resident memory.
struct Proved {
    rerun: Duration,
    program: Duration,
    stats: vos_pvm_recair::tree::Stats,
    whole: Duration,
    heap_mib: u64,
    resident_mib: u64,
}

impl Proved {
    /// A statement's time at the worker: its re-run and its proofs; its
    /// kernel's program is computed once a kernel.
    fn statement(&self) -> Duration {
        self.rerun + self.stats.took()
    }
}

/// `attest`, recorded by `actor`'s kernel, proved as the worker proves it
/// and accepted at a model venue holding `root` anchored in the space of
/// `genesis(1)`.
fn prove(name: &str, actor: &str, attest: &Attest) -> Proved {
    let (blob, record) = cut::kernel_of(actor, attest);
    common::resident_peak_mib(true);
    let started = Instant::now();
    let ((proof, rerun, program, stats, id), _, heap_mib) = common::measured(|| {
        let started = Instant::now();
        let trace = cut::traced(attest, &blob);
        let rerun = started.elapsed();
        let started = Instant::now();
        let (program, entry) = vos_pvm_recair::leaf::kernel_program(
            &blob,
            &record,
            vos_pvm_compiler::TRANSPILER_VERSION,
            &SEGMENT,
        )
        .expect("the kernel's program");
        let took = started.elapsed();
        let (proof, stats) = vos_pvm_recair::tree::prove_final(&program, &entry, &trace.side_note)
            .expect("the statement proves");
        let id = ProgramId(program.id().words());
        (proof, rerun, took, stats, id)
    });
    let whole = started.elapsed();
    let resident_mib = common::resident_peak_mib(false);

    let statement = cut::masked_statement(attest, id, attest.roots[0].space);
    let venue = Venue::pinned(VenueId([0x7e; 32]), &[genesis(1)], id);
    venue.anchor(&attest.roots[0]).expect("anchored");
    let verdict = vos_venue::VenueClient::submit(&venue.venue, &statement, &proof);
    assert_eq!(verdict.code(), 0, "{name}: accepted");

    let proved = Proved {
        rerun,
        program,
        stats,
        whole,
        heap_mib,
        resident_mib,
    };
    let stats = &proved.stats;
    eprintln!(
        "{name}: proved in {:.1}s, {:.1}s whole (re-run {:.2}s, program {:.2}s; {} segments {:.1}s, {} \
         leaves {:.1}s, {} folds {:.1}s, the masked wrap {:.1}s), {} bytes; peak heap {} MiB, \
         peak resident {} MiB; load {}",
        proved.statement().as_secs_f64(),
        proved.whole.as_secs_f64(),
        proved.rerun.as_secs_f64(),
        proved.program.as_secs_f64(),
        stats.segments,
        stats.segments_took.as_secs_f64(),
        stats.leaves,
        stats.leaves_took.as_secs_f64(),
        stats.folds,
        stats.folds_took.as_secs_f64(),
        stats.wrap_took.as_secs_f64(),
        proof.len(),
        proved.heap_mib,
        proved.resident_mib,
        common::load(),
    );
    proved
}

/// One prover keeps up at the default length: three window statements and
/// a `balance` statement prove within a window, within a prover's memory;
/// how many `balance` statements fit beside the three is printed.
#[test]
fn one_prover_keeps_up_at_the_default_window_length() {
    let length = Duration::from_millis(WindowClock::DEFAULT.length_ms);
    assert_eq!(length, Duration::from_secs(600));
    let window = {
        let cut = window_kernel::large();
        window_kernel::honest(&cut).attest().clone()
    };
    let window = prove("the window statement", "window", &window);
    let balance = {
        let cut = balance::balances();
        let c = balance::commitment(&balance::SALT, &balance::ACCOUNT);
        balance::at_least(&cut, c, 1_000, balance::SALT, balance::ACCOUNT)
            .attest()
            .clone()
    };
    let balance = prove("the balance statement", "balance", &balance);

    let windows = window.statement() * WINDOW_STATEMENTS;
    let left = length.saturating_sub(windows);
    let balances = left.as_secs_f64() / balance.statement().as_secs_f64();
    eprintln!(
        "a window of {}s: {WINDOW_STATEMENTS} window statements take {:.0}s, leaving {:.0}s: \
         {:.1} balance statements of {:.1}s each fit",
        length.as_secs(),
        windows.as_secs_f64(),
        left.as_secs_f64(),
        balances,
        balance.statement().as_secs_f64(),
    );
    // The window cut at the 32k class: a cut at a short class proves it in
    // 17 segments, over four times as long.
    assert!(
        window.stats.segments <= 4,
        "{} segments",
        window.stats.segments
    );
    for proved in [&window, &balance] {
        assert!(
            proved.resident_mib <= PROVER_MIB,
            "{} MiB",
            proved.resident_mib
        );
    }
    assert!(
        windows + balance.statement() <= length,
        "{WINDOW_STATEMENTS} window statements ({:.0}s) and one balance statement ({:.0}s) \
         pass a window",
        windows.as_secs_f64(),
        balance.statement().as_secs_f64()
    );
}
