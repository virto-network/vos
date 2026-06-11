//! End-to-end harness for the conservation-of-value transition guest.
//!
//! Builds an honest transition (2 accounts, 1 settled debit) host-side,
//! packages it as the `(voucher::Public, SuccinctTransitionWitness)` pair
//! the voucher-check guest decodes from `__VOS_WITNESS`, and exercises it
//! through the general prover path. The transition trace is millions of
//! steps (crypto + Merkle-path re-execution), so the load-bearing prove is
//! the bounded-memory SEGMENT CHAIN (`prove_transition_segmented_chain`);
//! the always-on regressions are trace-level (io-binding, witness size,
//! ledger-size independence). The `debug-constraints`-gated tests are the
//! constraint/logup pinpointing toolkit for when a prove regresses.
//!
//! Skips (does not fail) when the voucher-check ELF isn't built — build it
//! with `just build-voucher-check`.

use std::path::PathBuf;

use cipher_clerk::crypto::{Amount, Blinding};
use cipher_clerk::prelude::*;
use cipher_clerk::snapshot::{OpeningsOracle, VecLedger};
use cipher_clerk::state::Opening;
use cipher_clerk::succinct::SuccinctTransitionWitness;
use cipher_clerk::voucher::proof::{Public as VoucherPublic, public_bytes};
use prover_extension::{prove_with_details, trace_program, verify_proof_bytes};
use vos::Encode;

const PROGRAM: &[u8] = b"voucher-check";
const BATCH_TS: u64 = 600_000;

fn voucher_check_elf_path() -> PathBuf {
    if let Ok(p) = std::env::var("VOUCHER_CHECK_ELF") {
        return PathBuf::from(p);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("actors")
        .join("voucher-check")
        .join("target")
        .join("riscv64em-javm")
        .join("release")
        .join("voucher-check.elf")
}

/// Length-prefixed `[u32 public_len][public][u32 secret_len][secret]` —
/// the `__VOS_WITNESS` payload convention the guest reads.
fn encode_witness(public_bytes: &[u8], secret_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + public_bytes.len() + secret_bytes.len());
    v.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(public_bytes);
    v.extend_from_slice(&(secret_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(secret_bytes);
    v
}

/// Build an honest 2-account, 1-settled-debit transition and return the
/// voucher `Public` (with the real before/after roots) + the
/// `SuccinctTransitionWitness` the guest re-executes (touched leaves +
/// Merkle paths against `root_before`, not the full ledger).
fn build_transition() -> (VoucherPublic, SuccinctTransitionWitness) {
    let registrar = Keypair::generate();
    let journal = Journal::new(JournalId::random(), registrar.public, 1);
    let jid = journal.id;
    let mut ledger = VecLedger::new();
    ledger.set_journal(journal);

    // The debit amount + its opening (so the kernel range-check can reveal it).
    let value: u64 = 100;
    let blinding = Blinding::from_bytes([3u8; 32]).expect("canonical scalar");
    let amount_commit = Amount::commit(value, &blinding);
    let mut oracle = OpeningsOracle::new(vec![Opening {
        amount: amount_commit,
        value,
        blinding,
    }]);

    let alice_kp = Keypair::generate();
    let bob_kp = Keypair::generate();
    let alice = Account::open(
        AccountKind::Asset,
        jid,
        alice_kp.public,
        Iso4217::USD,
        BankCode::Vault,
    );
    let bob = Account::open(
        AccountKind::Liability,
        jid,
        bob_kp.public,
        Iso4217::USD,
        BankCode::Checking,
    );
    let creates = cipher_clerk::apply_account_creations(
        &mut ledger,
        &[
            CreateAccount::signed(alice.clone(), &registrar.secret),
            CreateAccount::signed(bob.clone(), &registrar.secret),
        ],
        &mut oracle,
        500_000,
    );
    for r in &creates {
        assert_eq!(r.status, EventStatus::Created);
    }

    let t = Transfer::builder(jid)
        .debit(&alice, Layer::Settled, amount_commit)
        .credit(&bob, Layer::Settled, amount_commit)
        .signed_with(&[(&alice, &alice_kp.secret)]);

    // Roots before/after applying the batch — what the voucher commits to.
    let root_before = ledger.root();
    let events = vec![t];
    let mut probe = ledger.clone();
    let mut probe_oracle = oracle.clone();
    let _ = cipher_clerk::apply_batch(&mut probe, &events, &mut probe_oracle, BATCH_TS);
    let root_after = probe.root();

    let public = VoucherPublic {
        issuer: registrar.public,
        amount_commit,
        state_root_before: root_before,
        state_root_after: root_after,
    };
    // Build the succinct witness from the snapshot at `root_before`: only
    // the touched leaves + their Merkle paths, discovered by replaying the
    // batch. Size and re-execution cost scale with the batch, not `ledger`.
    let witness = SuccinctTransitionWitness::from_full(&ledger, &events, &oracle, BATCH_TS);
    (public, witness)
}

/// Length-prefixed witness buffer for the transition, CACHED to disk so the
/// trace is reproducible across runs. `build_transition` uses `OsRng`
/// (`Keypair::generate`, `JournalId::random`, `AccountId::random`, signing
/// nonces), so each call traces a DIFFERENT witness — segment boundaries land
/// on different ops, and a boundary-sensitive bug lands in a different
/// segment. Freezing one witness makes "which segment is unbalanced" and any
/// subsequent bisection stable. Override the path with VOS_WITNESS_CACHE;
/// delete the file to re-roll.
#[allow(dead_code)]
fn cached_witness_buf() -> Vec<u8> {
    let path = std::env::var("VOS_WITNESS_CACHE")
        .unwrap_or_else(|_| "/tmp/transition_witness.bin".to_string());
    if let Ok(bytes) = std::fs::read(&path) {
        eprintln!("loaded cached witness ({} B) from {path}", bytes.len());
        return bytes;
    }
    let (public, witness) = build_transition();
    let buf = encode_witness(&public.encode(), &witness.encode());
    if std::fs::write(&path, &buf).is_ok() {
        eprintln!("built + cached witness ({} B) to {path}", buf.len());
    }
    buf
}

/// Diagnostic (no prove): size the kernel-transition trace and break it
/// down by op so we know what drives the prove's cost — software curve
/// math, blake2b/SMT, or raw step count — i.e. what to precompile /
/// segment next. On-demand: traces the full multi-million-step program.
#[test]
#[ignore]
fn measure_transition_trace() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }
    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());

    let Some(sn) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed (grey link / symbol / trace error)");
        return;
    };

    // Opcode histogram — the top families tell us where the steps go.
    use std::collections::BTreeMap;
    let mut hist: BTreeMap<String, u64> = BTreeMap::new();
    for s in &sn.steps {
        *hist.entry(format!("{:?}", s.opcode)).or_default() += 1;
    }
    let mut by_count: Vec<_> = hist.into_iter().collect();
    by_count.sort_by(|a, b| b.1.cmp(&a.1));

    eprintln!("=== kernel-transition trace breakdown ===");
    eprintln!("total PVM steps          : {}", sn.steps.len());
    eprintln!(
        "ristretto scalar-mult ECALLs (records) : {}",
        sn.ristretto_calls.len()
    );
    eprintln!(
        "  ↳ fixed-base (comb) calls            : {}",
        sn.ristretto_comb_calls.len()
    );
    eprintln!(
        "  ↳ variable-base field rows (software): {}",
        sn.ristretto_field_rows.len()
    );
    eprintln!("blake2b compression calls: {}", sn.blake2b_calls.len());
    eprintln!("scalar binop calls       : {}", sn.scalar_binop_calls.len());
    for (i, c) in sn.ristretto_comb_calls.iter().enumerate() {
        let is_id = c.scalar == [0u8; 32];
        eprintln!(
            "  comb[{i}] scalar = {}{}",
            c.scalar
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            if is_id { "  (identity, 0·G)" } else { "" }
        );
    }
    eprintln!("--- top 15 opcodes by step count ---");
    for (op, n) in by_count.iter().take(15) {
        eprintln!("  {op:24} {n:>10}");
    }
}

/// Honest 1-debit transition over a ledger padded with `n_padding` extra
/// untouched accounts (inserted directly, bypassing the kernel — they only
/// inflate the ledger / `root_before`, not the batch). Returns the pieces
/// from which either witness flavour can be built.
#[allow(dead_code)]
fn build_padded(
    n_padding: usize,
) -> (
    VoucherPublic,
    VecLedger,
    Vec<cipher_clerk::types::Transfer>,
    OpeningsOracle,
) {
    let registrar = Keypair::generate();
    let journal = Journal::new(JournalId::random(), registrar.public, 1);
    let jid = journal.id;
    let mut ledger = VecLedger::new();
    ledger.set_journal(journal);

    let value: u64 = 100;
    let blinding = Blinding::from_bytes([3u8; 32]).expect("canonical scalar");
    let amount_commit = Amount::commit(value, &blinding);
    let mut oracle = OpeningsOracle::new(vec![Opening {
        amount: amount_commit,
        value,
        blinding,
    }]);

    let alice_kp = Keypair::generate();
    let bob_kp = Keypair::generate();
    let alice = Account::open(
        AccountKind::Asset,
        jid,
        alice_kp.public,
        Iso4217::USD,
        BankCode::Vault,
    );
    let bob = Account::open(
        AccountKind::Liability,
        jid,
        bob_kp.public,
        Iso4217::USD,
        BankCode::Checking,
    );
    let creates = cipher_clerk::apply_account_creations(
        &mut ledger,
        &[
            CreateAccount::signed(alice.clone(), &registrar.secret),
            CreateAccount::signed(bob.clone(), &registrar.secret),
        ],
        &mut oracle,
        500_000,
    );
    for r in &creates {
        assert_eq!(r.status, EventStatus::Created);
    }

    // Pad the ledger with untouched accounts (direct insert — no kernel/sig).
    let mut pad_oracle = oracle.clone();
    for _ in 0..n_padding {
        let kp = Keypair::generate();
        let acct = Account::open(
            AccountKind::Asset,
            jid,
            kp.public,
            Iso4217::USD,
            BankCode::Vault,
        );
        cipher_clerk::state::LedgerState::put_account(&mut ledger, acct, &mut pad_oracle);
    }

    let t = Transfer::builder(jid)
        .debit(&alice, Layer::Settled, amount_commit)
        .credit(&bob, Layer::Settled, amount_commit)
        .signed_with(&[(&alice, &alice_kp.secret)]);

    let root_before = ledger.root();
    let events = vec![t];
    let mut probe = ledger.clone();
    let mut probe_oracle = oracle.clone();
    let _ = cipher_clerk::apply_batch(&mut probe, &events, &mut probe_oracle, BATCH_TS);
    let root_after = probe.root();

    let public = VoucherPublic {
        issuer: registrar.public,
        amount_commit,
        state_root_before: root_before,
        state_root_after: root_after,
    };
    (public, ledger, events, oracle)
}

/// THE PAYOFF, measured end-to-end: trace the succinct guest over the SAME
/// 1-debit batch against ledgers of growing size. The succinct guest's step
/// count stays ~flat (cost = O(touched · log N), the touched leaves' paths),
/// while the full-snapshot witness BYTES grow ~linearly (the whole ledger).
/// Tracing only — no prove. Run:
///   cargo test -p prover-extension --test prove_transition \
///     measure_succinct_ledger_size_independence -- --ignored --nocapture
#[test]
#[ignore]
fn measure_succinct_ledger_size_independence() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built");
        return;
    }
    use cipher_clerk::snapshot::TransitionWitness;
    eprintln!(
        "{:>9} {:>16} {:>16} {:>13}",
        "ledger_N", "full_wit_bytes", "succ_wit_bytes", "succ_steps"
    );
    let mut steps_curve: Vec<(usize, usize)> = Vec::new();
    for &pad in &[0usize, 100, 1000, 5000] {
        let (public, snapshot, events, oracle) = build_padded(pad);
        let n = snapshot.accounts.len();
        // Full-snapshot witness = the whole ledger → bytes grow O(N).
        let full = TransitionWitness {
            snapshot: snapshot.clone(),
            oracle: oracle.clone(),
            events: events.clone(),
            batch_seed_timestamp: BATCH_TS,
        };
        let full_bytes = full.encode().len();
        // Succinct witness: touched leaves + log-depth paths.
        let succ = SuccinctTransitionWitness::from_full(&snapshot, &events, &oracle, BATCH_TS);
        let succ_bytes = succ.encode().len();
        let witness_buf = encode_witness(&public.encode(), &succ.encode());
        let steps = trace_program(PROGRAM, &witness_buf)
            .map(|sn| sn.steps.len())
            .expect("trace");
        eprintln!("{n:>9} {full_bytes:>16} {succ_bytes:>16} {steps:>13}");
        steps_curve.push((n, steps));
    }
    // The succinct guest's cost must NOT scale with ledger size: a 5000-account
    // ledger traces within 1.5× of the baseline (only the log-depth paths grow).
    let base = steps_curve.first().unwrap().1 as f64;
    let max = steps_curve.iter().map(|(_, s)| *s).max().unwrap() as f64;
    assert!(
        max <= base * 1.5,
        "succinct trace scaled with ledger size: {steps_curve:?} (max {max} > 1.5×{base})"
    );
    eprintln!(
        "succinct trace is ledger-size-independent ({}→{} accounts within {:.2}×)",
        steps_curve.first().unwrap().0,
        steps_curve.last().unwrap().0,
        max / base
    );
}

/// Per-segment step cap — sets each segment's `log_size`, hence its prove
/// memory. The 5.3M-step transition's single-shot prove (even one chip)
/// OOMs a 64 GB host; ~500K-step segments under the mobile FRI config fit
/// in well under 16 GB.
const SEG_STEPS: usize = 500_000;

/// verify_chain with the MOBILE pcs policy: boundary continuity (each
/// segment's `final_state` == the next's `initial_state`, Phase-Z0-bound)
/// + per-segment `verify_with_pcs_policy(MOBILE)`. The crate `verify_chain`
/// hardcodes the STANDARD policy and would reject mobile proofs.
///
/// Segment side notes are RE-DERIVED one at a time via `segment` (a
/// deterministic slice of the full trace) instead of being retained from
/// the prove loop — holding all of them at once costs GBs per segment and
/// is what pushes the multi-million-step chain past the host's memory.
#[allow(dead_code)]
fn verify_chain_mobile(
    proofs: &[zkpvm::Proof],
    mut segment: impl FnMut(usize) -> zkpvm::SideNote,
) -> Result<(), String> {
    for w in proofs.windows(2) {
        if w[0].final_state != w[1].initial_state {
            return Err(format!(
                "segment boundary mismatch (ts {} ≠ {})",
                w[0].final_state.timestamp, w[1].initial_state.timestamp
            ));
        }
    }
    for (i, p) in proofs.iter().enumerate() {
        let sn = segment(i);
        zkpvm::verify_with_pcs_policy(p.clone(), &sn, &zkpvm::PcsPolicy::MOBILE)
            .map_err(|e| format!("{e:?}"))?;
    }
    Ok(())
}

/// Segmentation end-to-end: prove the FULL kernel transition as a chain of
/// bounded segments and `verify_chain` it. This is the general capability —
/// any actor trace too large for a single proof becomes provable in bounded
/// memory. Also pins that a broken segment boundary is rejected.
/// Heavy (minutes); `#[ignore]` — run with:
///   cargo test -p prover-extension --test prove_transition \
///     prove_transition_segmented_chain -- --ignored --nocapture
#[test]
#[ignore]
fn prove_transition_segmented_chain() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }
    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());
    let Some(full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let total = full.steps.len();
    // The real kernel transition is millions of steps. A tiny trace means
    // the guest early-exited WITHOUT verifying (witness decode failed —
    // stale voucher-check ELF vs the current cipher-clerk witness layout),
    // and proving it would be a vacuous green. Rebuild the ELF.
    assert!(
        total > 1_000_000,
        "trace is only {total} steps — guest early-exited (stale voucher-check ELF? \
         run `just build-voucher-check`)"
    );
    let mut bounds = zkpvm::segment::segment_bounds(total, SEG_STEPS);
    // DBG_MAX_SEGS limits the chain to the first N segments for a fast
    // boundary-continuity check (a chain of mid-trace segments still
    // exercises per-segment prove + verify_chain's boundary linkage).
    if let Some(n) = std::env::var("DBG_MAX_SEGS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    {
        bounds.truncate(n.max(1));
    }
    eprintln!(
        "segmenting {total} steps → {} segments of ≤ {SEG_STEPS}",
        bounds.len()
    );

    // Prove segment-by-segment, dropping each side note after its proof:
    // the side notes are deterministic slices of `full`, re-derived at
    // verify time, so peak memory holds the full trace + ONE segment.
    let mut proofs = Vec::new();
    for (i, (a, b)) in bounds.iter().enumerate() {
        let mut sn = zkpvm::segment::segment_side_note(&full, *a, *b);
        let t = std::time::Instant::now();
        let proof = zkpvm::prove_mobile(&mut sn)
            .unwrap_or_else(|e| panic!("prove segment {i} [{a},{b}): {e:?}"));
        eprintln!(
            "  segment {i} [{a},{b}) ({} steps): proved in {:.1?}",
            b - a,
            t.elapsed()
        );
        proofs.push(proof);
    }

    let resegment = |i: usize| {
        let (a, b) = bounds[i];
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        // A re-derived slice must be normalized the way `prove` does it
        // (closing-chip activation + register-image backfills) or the
        // verifier's Fiat-Shamir transcript diverges at OODS.
        zkpvm::prepare_side_note_for_verification(&mut sn);
        sn
    };
    let t = std::time::Instant::now();
    verify_chain_mobile(&proofs, resegment)
        .expect("verify_chain (mobile) over transition segments");
    eprintln!(
        "verify_chain over {} segments: ok ({:.1?})",
        proofs.len(),
        t.elapsed()
    );

    // A broken boundary (tampered initial-state timestamp) must be rejected.
    if proofs.len() >= 2 {
        let mut forged = proofs.clone();
        forged[1].initial_state.timestamp ^= 1;
        assert!(
            verify_chain_mobile(&forged, resegment).is_err(),
            "verify_chain must reject a broken segment boundary"
        );
    }
    eprintln!(
        "ALL {total} steps PROVED + verify_chain green across {} segments",
        proofs.len()
    );
}

/// Dump the traced steps around given indices (comma-separated DBG_ROWS) —
/// maps an AssertEvaluator `row #X` back to the opcode/operands that filled
/// it. Uses the cached witness so rows line up with the failing assert run.
///   DBG_ROWS=88816,31176 cargo test -p prover-extension \
///     --test prove_transition dump_steps -- --ignored --nocapture
#[test]
#[ignore]
fn dump_steps() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built");
        return;
    }
    let witness_buf = cached_witness_buf();
    let Some(full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let rows: Vec<usize> = std::env::var("DBG_ROWS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect();
    for &r in &rows {
        eprintln!("=== rows around #{r} ===");
        for i in r.saturating_sub(3)..=(r + 3).min(full.steps.len() - 1) {
            let s = &full.steps[i];
            let av = s.regs_before.get(s.reg_a).copied().unwrap_or(0);
            let bv = s.regs_before.get(s.reg_b).copied().unwrap_or(0);
            let dv = s.regs_before.get(s.reg_d).copied().unwrap_or(0);
            let wr = s
                .reg_write
                .map(|w| format!(" → r{w}={:#x}", s.regs_after[w]))
                .unwrap_or_default();
            eprintln!(
                "  {i:>8}{} {:?} a=r{}({av:#x}) b=r{}({bv:#x}) d=r{}({dv:#x}) imm={:#x}{wr}",
                if i == r { "*" } else { " " },
                s.opcode,
                s.reg_a,
                s.reg_b,
                s.reg_d,
                s.imm,
            );
        }
    }
}

/// Pinpoint a constraint failure in a single segment (lighter than prove:
/// no FRI). Run:
///   cargo test -p prover-extension --features debug-constraints \
///     --test prove_transition debug_one_transition_segment -- --ignored --nocapture
#[cfg(feature = "debug-constraints")]
#[test]
#[ignore]
fn debug_one_transition_segment() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built");
        return;
    }
    let witness_buf = cached_witness_buf();
    let Some(full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let total = full.steps.len();
    // DBG_SEG_A/DBG_SEG_B select a [a, b) window so the AssertEvaluator fits
    // (≤ log 18) while we pinpoint the failing chip/row. DBG_SEG_A > 0
    // exercises the memory-threading path (non-initial segment).
    let a = std::env::var("DBG_SEG_A")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0)
        .min(total.saturating_sub(1));
    let b = std::env::var("DBG_SEG")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(120_000)
        .min(total);
    let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
    let comps = zkpvm::active_components(&sn);
    eprintln!("asserting segment [{a}, {b}) across {} chips…", comps.len());
    zkpvm::debug_assert_constraints_streaming(&mut sn, &comps);
    eprintln!("segment [{a}, {b}) constraints OK");
}

/// Localize a `verify_chain` "claimed logup sum is not zero" failure WITHOUT
/// proving. For each segment, generate every chip's interaction trace and sum
/// the per-component claimed logup sums: a balanced segment totals zero; the
/// segment that doesn't is the one whose proof fails to verify, and the
/// per-component breakdown points at the imbalanced relation (e.g. a memory
/// boundary mismatch, or a mis-derived ristretto-comb routing at a slice
/// boundary). Trace-gen only (no FRI), so all 11 segments check in minutes,
/// not the hour a full prove-chain costs. DBG_SEG_I=k restricts to one
/// segment index. Run:
///   cargo test -p prover-extension --features debug-constraints \
///     --test prove_transition diag_segment_logup -- --ignored --nocapture
#[cfg(feature = "debug-constraints")]
#[test]
#[ignore]
fn diag_segment_logup() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built");
        return;
    }
    let witness_buf = cached_witness_buf();
    let Some(full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let total = full.steps.len();
    let bounds = zkpvm::segment::segment_bounds(total, SEG_STEPS);
    let only = std::env::var("DBG_SEG_I")
        .ok()
        .and_then(|s| s.parse::<usize>().ok());
    eprintln!(
        "checking logup balance of {} segments of ≤ {SEG_STEPS} ({total} steps)",
        bounds.len()
    );
    let mut unbalanced = Vec::new();
    for (i, (a, b)) in bounds.iter().enumerate() {
        if only.is_some_and(|j| i != j) {
            continue;
        }
        let mut sn = zkpvm::segment::segment_side_note(&full, *a, *b);
        eprintln!("\n=== segment {i} [{a},{b}) ({} steps) ===", b - a);
        // debug_claimed_sums prints per-component sums + the total and
        // returns whether it balances; collect the verdict for a summary.
        if !zkpvm::debug_claimed_sums(&mut sn) {
            unbalanced.push(i);
        }
    }
    eprintln!("\n=== summary ===");
    if unbalanced.is_empty() {
        eprintln!("all checked segments balance");
    } else {
        eprintln!("UNBALANCED segments (proof would fail verify): {unbalanced:?}");
    }
}

/// Decide whether a per-segment logup imbalance is a SEGMENTATION boundary
/// artifact or a real per-chip bug in that region of the program: check
/// whether the FULL (un-segmented) trace's logup balances.
/// `debug_claimed_sums_streaming` accumulates the global claimed-sum one
/// chip at a time, so it fits where a single-shot prove cannot.
/// - BALANCES  → the full execution is sound; the segment imbalance is purely
///   a boundary-reconstruction bug in `segment_side_note`.
/// - DOES NOT  → a genuine chip bug fires on some op in the trace,
///   independent of segmentation.
/// Run:
///   cargo test -p prover-extension --features debug-constraints \
///     --test prove_transition debug_transition_full_logup -- --ignored --nocapture
#[cfg(feature = "debug-constraints")]
#[test]
#[ignore]
fn debug_transition_full_logup() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built");
        return;
    }
    let witness_buf = cached_witness_buf();
    let Some(mut full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let n = full.steps.len();
    let components = zkpvm::active_components(&full);
    eprintln!(
        "checking FULL-trace logup balance over {n} steps across {} chips…",
        components.len()
    );
    let ok = zkpvm::debug_claimed_sums_streaming(&mut full, &components);
    eprintln!(
        "FULL trace ({n} steps): {}",
        if ok {
            "BALANCES → segment imbalance is a boundary artifact"
        } else {
            "DOES NOT BALANCE → real per-chip bug in the trace"
        }
    );
}

/// Pinpoint the buggy step behind an intrinsic (non-boundary) logup
/// imbalance by bisecting a step window. When boundary reconstruction is
/// balanced (segments not containing the bug balance), a sub-window is
/// unbalanced IFF it contains the offending op — so binary search converges
/// on it, and we dump the opcodes in the minimal window. DBG_SCAN_FROM
/// skips ahead when the rough region is known; DBG_MIN sets the stop
/// width. Uses the cached (deterministic) witness. Run:
///   cargo test -p prover-extension --features debug-constraints \
///     --test prove_transition bisect_segment_logup -- --ignored --nocapture
#[cfg(feature = "debug-constraints")]
#[test]
#[ignore]
fn bisect_segment_logup() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built");
        return;
    }
    let witness_buf = cached_witness_buf();
    let Some(full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let total = full.steps.len();
    let env_usize = |k: &str, d: usize| {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(d)
            .min(total)
    };
    let min_w = env_usize("DBG_MIN", 200);
    // Scan window (500K segments via segment_bounds) is bounded so
    // debug_claimed_sums (which holds all chip traces) never OOMs.
    // DBG_SCAN_FROM skips ahead when the rough region is known.
    let scan_from = env_usize("DBG_SCAN_FROM", 0);

    let balances = |a: usize, b: usize| -> bool {
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        zkpvm::debug_claimed_sums(&mut sn)
    };

    // 1) Locate the first ≤500K segment (at/after scan_from) that doesn't
    //    balance — that's the one carrying the intrinsic bug.
    let (mut lo, mut hi) = {
        let mut found = None;
        let mut a = scan_from;
        while a < total {
            let b = (a + SEG_STEPS).min(total);
            eprintln!("scan segment [{a},{b})…");
            if !balances(a, b) {
                eprintln!("  → UNBALANCED; bisecting this segment");
                found = Some((a, b));
                break;
            }
            a = b;
        }
        found.unwrap_or_else(|| {
            panic!("no unbalanced segment found at/after {scan_from}; lower DBG_SCAN_FROM")
        })
    };
    eprintln!("bisecting [{lo},{hi}) for the intrinsic logup imbalance…");

    while hi - lo > min_w {
        let mid = lo + (hi - lo) / 2;
        if !balances(lo, mid) {
            eprintln!("  [{lo},{mid}) UNBALANCED → recurse left");
            hi = mid;
        } else if !balances(mid, hi) {
            eprintln!("  [{mid},{hi}) UNBALANCED → recurse right");
            lo = mid;
        } else {
            // Both halves balance but the parent doesn't → the offending
            // producer/consumer pair straddles `mid`. Stop with a small
            // window centred on mid.
            eprintln!("  straddle at mid={mid}: both halves balance; centring window");
            lo = mid.saturating_sub(min_w);
            hi = (mid + min_w).min(total);
            break;
        }
    }

    eprintln!(
        "\n=== minimal unbalanced window [{lo},{hi}) ({} steps) ===",
        hi - lo
    );
    use std::collections::BTreeMap;
    let mut hist: BTreeMap<String, u32> = BTreeMap::new();
    for s in &full.steps[lo..hi] {
        *hist.entry(format!("{:?}", s.opcode)).or_default() += 1;
    }
    eprintln!("--- opcode histogram of the window ---");
    let mut by_n: Vec<_> = hist.into_iter().collect();
    by_n.sort_by(|a, b| b.1.cmp(&a.1));
    for (op, n) in &by_n {
        eprintln!("  {op:28} {n:>5}");
    }
    eprintln!("--- step-by-step (opcode | regs a/b/d | imm | a,b vals → d val | mem) ---");
    for (i, s) in full.steps[lo..hi].iter().enumerate() {
        let av = s.regs_before.get(s.reg_a).copied().unwrap_or(0);
        let bv = s.regs_before.get(s.reg_b).copied().unwrap_or(0);
        let dv = s
            .reg_write
            .and_then(|w| s.regs_after.get(w).copied())
            .unwrap_or(0);
        let mem = match (&s.mem_read, &s.mem_write) {
            (Some(r), _) => format!(" R[{:#x}]={:#x}/{}", r.address, r.value, r.size),
            (_, Some(w)) => format!(" W[{:#x}]={:#x}/{}", w.address, w.value, w.size),
            _ => String::new(),
        };
        eprintln!(
            "  {:>8} {:<16?} a=r{} b=r{} d=r{} imm={:#x} | a={:#x} b={:#x} -> d={:#x}{mem}",
            lo + i,
            s.opcode,
            s.reg_a,
            s.reg_b,
            s.reg_d,
            s.imm,
            av,
            bv,
            dv,
        );
    }
}

/// Whole-trace constraint check (no FRI / no blowup / no Merkle commit, so
/// far lighter than `prove`). Confirms EVERY chip's constraints hold across
/// the full kernel-transition trace — i.e. that beyond the task-#7 comb fix
/// there is no other `ConstraintsNotSatisfied` lurking, which the OOM-ing
/// full prove can't tell us. Panics with `row #X, constraint #N` on the
/// first violation. Run:
///   cargo test -p prover-extension --features debug-constraints \
///     --test prove_transition debug_transition_constraints -- --nocapture
#[cfg(feature = "debug-constraints")]
#[test]
fn debug_transition_constraints() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }
    let witness_buf = cached_witness_buf();
    let Some(mut sn) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let n = sn.steps.len();
    let components = zkpvm::active_components(&sn);
    eprintln!(
        "asserting constraints over {n} steps across {} active chips…",
        components.len()
    );
    // Streaming variant: builds + asserts one chip at a time so peak memory
    // is the largest single chip, not the sum (the explicit asserter holds
    // all 26 traces and OOMs on a multi-million-step trace). Panics
    // (row/constraint) on the first violation; returns on success.
    zkpvm::debug_assert_constraints_streaming(&mut sn, &components);
    eprintln!("ALL constraints satisfied across the full {n}-step transition trace");
}

/// Trace-level io-binding regression (no prove): the guest must bind a
/// DIFFERENT io-hash for a different voucher `Public`, and each hash must
/// equal `compute_io_hash(public_bytes(public), [1])`. Reads φ[9..12]
/// from the trace's final register state — the same registers the Z0
/// closing chip pins into `proof.final_state.registers` — so it covers
/// the guest's binding end-to-end without a (segment-chain-sized) prove.
/// Also asserts the cipher-clerk precompile path is wired (ristretto
/// ECALLs present).
#[test]
fn traced_io_hash_reflects_public_input() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }
    let mut hashes = Vec::new();
    for _ in 0..2 {
        // build_transition draws fresh random ids/keys, so the two
        // iterations bind different `Public`s.
        let (public, witness) = build_transition();
        let public_bytes_rkyv = public.encode();
        let witness_bytes = witness.encode();
        assert!(
            4 + public_bytes_rkyv.len() + 4 + witness_bytes.len() <= 16384,
            "witness exceeds the guest __VOS_WITNESS buffer (grow witness_buffer!)"
        );
        let witness_buf = encode_witness(&public_bytes_rkyv, &witness_bytes);
        let Some(full) = trace_program(PROGRAM, &witness_buf) else {
            eprintln!("SKIP: trace failed");
            return;
        };
        assert!(
            !full.ristretto_calls.is_empty(),
            "kernel re-execution must reach the ristretto precompile ECALLs"
        );
        let last = full.steps.last().expect("non-empty trace");
        let mut bound = [0u8; 32];
        for (k, reg) in (9..13).enumerate() {
            bound[k * 8..(k + 1) * 8].copy_from_slice(&last.regs_after[reg].to_le_bytes());
        }
        let expected = vos::zk::compute_io_hash(&public_bytes(&public), &[1u8]);
        assert_eq!(
            bound, expected,
            "guest-bound φ[9..12] must equal compute_io_hash(public_bytes, [1])"
        );
        hashes.push(bound);
    }
    assert_ne!(
        hashes[0], hashes[1],
        "different Public must bind a different io-hash"
    );
}

/// Proof-level roundtrip + forgery rejection through the single-shot
/// prover path. The transition trace is millions of steps and only
/// proves as a segment chain, so the single-shot path cannot complete
/// here — `#[ignore]`d until chain-aware prove/verify is exposed through
/// the prover extension (see docs/plans/succinct-merkle-witness.md).
/// Until then: the chain capstone (`prove_transition_segmented_chain`)
/// covers honest proving, and `traced_io_hash_reflects_public_input`
/// covers the io-binding the forgery case relies on.
#[test]
#[ignore]
fn prove_transition_roundtrip_and_forgery_rejected() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }

    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());

    // The io-binding public half is the explicit voucher public_bytes,
    // distinct from the rkyv witness public above.
    let io_public = public_bytes(&public);
    let return_bytes = vec![1u8];

    let Some((proof_bytes, commitment, _io)) = prove_with_details(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: single-shot prove did not complete (expected — chain-sized trace)");
        return;
    };

    // Happy path: valid STARK against the proof's own commitment AND the
    // io-binding to the asserted voucher public.
    assert!(
        verify_proof_bytes(&commitment, &proof_bytes, &io_public, &return_bytes),
        "an honest transition proof must verify against the voucher public_bytes"
    );

    // Forgery: a voucher claiming a DIFFERENT root_after (a fork / fake
    // post-state) must reject — its public_bytes differ, so the io-binding
    // fails. This is the property the old weak `check` could NOT enforce.
    let mut forged = public.clone();
    forged.state_root_after = [0xEE; 32];
    let forged_io_public = public_bytes(&forged);
    assert!(
        !verify_proof_bytes(&commitment, &proof_bytes, &forged_io_public, &return_bytes),
        "a voucher with a forged root_after must NOT verify against this proof"
    );
}
