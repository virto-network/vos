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

/// Run `f` on a thread with a large (512 MiB) stack.
///
/// The standalone STARK verifier on a CANONICAL proof (all 31 components
/// present + forced large `log_size`s — `BLAKE2B_BOUNDARY` @ 17, plus the
/// natural `CPU`/`MEMORY` @ 17-19) uses far more stack than libtest's default
/// ~2 MiB test-thread stack and aborts with "stack overflow" otherwise.
/// PRODUCTION verifiers must likewise run `verify_chain_standalone_allowlist`
/// on an adequate stack (set `RUST_MIN_STACK`, or spawn a large-stack thread) —
/// a federation wire-through W1/W2 wiring requirement, not just a test detail.
fn run_with_large_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .expect("spawn large-stack thread")
        .join()
        .expect("large-stack test body panicked");
}

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

/// Phase-A sizing (trustless-chain-verification roadmap): measure the
/// per-segment touched-memory BOUNDARY on the REAL transition workload —
/// distinct touched pages (the Merkle-multiproof leaf count that drives the
/// in-circuit blake2b cost of binding `memory_commitment`) + read-before-write
/// / written address counts. Informs page granularity and whether Phase A is
/// cheap (KBs of pages) or notable (MBs). Measurement only — no proving.
///   cargo test -p prover-extension --test prove_transition \
///     measure_memory_boundary -- --ignored --nocapture
#[test]
#[ignore]
fn measure_memory_boundary() {
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
    assert!(total > 1_000_000, "trace only {total} steps — stale ELF?");
    let bounds = zkpvm::segment::segment_bounds(total, SEG_STEPS);
    eprintln!(
        "total steps: {total}; {} segments of <= {SEG_STEPS}",
        bounds.len()
    );
    eprintln!();
    eprintln!("seg    steps     bytes      rbw  written  pg@64  pg@256  pg@1024  pg@4096");
    let mut max_pages = [0usize; 4];
    let mut sum_pages = [0usize; 4];
    let mut max_rbw = 0usize;
    let mut max_written = 0usize;
    for (i, &(a, b)) in bounds.iter().enumerate() {
        let sn = zkpvm::segment::segment_side_note(&full, a, b);
        let r = zkpvm::chips::memory::analyze_dedup(&sn);
        let p: Vec<usize> = r.distinct_pages.iter().map(|&(_, c)| c).collect();
        eprintln!(
            "{i:>3}  {:>8}  {:>8}  {:>7}  {:>7}  {:>5}  {:>6}  {:>7}  {:>7}",
            b - a,
            r.distinct_addresses,
            r.read_before_write,
            r.written_addresses,
            p[0],
            p[1],
            p[2],
            p[3],
        );
        for k in 0..4 {
            max_pages[k] = max_pages[k].max(p[k]);
            sum_pages[k] += p[k];
        }
        max_rbw = max_rbw.max(r.read_before_write);
        max_written = max_written.max(r.written_addresses);
    }
    let n = bounds.len().max(1);
    eprintln!();
    eprintln!(
        "PER-SEGMENT MAX:  rbw={max_rbw}  written={max_written}  pages: @64={} @256={} @1024={} @4096={}",
        max_pages[0], max_pages[1], max_pages[2], max_pages[3]
    );
    eprintln!(
        "PER-SEGMENT AVG:  pages: @64={} @256={} @1024={} @4096={}",
        sum_pages[0] / n,
        sum_pages[1] / n,
        sum_pages[2] / n,
        sum_pages[3] / n
    );
}

/// Canonical-shape BLOCKER measurement (federation wire-through W0, "measure
/// first"): how many DISTINCT preprocessed-commitment shapes would canonical
/// proving produce across the whole segment chain?
///
/// Forcing each preprocessed-bearing chip to a fixed per-chip `log_size` pins
/// every chip whose preprocessed COLUMNS are a pure function of `log_size`
/// (a period/table) — blake2b, blake2b-boundary, memory-page, and 5 of the 7
/// ristretto chips (ecall, comb-anchor, comb-scalar-boundary,
/// comb-compress-output, the field-op chip): all positional, so at a fixed
/// forced `log_size` they emit identical preprocessed columns for every
/// segment. The TWO exceptions are `RistrettoFixedBaseConsumerChip`
/// (`IsFinalAccProducer`/`FinalAccCallIdx`/`FinalAccCoordKind` set only on the
/// real call-blocks, `ristretto_fixed_base_consumer.rs:675`) and
/// `RistrettoCombCompressChip` (`IsUnityCheck`/`IsOutputProducer`/`CallIdx`/
/// `IsCoordInputConsumer` gated on `real_n_rows`,
/// `ristretto_comb_compress.rs:1468`): their preprocessed CONTENT is a pure
/// function of the per-segment comb-call count, so two segments with different
/// comb-call counts get DIFFERENT preprocessed commitments even at the same
/// forced `log_size`.
///
/// Therefore the number of distinct per-segment comb-call counts == the number
/// of distinct canonical program commitments the chain would need. This
/// measures that (trace-gen only, NO proving): a small bounded set ⇒ a
/// commitment-allowlist is viable; a large/varying set ⇒ canonical proving (A)
/// needs the positional-at-fixed-M comb-chip rework, or (B) the separate
/// program-identity commitment.
///   SEG_STEPS=100000 cargo test -p prover-extension --release \
///     --test prove_transition measure_comb_preproc_shapes -- --ignored --nocapture
#[test]
#[ignore]
fn measure_comb_preproc_shapes() {
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
    assert!(total > 1_000_000, "trace only {total} steps — stale ELF?");
    let seg_steps = std::env::var("SEG_STEPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(SEG_STEPS);
    let bounds = zkpvm::segment::segment_bounds(total, seg_steps);
    let n_seg = bounds.len();
    eprintln!("total steps: {total}; {n_seg} segments of <= {seg_steps}");

    // Bucket every precompile record into its segment by timestamp, using the
    // SAME [ts_lo, ts_hi) window `segment_side_note` uses (so the counts equal
    // what each segment's chips see).
    let seg_of = |ts: u64| -> Option<usize> {
        bounds.iter().position(|&(a, b)| {
            let ts_lo = full.steps[a].timestamp;
            let ts_hi = full.steps.get(b).map(|s| s.timestamp).unwrap_or(u64::MAX);
            ts >= ts_lo && ts < ts_hi
        })
    };
    let mut comb = vec![0usize; n_seg];
    let mut ecall = vec![0usize; n_seg];
    let mut blake = vec![0usize; n_seg];
    for c in &full.ristretto_comb_calls {
        if let Some(s) = seg_of(c.ts) {
            comb[s] += 1;
        }
    }
    // RistrettoEcallChip block count (positional chip — drives its SIZE only).
    for op in &full.ristretto_mem_ops {
        if let Some(s) = seg_of(op.ts) {
            ecall[s] += 1;
        }
    }
    for op in &full.blake2b_mem_ops {
        if let Some(s) = seg_of(op.ts) {
            blake[s] += 1;
        }
    }

    eprintln!();
    eprintln!("seg    steps   comb_calls  ristretto_mem_ops  blake2b_mem_ops");
    for (i, &(a, b)) in bounds.iter().enumerate() {
        if comb[i] > 0 || ecall[i] > 0 || blake[i] > 0 {
            eprintln!(
                "{i:>3}  {:>8}  {:>10}  {:>17}  {:>15}",
                b - a,
                comb[i],
                ecall[i],
                blake[i]
            );
        }
    }

    use std::collections::BTreeMap;
    let mut hist: BTreeMap<usize, usize> = BTreeMap::new();
    for &c in &comb {
        *hist.entry(c).or_default() += 1;
    }
    let distinct = hist.len();
    let comb_segments = comb.iter().filter(|&&c| c > 0).count();
    let max_comb = comb.iter().copied().max().unwrap_or(0);
    eprintln!();
    eprintln!("comb-call-count histogram (calls -> #segments): {hist:?}");
    eprintln!("segments with >=1 comb call: {comb_segments} / {n_seg}");
    eprintln!("max comb calls in any single segment: {max_comb}");
    eprintln!();
    eprintln!(
        "==> DISTINCT comb-call counts = {distinct} => canonical-shape proving \
         (forcing log_size) yields {distinct} distinct program commitments \
         (the 2 comb chips are the only witness-dependent-preprocessed chips)."
    );
    if distinct <= 3 {
        eprintln!(
            "    SMALL bounded set: a {distinct}-entry commitment allowlist is viable, \
             OR pad the comb witness to the canonical max ({max_comb}) call-blocks."
        );
    } else {
        eprintln!(
            "    LARGE set: needs the positional-at-fixed-M comb-chip rework (A) \
             or the separate program-identity commitment (B)."
        );
    }
}

/// Lock the canonical forcing profile (federation wire-through W0): the
/// per-chip MAX natural `log_size` of each forcing-set chip across ALL
/// segments. `prove_canonical` pads each forcing-set chip up to this value, so
/// every segment's forced chips share one `log_size` and the only remaining
/// commitment variation is the 2 comb chips' witness-gated CONTENT (handled by
/// the allowlist). The profile MUST be >= every segment's natural size or that
/// segment lands on a third (unlisted) commitment. Trace-gen only (no FRI),
/// but heavy (per-segment page-merkle ingest + per-chip trace-gen).
///   SEG_STEPS=100000 cargo test -p prover-extension --release \
///     --test prove_transition measure_canonical_profile -- --ignored --nocapture
#[test]
#[ignore]
fn measure_canonical_profile() {
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
    assert!(total > 1_000_000, "trace only {total} steps — stale ELF?");
    let seg_steps = std::env::var("SEG_STEPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(SEG_STEPS);
    let bounds = zkpvm::segment::segment_bounds(total, seg_steps);
    // chip_idx of the forcing set (variable preprocessed-bearing chips).
    const FORCING: [usize; 10] = [1, 2, 4, 23, 24, 26, 27, 28, 29, 30];
    const NAMES: [&str; 10] = [
        "BLAKE2B",
        "BLAKE2B_BOUNDARY",
        "MEMORY_PAGE",
        "RISTRETTO",
        "RIST_ECALL",
        "FIXED_BASE_CONSUMER",
        "COMB_ANCHOR",
        "COMB_SCALAR_BOUNDARY",
        "COMB_COMPRESS",
        "COMB_COMPRESS_OUTPUT",
    ];
    eprintln!(
        "profiling {} segments of <= {seg_steps} ({total} steps)…",
        bounds.len()
    );
    let mut maxes = [0u32; 10];
    for (i, &(a, b)) in bounds.iter().enumerate() {
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        let sizes = zkpvm::natural_log_sizes_for(&mut sn, &FORCING);
        for k in 0..10 {
            maxes[k] = maxes[k].max(sizes[k]);
        }
        if i % 10 == 0 || !sn.ristretto_comb_calls.is_empty() {
            eprintln!("  seg {i:>3}: {sizes:?}");
        }
    }
    eprintln!();
    eprintln!("=== per-chip MAX natural log_size across all segments ===");
    for k in 0..10 {
        eprintln!(
            "  chip_idx {:>2} {:<22} = {}",
            FORCING[k], NAMES[k], maxes[k]
        );
    }
    // Emit the full chip_idx-indexed profile literal (0 for non-forcing chips).
    let mut arr = [0u32; 31];
    for k in 0..10 {
        arr[FORCING[k]] = maxes[k];
    }
    eprintln!();
    eprintln!("VOUCHER_CHECK_CANONICAL_PROFILE (chip_idx 0..31) = {arr:?}");
    let cap = *maxes.iter().max().unwrap();
    assert!(
        cap <= 24,
        "a forcing-set chip needs log_size {cap} > DEFAULT_MAX_LOG_SIZE (24)"
    );
}

/// Canonical-shape sizing (federation wire-through W0): prove a few segments
/// of the real transition and dump each one's `(num_components, component_mask,
/// log_sizes, program_commitment)`. Confirms the load-bearing finding — that
/// structurally-different segments produce DIFFERENT commitments (so a single
/// published commitment can't pin a witness-varying chain without forcing a
/// canonical per-chip log_size profile) — and prints the per-chip MAX log_size
/// across the proved segments (the canonical profile the padding mode targets).
/// Also the proving-time release re-measure (lever 0).
///   DBG_MAX_SEGS=4 SEG_STEPS=200000 cargo test -p prover-extension --release \
///     --test prove_transition measure_segment_log_sizes -- --ignored --nocapture
#[test]
#[ignore]
fn measure_segment_log_sizes() {
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
    assert!(total > 1_000_000, "trace only {total} steps — stale ELF?");
    let seg_steps = std::env::var("SEG_STEPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(SEG_STEPS);
    let all_bounds = zkpvm::segment::segment_bounds(total, seg_steps);
    let n_all = all_bounds.len();
    // Map a step ts to its segment index.
    let seg_of = |ts: u64| -> Option<usize> {
        all_bounds
            .iter()
            .position(|&(a, b)| (ts as usize) >= a && (ts as usize) < b)
    };
    // Bucket the precompile ECALLs by segment (cheap — no proving) so we can
    // sample the crypto-bearing segments (where the ristretto / blake2b chips
    // peak), not just an even spread that misses the ~7 clustered scalar_mults.
    let mut rist = std::collections::BTreeSet::new();
    for op in &full.ristretto_mem_ops {
        if let Some(s) = seg_of(op.ts) {
            rist.insert(s);
        }
    }
    let mut blake_per_seg = vec![0usize; n_all];
    for op in &full.blake2b_mem_ops {
        if let Some(s) = seg_of(op.ts) {
            blake_per_seg[s] += 1;
        }
    }
    let max_blake_seg = (0..n_all).max_by_key(|&i| blake_per_seg[i]).unwrap_or(0);
    eprintln!(
        "ristretto-bearing segments: {:?}; max-blake2b segment: #{max_blake_seg} ({} calls)",
        rist, blake_per_seg[max_blake_seg]
    );
    // DBG_SEGS=0,25,... overrides; else auto-pick {0, last, max-blake2b,
    // ristretto segments} — the archetypes whose union sets the canonical max.
    let idxs: Vec<usize> = match std::env::var("DBG_SEGS").ok() {
        Some(s) => s
            .split(',')
            .filter_map(|x| x.trim().parse::<usize>().ok())
            .filter(|&i| i < n_all)
            .collect(),
        None => {
            let mut set: std::collections::BTreeSet<usize> = rist.clone();
            set.insert(0);
            set.insert(n_all.saturating_sub(1));
            set.insert(max_blake_seg);
            set.into_iter().collect()
        }
    };
    let bounds: Vec<(usize, usize)> = idxs.iter().map(|&i| all_bounds[i]).collect();
    eprintln!(
        "segmenting {total} steps → {n_all} segments of ≤ {seg_steps}; proving indices {idxs:?}"
    );

    // chip index -> max log_size seen across the proved segments.
    let mut per_chip_max = [0u32; 32];
    let mut commitments: Vec<String> = Vec::new();
    for (i, &(a, b)) in bounds.iter().enumerate() {
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        let t = std::time::Instant::now();
        let proof = zkpvm::prove_mobile(&mut sn)
            .unwrap_or_else(|e| panic!("prove segment {i} [{a},{b}): {e:?}"));
        let elapsed = t.elapsed();
        let commit = zkpvm::program_commitment_of_proof(&proof).to_string();
        // Expand log_sizes (ordered by active components) onto chip indices via
        // the component mask.
        let mask = proof.component_mask;
        let mut per_chip = [0u32; 32];
        let mut j = 0usize;
        for chip_i in 0..32 {
            if (mask >> chip_i) & 1 == 1 {
                let ls = proof.log_sizes[j];
                per_chip[chip_i] = ls;
                per_chip_max[chip_i] = per_chip_max[chip_i].max(ls);
                j += 1;
            }
        }
        eprintln!(
            "seg #{} [{a},{b}) {} steps  ncomp={} mask={:#010x}  proved {:.1?}\n     log_sizes={:?}\n     commitment={commit}",
            idxs[i],
            b - a,
            proof.num_components,
            mask,
            elapsed,
            proof.log_sizes,
        );
        commitments.push(commit);
    }

    let distinct: std::collections::BTreeSet<&String> = commitments.iter().collect();
    eprintln!();
    eprintln!(
        "DISTINCT COMMITMENTS across {} proved segments: {} (=> {})",
        commitments.len(),
        distinct.len(),
        if distinct.len() > 1 {
            "HETEROGENEOUS — one published commitment needs canonical-shape padding"
        } else {
            "uniform (these segments share a shape)"
        }
    );
    eprintln!("PER-CHIP MAX log_size (canonical profile target): {per_chip_max:?}");
}

/// W0 validation gate (federation wire-through): canonical-shape proving with
/// [`prover_extension::VOUCHER_CHECK_CANONICAL_PROFILE`] collapses the
/// conservation transition's heterogeneous segments onto the small published
/// commitment allowlist `{C_0, C_1}`.
///
/// Asserts:
///  - two structurally-DIFFERENT comb-free segments (different natural blake2b
///    / page sizes) produce the SAME commitment `C_0` — canonical forcing
///    unified their non-comb shape variation;
///  - the segment carrying a fixed-base scalar mult produces `C_1 != C_0` (the
///    2 comb chips' `real_n_rows`-gated preprocessed content — the only
///    residual variation, which the allowlist absorbs);
///  - every segment verifies standalone (MOBILE) against its own commitment;
///  - `verify_chain_standalone_allowlist` accepts a contiguous chain whose
///    segments are all in `{C_0, C_1}`, and rejects one outside the set.
///
/// Prints `C_0` / `C_1` for re-pinning `VOUCHER_CHECK_COMMITMENTS`.
///   SEG_STEPS=100000 cargo test -p prover-extension --release \
///     --test prove_transition canonical_commitment_allowlist -- --ignored --nocapture
#[test]
#[ignore]
fn canonical_commitment_allowlist() {
    run_with_large_stack(canonical_commitment_allowlist_impl);
}

fn canonical_commitment_allowlist_impl() {
    use zkpvm_verifier::{
        DEFAULT_MAX_LOG_SIZE, PcsPolicy, verify_chain_standalone_allowlist,
        verify_standalone_with_pcs_policy,
    };
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
    assert!(total > 1_000_000, "trace only {total} steps — stale ELF?");
    let seg_steps = std::env::var("SEG_STEPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(SEG_STEPS);
    let bounds = zkpvm::segment::segment_bounds(total, seg_steps);
    let n = bounds.len();
    assert!(n >= 3, "need >= 3 segments to exercise the allowlist");

    // The comb (fixed-base scalar mult) segment — the only shape carrying C_1.
    let comb_seg = (0..n)
        .find(|&i| {
            let (a, b) = bounds[i];
            !zkpvm::segment::segment_side_note(&full, a, b)
                .ristretto_comb_calls
                .is_empty()
        })
        .expect("the conservation transition must contain a fixed-base scalar mult (comb) segment");
    eprintln!("comb segment = #{comb_seg} of {n}");

    let profile = &prover_extension::VOUCHER_CHECK_CANONICAL_PROFILE;
    let prove_seg = |i: usize| -> zkpvm::Proof {
        let (a, b) = bounds[i];
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        zkpvm::prove_canonical(&mut sn, profile)
            .unwrap_or_else(|e| panic!("prove_canonical seg {i} [{a},{b}): {e:?}"))
    };

    // Two comb-free segments as far apart as possible (very different natural
    // blake2b / page sizes) — both must collapse to C_0 under forcing.
    let cf_a = 0usize;
    let mut cf_b = n - 1;
    if cf_b == comb_seg {
        cf_b = n - 2;
    }
    assert!(cf_a != comb_seg && cf_b != comb_seg && cf_a != cf_b);

    let p_a = prove_seg(cf_a);
    let p_b = prove_seg(cf_b);
    let p_comb = prove_seg(comb_seg);
    let c0_a = zkpvm::program_commitment_of_proof(&p_a);
    let c0_b = zkpvm::program_commitment_of_proof(&p_b);
    let c1 = zkpvm::program_commitment_of_proof(&p_comb);
    eprintln!("C(seg {cf_a}, comb-free) = {c0_a}");
    eprintln!("C(seg {cf_b}, comb-free) = {c0_b}");
    eprintln!("C(seg {comb_seg}, comb)  = {c1}");

    assert_eq!(
        c0_a, c0_b,
        "canonical forcing must unify structurally-different comb-free segments \
         onto ONE commitment C_0 (segments {cf_a} and {cf_b})"
    );
    assert_ne!(
        c0_a, c1,
        "the comb segment's witness-gated preprocessed content must yield a \
         distinct commitment C_1 (this is why the chain needs an allowlist)"
    );

    verify_standalone_with_pcs_policy(p_a.clone(), c0_a, &PcsPolicy::MOBILE)
        .expect("comb-free segment must verify standalone (MOBILE)");
    verify_standalone_with_pcs_policy(p_b, c0_b, &PcsPolicy::MOBILE)
        .expect("comb-free segment must verify standalone (MOBILE)");
    verify_standalone_with_pcs_policy(p_comb.clone(), c1, &PcsPolicy::MOBILE)
        .expect("comb segment must verify standalone (MOBILE)");

    // A contiguous comb-free chain (seg 0 + seg 1, both C_0) verifies under the
    // {C_0, C_1} allowlist.
    let p0 = p_a;
    let p1 = prove_seg(1);
    let allowlist = [c0_a, c1];
    let expected_root = p0.initial_state.memory_root;
    verify_chain_standalone_allowlist(
        &[p0.clone(), p1.clone()],
        &allowlist,
        expected_root,
        DEFAULT_MAX_LOG_SIZE,
        &PcsPolicy::MOBILE,
    )
    .expect("contiguous comb-free chain must verify under the {C_0, C_1} allowlist");

    // A commitment outside the allowlist is rejected.
    let mut bad = c0_a;
    bad.0[0] ^= 0xFF;
    verify_chain_standalone_allowlist(
        &[p0, p1],
        &[bad],
        expected_root,
        DEFAULT_MAX_LOG_SIZE,
        &PcsPolicy::MOBILE,
    )
    .expect_err("a chain whose segment commitments are not in the allowlist must be rejected");

    // Heterogeneous chain: a CONTIGUOUS run spanning the comb segment
    // (comb_seg-1 = C_0, comb_seg = C_1, comb_seg+1 = C_0) — the real federation
    // case, a chain carrying BOTH canonical shapes — must verify under the
    // {C_0, C_1} allowlist (boundary continuity holds across the C_0→C_1→C_0
    // shape change; only the commitment differs).
    if comb_seg >= 1 && comb_seg + 1 < n {
        let p_before = prove_seg(comb_seg - 1);
        let p_after = prove_seg(comb_seg + 1);
        let het = [p_before, p_comb, p_after];
        let het_commits: Vec<_> = het.iter().map(zkpvm::program_commitment_of_proof).collect();
        assert!(
            het_commits.contains(&c1),
            "the heterogeneous chain must actually include the C_1 (comb) shape"
        );
        verify_chain_standalone_allowlist(
            &het,
            &allowlist,
            het[0].initial_state.memory_root,
            DEFAULT_MAX_LOG_SIZE,
            &PcsPolicy::MOBILE,
        )
        .expect("a contiguous C_0–C_1–C_0 chain must verify under the {C_0, C_1} allowlist");
        eprintln!(
            "heterogeneous chain [{},{},{}] verified under the allowlist",
            comb_seg - 1,
            comb_seg,
            comb_seg + 1
        );
    }

    eprintln!("\nW0 GATE GREEN — canonical proving yields the 2-entry allowlist.");
    eprintln!(
        "VOUCHER_CHECK_COMMITMENTS[0] (C_0, comb-free) = {:?}",
        c0_a.0
    );
    eprintln!("VOUCHER_CHECK_COMMITMENTS[1] (C_1, one comb)  = {:?}", c1.0);
}

/// Drift guard for the re-pinned canonical commitment allowlist (federation
/// wire-through W0). Re-derives `C_0` (a comb-free segment) and `C_1` (the comb
/// segment) via canonical proving and asserts they equal the baked
/// [`prover_extension::VOUCHER_CHECK_COMMITMENTS`]. Fails loudly if the AIR, the
/// canonical profile, or the voucher-check ELF changes the program commitment —
/// re-run `canonical_commitment_allowlist`, paste the printed values, and bump
/// the proof-format version if the change is an AIR change.
///   SEG_STEPS=100000 cargo test -p prover-extension --release \
///     --test prove_transition canonical_commitment_drift_guard -- --ignored --nocapture
#[test]
#[ignore]
fn canonical_commitment_drift_guard() {
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
    assert!(total > 1_000_000, "trace only {total} steps — stale ELF?");
    let seg_steps = std::env::var("SEG_STEPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(SEG_STEPS);
    let bounds = zkpvm::segment::segment_bounds(total, seg_steps);
    let n = bounds.len();
    let comb_seg = (0..n)
        .find(|&i| {
            let (a, b) = bounds[i];
            !zkpvm::segment::segment_side_note(&full, a, b)
                .ristretto_comb_calls
                .is_empty()
        })
        .expect("conservation transition must contain a comb segment");

    let profile = &prover_extension::VOUCHER_CHECK_CANONICAL_PROFILE;
    let prove_seg = |i: usize| {
        let (a, b) = bounds[i];
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        let proof = zkpvm::prove_canonical(&mut sn, profile)
            .unwrap_or_else(|e| panic!("prove_canonical seg {i}: {e:?}"));
        zkpvm::program_commitment_of_proof(&proof).0
    };
    let c0 = prove_seg(0);
    let c1 = prove_seg(comb_seg);

    let baked = prover_extension::VOUCHER_CHECK_COMMITMENTS;
    assert_eq!(
        c0, baked[0],
        "C_0 (comb-free canonical commitment) drifted — re-run \
         canonical_commitment_allowlist and re-pin VOUCHER_CHECK_COMMITMENTS[0]"
    );
    assert_eq!(
        c1, baked[1],
        "C_1 (one-comb canonical commitment) drifted — re-pin \
         VOUCHER_CHECK_COMMITMENTS[1]"
    );
}

/// Fast (no-prove) coverage of the manifest codec + the `verify_chain_segments`
/// guard/reject paths that short-circuit before any STARK work. Complements the
/// heavy `chain_manifest_roundtrip` (which exercises the accept path on a real
/// chain) so a regression in the cheap logic is caught without a ~13-min prove.
#[test]
fn manifest_codec_and_verify_guards() {
    // Manifest codec round-trips an ordered hash list (order-preserving).
    let hashes: Vec<[u8; 32]> = (0u8..5).map(|i| [i; 32]).collect();
    let blob = prover_extension::encode_chain_manifest(&hashes);
    assert_eq!(
        prover_extension::decode_chain_manifest(&blob).as_deref(),
        Some(&hashes[..]),
        "manifest encode→decode must preserve the ordered segment hashes"
    );
    // A garbled manifest blob decodes to None (not a panic, not a partial list).
    assert!(
        prover_extension::decode_chain_manifest(&[0xFFu8; 7]).is_none(),
        "a malformed manifest blob must decode to None"
    );

    let c0 = prover_extension::VOUCHER_CHECK_COMMITMENTS[0];
    let io = b"some-public-bytes";
    // Empty chain → reject (no segments to anchor/verify).
    assert!(
        !prover_extension::verify_chain_segments(&c0[..], &[], io, &[1u8]),
        "an empty segment list must reject"
    );
    // Non-32-byte commitment → reject before any work.
    assert!(
        !prover_extension::verify_chain_segments(&[0u8; 16], &[vec![0u8; 4]], io, &[1u8]),
        "a non-32-byte commitment must reject"
    );
    // A commitment outside every published allowlist → reverse-lookup miss →
    // reject before decoding any segment.
    let mut foreign = c0;
    foreign[0] ^= 0xFF;
    assert!(
        !prover_extension::verify_chain_segments(&foreign[..], &[vec![0u8; 4]], io, &[1u8]),
        "a commitment outside the allowlist must reject"
    );
    // A valid allowlisted commitment but garbage segment bytes → per-segment
    // decode fails → reject (no panic).
    assert!(
        !prover_extension::verify_chain_segments(&c0[..], &[vec![0xABu8; 32]], io, &[1u8]),
        "an undecodable segment blob must reject"
    );
}

/// W1 round-trip (federation wire-through): prove the conservation transition
/// as a canonical segment CHAIN through `prove_chain_segments`, then verify it
/// through `verify_chain_segments` against the baked canonical commitment
/// allowlist + the io-binding — the federation happy path minus the
/// runtime/bridge/libp2p plumbing (the manifest CAS round-trip is exercised by
/// the federation e2e §5h). `verify_chain_segments` runs the (stack-heavy)
/// canonical chain verify on its own large-stack thread, so this test needs no
/// `run_with_large_stack` wrapper.
///   SEG_STEPS unused here (prove_chain_segments pins CHAIN_SEG_STEPS); heavy.
///   cargo test -p prover-extension --release --test prove_transition \
///     chain_manifest_roundtrip -- --ignored --nocapture --test-threads=1
#[test]
#[ignore]
fn chain_manifest_roundtrip() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }
    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());
    let segments = prover_extension::prove_chain_segments(PROGRAM, &witness_buf)
        .expect("prove_chain_segments over the conservation transition (stale ELF?)");

    let io_public = public_bytes(&public);
    let c0 = prover_extension::VOUCHER_CHECK_COMMITMENTS[0];
    let c1 = prover_extension::VOUCHER_CHECK_COMMITMENTS[1];

    // Happy: honest chain + an allowlisted commitment + the correct io-binding.
    assert!(
        prover_extension::verify_chain_segments(&c0[..], &segments, &io_public, &[1u8]),
        "an honest canonical chain must verify against C_0 + the io-binding"
    );
    // Passing C_1 resolves the SAME {C_0, C_1} allowlist → also accepts (the
    // chain's per-segment commitments are matched by SET membership).
    assert!(
        prover_extension::verify_chain_segments(&c1[..], &segments, &io_public, &[1u8]),
        "passing C_1 must resolve the same allowlist and accept"
    );
    // Forged io: a different root_after → public_bytes differ → the final
    // segment's STARK-bound io-hash no longer matches → reject.
    let mut forged = public.clone();
    forged.state_root_after = [0xEE; 32];
    assert!(
        !prover_extension::verify_chain_segments(
            &c0[..],
            &segments,
            &public_bytes(&forged),
            &[1u8]
        ),
        "a forged root_after (io-hash mismatch) must reject"
    );
    // A commitment outside every published allowlist → reverse-lookup misses → reject.
    let mut wrong = c0;
    wrong[0] ^= 0xFF;
    assert!(
        !prover_extension::verify_chain_segments(&wrong[..], &segments, &io_public, &[1u8]),
        "a commitment outside the allowlist must reject"
    );
    // Truncated chain: drop the final segment → the (now-)last segment's
    // halt-bound io-hash no longer matches the asserted io (and continuity to
    // the dropped segment is gone) → reject. A short manifest cannot pass.
    if segments.len() > 1 {
        let truncated = &segments[..segments.len() - 1];
        assert!(
            !prover_extension::verify_chain_segments(&c0[..], truncated, &io_public, &[1u8]),
            "a truncated chain (missing final segment) must reject"
        );
    }
    // Also round-trip the manifest codec itself (the tiny blob the voucher
    // addresses): encoding N hashes and decoding them must be order-preserving.
    let hashes: Vec<[u8; 32]> = (0..segments.len() as u8).map(|i| [i; 32]).collect();
    let manifest_blob = prover_extension::encode_chain_manifest(&hashes);
    assert_eq!(
        prover_extension::decode_chain_manifest(&manifest_blob).as_deref(),
        Some(&hashes[..]),
        "manifest encode/decode must round-trip the ordered segment hashes"
    );
    eprintln!("chain_manifest_roundtrip GREEN: canonical chain verifies via the allowlist");
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
    run_with_large_stack(prove_transition_segmented_chain_impl);
}

fn prove_transition_segmented_chain_impl() {
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
    // SEG_STEPS env override: smaller segments cap per-segment prover RAM (the
    // Phase-A memory machinery — per-page boundary injection + Blake2bBoundary —
    // pushes a 500k-step segment to ~37 GB peak, OOM-prone on a 62 GB box).
    let seg_steps = std::env::var("SEG_STEPS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(SEG_STEPS);
    let mut bounds = zkpvm::segment::segment_bounds(total, seg_steps);
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
        "segmenting {total} steps → {} segments of ≤ {seg_steps}",
        bounds.len()
    );

    // Prove segment-by-segment with CANONICAL-SHAPE proving (the federation
    // path): every segment shares VOUCHER_CHECK_CANONICAL_PROFILE and lands on
    // one of the small commitment allowlist {C_0, C_1}. Drop each side note
    // after its proof (peak memory holds the full trace + ONE segment); collect
    // the distinct commitments observed — that IS the chain's allowlist.
    use zkpvm_verifier::{DEFAULT_MAX_LOG_SIZE, PcsPolicy, verify_chain_standalone_allowlist};
    let profile = &prover_extension::VOUCHER_CHECK_CANONICAL_PROFILE;
    let mut proofs = Vec::new();
    let mut allowlist: Vec<zkpvm::ProgramCommitment> = Vec::new();
    for (i, (a, b)) in bounds.iter().enumerate() {
        let mut sn = zkpvm::segment::segment_side_note(&full, *a, *b);
        let t = std::time::Instant::now();
        let proof = zkpvm::prove_canonical(&mut sn, profile)
            .unwrap_or_else(|e| panic!("prove_canonical segment {i} [{a},{b}): {e:?}"));
        let c = zkpvm::program_commitment_of_proof(&proof);
        if !allowlist.contains(&c) {
            allowlist.push(c);
        }
        eprintln!(
            "  segment {i} [{a},{b}) ({} steps): proved canonical in {:.1?} ({c})",
            b - a,
            t.elapsed()
        );
        proofs.push(proof);
    }
    eprintln!(
        "distinct canonical commitments across the chain: {} ({allowlist:?})",
        allowlist.len()
    );

    // Side-note-FREE chain verification against the (self-derived) allowlist —
    // the trustless federation path, NOT the test-local verify_chain_mobile.
    let expected_root = proofs[0].initial_state.memory_root;
    let t = std::time::Instant::now();
    verify_chain_standalone_allowlist(
        &proofs,
        &allowlist,
        expected_root,
        DEFAULT_MAX_LOG_SIZE,
        &PcsPolicy::MOBILE,
    )
    .expect("verify_chain_standalone_allowlist over canonical transition segments");
    eprintln!(
        "verify_chain_standalone_allowlist over {} segments: ok ({:.1?})",
        proofs.len(),
        t.elapsed()
    );

    // A broken boundary (tampered initial-state timestamp) must be rejected.
    if proofs.len() >= 2 {
        let mut forged = proofs.clone();
        forged[1].initial_state.timestamp ^= 1;
        assert!(
            verify_chain_standalone_allowlist(
                &forged,
                &allowlist,
                expected_root,
                DEFAULT_MAX_LOG_SIZE,
                &PcsPolicy::MOBILE,
            )
            .is_err(),
            "verify_chain must reject a broken segment boundary"
        );
    }
    eprintln!(
        "ALL {total} steps PROVED canonical + verify_chain_standalone_allowlist \
         green across {} segments",
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
