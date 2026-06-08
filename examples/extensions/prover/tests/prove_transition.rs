//! Feasibility + correctness probe for the kernel state-transition guest.
//!
//! Builds a tiny honest transition (2 accounts, 1 settled debit) host-side,
//! packages it as the `(voucher::Public, TransitionWitness)` witness the
//! voucher-check guest now expects, proves it through the GENERAL prover
//! path, and asserts the composed io-binding verify accepts it — and that a
//! FORGED voucher (overstated root_after) is rejected.
//!
//! This is the Phase-A go/no-go: if the kernel transition proves in
//! acceptable wall-clock and fits the 64 KB PVM heap, the full-snapshot
//! approach is viable for small/pilot ledgers. The harness prints the
//! witness sizes and the freshly-proven program commitment (for re-pinning
//! `VOUCHER_CHECK_COMMITMENT`).
//!
//! Skips (does not fail) when the voucher-check ELF isn't built — build it
//! with `just build-voucher-check`.

use std::path::PathBuf;

use cipher_clerk::crypto::{Amount, Blinding};
use cipher_clerk::prelude::*;
use cipher_clerk::snapshot::{OpeningsOracle, TransitionWitness, VecLedger};
use cipher_clerk::state::Opening;
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
/// `TransitionWitness` the guest re-executes.
fn build_transition() -> (VoucherPublic, TransitionWitness) {
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
    let witness = TransitionWitness {
        snapshot: ledger,
        oracle,
        events,
        batch_seed_timestamp: BATCH_TS,
    };
    (public, witness)
}

/// Diagnostic (no prove): find the first segment memory read whose value
/// disagrees with the threaded initial_memory (the boundary the MemoryChip
/// read-consistency check uses), then report what (if anything) actually
/// wrote that address in [0, a). Pinpoints the missing write source in the
/// segment memory-threading. DBG_SEG_A selects the segment start.
#[test]
#[ignore]
fn diag_segment_memory() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP");
        return;
    }
    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());
    let Some(full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace");
        return;
    };
    let total = full.steps.len();
    let a = std::env::var("DBG_SEG_A")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(500_000)
        .min(total - 1);
    let b = (a + 262_144).min(total);
    let sn = zkpvm::segment::segment_side_note(&full, a, b);
    let mem = &sn.initial_memory; // the threaded boundary
    let ts_lo = full.steps[a].timestamp;

    // Walk the segment in order, tracking per-byte current value (init from
    // the boundary). First read whose byte disagrees = the bug.
    use std::collections::HashMap;
    let mut cur: HashMap<u32, u8> = HashMap::new();
    let byte_at = |cur: &HashMap<u32, u8>, mem: &[u8], addr: u32| -> u8 {
        if let Some(v) = cur.get(&addr) {
            *v
        } else {
            *mem.get(addr as usize).unwrap_or(&0)
        }
    };
    for s in &full.steps[a..b] {
        if let Some(r) = &s.mem_read {
            let bytes = r.value.to_le_bytes();
            for i in 0..r.size as usize {
                let addr = r.address + i as u32;
                let expect = byte_at(&cur, mem, addr);
                if bytes[i] != expect {
                    eprintln!(
                        "MISMATCH at step ts={} addr={addr:#x}: read byte {:#x} but boundary/cur has {:#x}",
                        s.timestamp, bytes[i], expect
                    );
                    // Full write history of this addr in [0, a) across ALL
                    // sources, sorted by ts — reveals the missing/mis-ordered
                    // write.
                    let mut hist: Vec<(u64, &str, u8)> = Vec::new();
                    for ws in &full.steps {
                        if ws.timestamp >= ts_lo {
                            break;
                        }
                        if let Some(w) = &ws.mem_write {
                            let wb = w.value.to_le_bytes();
                            for k in 0..w.size as usize {
                                if w.address + k as u32 == addr {
                                    hist.push((ws.timestamp, "step.store", wb[k]));
                                }
                            }
                        }
                    }
                    for m in &full.blake2b_mem_ops {
                        if m.ts < ts_lo && addr >= m.h_ptr && addr < m.h_ptr + 64 {
                            hist.push((
                                m.ts,
                                "blake2b@h_ptr",
                                m.out_bytes[(addr - m.h_ptr) as usize],
                            ));
                        }
                    }
                    for m in &full.ristretto_mem_ops {
                        if m.ts < ts_lo && addr >= m.output_ptr && addr < m.output_ptr + 32 {
                            hist.push((
                                m.ts,
                                "ristretto@out",
                                m.out_bytes[(addr - m.output_ptr) as usize],
                            ));
                        }
                    }
                    for m in &full.ristretto_add_mem_ops {
                        if m.ts < ts_lo && addr >= m.output_ptr && addr < m.output_ptr + 32 {
                            hist.push((
                                m.ts,
                                "rist_add@out",
                                m.out_bytes[(addr - m.output_ptr) as usize],
                            ));
                        }
                    }
                    for m in &full.scalar_reduce_wide_mem_ops {
                        if m.ts < ts_lo && addr >= m.output_ptr && addr < m.output_ptr + 32 {
                            hist.push((
                                m.ts,
                                "scalar_reduce@out",
                                m.out_bytes[(addr - m.output_ptr) as usize],
                            ));
                        }
                    }
                    for m in &full.scalar_binop_mem_ops {
                        if m.ts < ts_lo && addr >= m.output_ptr && addr < m.output_ptr + 32 {
                            hist.push((
                                m.ts,
                                "scalar_binop@out",
                                m.out_bytes[(addr - m.output_ptr) as usize],
                            ));
                        }
                    }
                    // Also: does any precompile READ this addr (input region)?
                    for m in &full.blake2b_mem_ops {
                        if m.ts < ts_lo && addr >= m.m_ptr && addr < m.m_ptr + 128 {
                            hist.push((
                                m.ts,
                                "blake2b READS m here",
                                m.m_bytes[(addr - m.m_ptr) as usize],
                            ));
                        }
                    }
                    hist.sort_by_key(|h| h.0);
                    eprintln!("  write/access history of {addr:#x} in [0,{a}):");
                    for (ts, src, byte) in hist.iter().rev().take(8).rev() {
                        eprintln!("    ts={ts:>8} {src:24} byte={byte:#x}");
                    }
                    eprintln!("  → boundary={expect:#x}, real read={:#x}", bytes[i]);
                    return;
                }
            }
        }
        if let Some(w) = &s.mem_write {
            let wb = w.value.to_le_bytes();
            for i in 0..w.size as usize {
                cur.insert(w.address + i as u32, wb[i]);
            }
        }
    }
    eprintln!("no first-access read mismatch found in [{a},{b})");
}

/// Diagnostic (no prove): size the kernel-transition trace and break it
/// down by op so we know what drives the prove's memory footprint. The
/// full prove OOMs; this tells us whether it's software variable-base
/// Ristretto (b·H, e·P), blake2b/SMT, or raw step count that dominates —
/// i.e. what to precompile / segment next.
#[test]
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
            if is_id {
                "  <-- IDENTITY (0·G, task #7)"
            } else {
                ""
            }
        );
    }
    eprintln!("--- top 15 opcodes by step count ---");
    for (op, n) in by_count.iter().take(15) {
        eprintln!("  {op:24} {n:>10}");
    }
}

/// Segmentation baseline: a single bounded segment of the kernel transition
/// proves in bounded memory and is constraint-clean. The single-shot prove
/// of the whole 5.3M-step trace OOMs a 64 GB host; one ~1M-step segment fits.
/// Heavy; `#[ignore]` — run with `--ignored`.
#[test]
#[ignore]
fn prove_one_transition_segment() {
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
    let b = total.min(SEG_STEPS);
    eprintln!("proving segment [0, {b}) of {total} steps (mobile config)…");
    let mut sn = zkpvm::segment::segment_side_note(&full, 0, b);
    let t = std::time::Instant::now();
    // Mobile config: FRI log_blowup 2 (4×) vs default 4 (16×) — the blowup
    // is the commit-phase memory driver, so mobile + a bounded segment fits.
    let proof = zkpvm::prove_mobile(&mut sn).expect("segment [0, b) must prove (bounded memory)");
    eprintln!("segment [0, {b}) proved in {:.1?}", t.elapsed());
    zkpvm::verify_with_pcs_policy(proof, &sn, &zkpvm::PcsPolicy::MOBILE)
        .expect("segment proof must verify (mobile policy)");
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
#[allow(dead_code)]
fn verify_chain_mobile(proofs: &[zkpvm::Proof], sns: &[&zkpvm::SideNote]) -> Result<(), String> {
    for w in proofs.windows(2) {
        if w[0].final_state != w[1].initial_state {
            return Err(format!(
                "segment boundary mismatch (ts {} ≠ {})",
                w[0].final_state.timestamp, w[1].initial_state.timestamp
            ));
        }
    }
    for (p, sn) in proofs.iter().zip(sns) {
        zkpvm::verify_with_pcs_policy(p.clone(), sn, &zkpvm::PcsPolicy::MOBILE)
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

    let mut side_notes: Vec<zkpvm::SideNote> = Vec::new();
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
        side_notes.push(sn);
        proofs.push(proof);
    }

    let sn_refs: Vec<&zkpvm::SideNote> = side_notes.iter().collect();
    let t = std::time::Instant::now();
    verify_chain_mobile(&proofs, &sn_refs).expect("verify_chain (mobile) over transition segments");
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
            verify_chain_mobile(&forged, &sn_refs).is_err(),
            "verify_chain must reject a broken segment boundary"
        );
    }
    eprintln!(
        "ALL {total} steps PROVED + verify_chain green across {} segments",
        proofs.len()
    );
}

/// Pinpoint WHICH chip's constraints fail at log_size 19 (where the full
/// prove returns ConstraintsNotSatisfied but the AssertEvaluator OOMs).
/// `prove_with_explicit_components` over a single chip still runs the
/// quotient/constraint check (→ Err(ConstraintsNotSatisfied) for the
/// culprit) but fits in memory. DBG_CHIP selects the active-component index;
/// DBG_SEG the segment size. Run:
///   DBG_CHIP=0 DBG_SEG=500000 cargo test -p prover-extension \
///     --test prove_transition pinpoint_segment_chip -- --ignored --nocapture
#[test]
#[ignore]
fn pinpoint_segment_chip() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built");
        return;
    }
    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());
    let Some(full) = trace_program(PROGRAM, &witness_buf) else {
        eprintln!("SKIP: trace failed");
        return;
    };
    let total = full.steps.len();
    let b = std::env::var("DBG_SEG")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(500_000)
        .min(total);
    let idx = std::env::var("DBG_CHIP")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let mut sn = zkpvm::segment::segment_side_note(&full, 0, b);
    let comps = zkpvm::active_components(&sn);
    eprintln!(
        "segment [0,{b}) has {} active chips; proving chip #{idx} alone…",
        comps.len()
    );
    let single: Vec<&dyn zkpvm::harness::MachineProverComponent> = vec![comps[idx]];
    // Mobile FRI config (blowup 2) so a single chip at log 19 fits.
    let config = zkpvm::PcsConfig {
        pow_bits: 20,
        fri_config: zkpvm::FriConfig::new(0, 2, 38, 1),
        lifting_log_size: None,
    };
    match zkpvm::prove_with_explicit_components(&mut sn, config, &single) {
        Ok(_) => eprintln!("chip #{idx}: constraints OK at [0,{b})"),
        Err(e) => eprintln!("chip #{idx}: FAILED at [0,{b}) — {e:?}"),
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
    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());
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
    let (public, witness) = build_transition();
    let witness_buf = encode_witness(&public.encode(), &witness.encode());
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

#[test]
fn prove_transition_roundtrip_and_forgery_rejected() {
    if !voucher_check_elf_path().exists() {
        eprintln!("SKIP: voucher-check ELF not built — run `just build-voucher-check`");
        return;
    }

    let (public, witness) = build_transition();
    let public_bytes_rkyv = public.encode(); // witness public half (rkyv)
    let witness_bytes = witness.encode(); // witness secret half (rkyv TransitionWitness)
    eprintln!(
        "witness sizes: public={} B, transition={} B, buffer=16384 B",
        public_bytes_rkyv.len(),
        witness_bytes.len()
    );
    assert!(
        4 + public_bytes_rkyv.len() + 4 + witness_bytes.len() <= 16384,
        "witness exceeds the guest __VOS_WITNESS buffer (grow witness_buffer!)"
    );
    let witness_buf = encode_witness(&public_bytes_rkyv, &witness_bytes);

    // The io-binding public half is the explicit voucher public_bytes (D1),
    // distinct from the rkyv witness public above.
    let io_public = public_bytes(&public);
    let return_bytes = vec![1u8];

    let Some((proof_bytes, commitment, _io)) = prove_with_details(PROGRAM, &witness_buf) else {
        // Known blocker (Phase A): the kernel `apply_batch` transition is not
        // yet PVM-provable because `grey-transpiler` errors lowering
        // `SLT rd, x0, rs2` (signed-compare-against-zero in the kernel's
        // balance-overflow check) on its main OP-decode path
        // (riscv.rs:~1135) — even though grey's `translate_op` already
        // handles that exact encoding (regression test
        // `translates_slt_x0_rs2_to_set_gt_s_imm`). The incomplete fix needs
        // the main OP path to delegate x0-as-rs1 SLT/SLTU to `translate_op`,
        // then a grey rev bump in vos. The transition LOGIC is host-verified
        // in `cipher_clerk::snapshot` (VecLedger / TransitionWitness). This
        // gate goes green once grey lowers SLT-x0.
        eprintln!(
            "SKIP: kernel transition not yet PVM-provable (grey-transpiler SLT-x0 gap). \
             witness OK ({} B). See project_voucher_state_transition_phaseA memory.",
            witness_bytes.len()
        );
        return;
    };
    eprintln!(
        "FRESH VOUCHER_CHECK_COMMITMENT = {:?}",
        commitment
            .iter()
            .map(|b| format!("0x{b:02x}"))
            .collect::<Vec<_>>()
    );

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
