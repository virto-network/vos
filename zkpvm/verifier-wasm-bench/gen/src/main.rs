//! Fixture generator for the wasm-verify benchmarks + the settlement-binding
//! fixtures consumed by external verify-only environments.
//!
//! Usage (one shape per process, like measure_finish_line, so a large trace
//! never contends for RAM with another):
//!   vwb-gen <fixtures-dir> prove <log_size> <standard|mobile>
//!   vwb-gen <fixtures-dir> tamper            # derives tamper.bin from log12_standard.bin
//!   vwb-gen <fixtures-dir> binding <io_hash_hex>   # F3: see `binding_fixture`
//!
//! Each `prove` run writes `<fixtures-dir>/log{N}_{policy}.bin` — a
//! postcard-serialized `(Proof, CommitmentHash)` tuple — and appends a TSV
//! measurement line to `<fixtures-dir>/meta.tsv`:
//!   shape  policy  steps  trace_ms  prove_ms  proof_postcard_bytes
//!   fixture_bytes  native_verify_best_ms  native_verify_median_ms
//!   max_log  n_components  peak_rss_mib
//!
//! The trace shape uses the shared `zkpvm::bench_helpers::add_side_note` helper
//! (the established log-ladder: N sequential Add64s + Trap, 64 KiB memory) so
//! the numbers are comparable with the existing prove benchmarks.

use std::time::Instant;

use javm::instruction::Opcode;
use javm::interpreter::Interpreter;
use javm::PVM_REGISTER_COUNT;
use zkpvm::bench_helpers::add_side_note;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::{
    production_pcs_config, production_pcs_config_mobile, program_commitment_of_proof,
    prove_with_config, PcsPolicy, SideNote,
};
use zkpvm_verifier::{verify_standalone_with_pcs_policy, CommitmentHash, Proof};

/// Peak resident set of this process, in KiB (`VmHWM` from /proc).
fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:")?.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn prove_fixture(dir: &std::path::Path, log_size: u32, policy_name: &str) {
    let (config, policy) = match policy_name {
        "standard" => (production_pcs_config(), PcsPolicy::STANDARD),
        "mobile" => (production_pcs_config_mobile(), PcsPolicy::MOBILE),
        other => panic!("unknown policy {other} (use standard|mobile)"),
    };

    let t0 = Instant::now();
    let (mut side_note, steps) = add_side_note(log_size);
    let trace_ms = t0.elapsed().as_secs_f64() * 1e3;

    let t1 = Instant::now();
    let proof = prove_with_config(&mut side_note, config).expect("proving failed");
    let prove_ms = t1.elapsed().as_secs_f64() * 1e3;

    let commitment = program_commitment_of_proof(&proof);
    let proof_bytes = postcard::to_allocvec(&proof).expect("postcard proof").len();
    let fixture = postcard::to_allocvec(&(proof.clone(), commitment)).expect("postcard fixture");

    // Native cross-check on the EXACT code path the wasm build runs
    // (postcard decode of the fixture + verify_standalone_with_pcs_policy).
    let mut times = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        let (p, c): (Proof, CommitmentHash) =
            postcard::from_bytes(&fixture).expect("fixture decode");
        verify_standalone_with_pcs_policy(p, c, &policy).expect("native verify failed");
        times.push(t.elapsed().as_secs_f64() * 1e3);
    }
    let best = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let med = median(times);

    let max_log = proof.log_sizes.iter().copied().max().unwrap_or(0);
    let n_components = proof.log_sizes.len();
    let shape = format!("log{log_size:02}");
    let path = dir.join(format!("{shape}_{policy_name}.bin"));
    std::fs::write(&path, &fixture).expect("write fixture");

    let line = format!(
        "{shape}\t{policy_name}\t{steps}\t{trace_ms:.0}\t{prove_ms:.0}\t{proof_bytes}\t{}\t{best:.2}\t{med:.2}\t{max_log}\t{n_components}\t{:.0}\n",
        fixture.len(),
        peak_rss_kib() as f64 / 1024.0,
    );
    let meta = dir.join("meta.tsv");
    let mut existing = std::fs::read_to_string(&meta).unwrap_or_default();
    existing.push_str(&line);
    std::fs::write(&meta, existing).expect("write meta");
    eprintln!("wrote {} ({} bytes)\n{line}", path.display(), fixture.len());
}

/// Derive tamper.bin: flip one byte of log12_standard.bin such that postcard
/// STILL decodes (so the wasm export exercises real verification, not the
/// decode guard) but verification fails.
fn tamper(dir: &std::path::Path) {
    let src = dir.join("log12_standard.bin");
    let bytes = std::fs::read(&src).expect("log12_standard.bin missing — run prove 12 standard first");
    // Start in the middle of the buffer (deep in the STARK proof body) and
    // scan for an offset whose bit-flip survives decoding.
    let mut probe = bytes.len() / 2;
    loop {
        assert!(probe < bytes.len(), "no decodable tamper offset found");
        let mut t = bytes.clone();
        t[probe] ^= 0x01;
        if let Ok((p, c)) = postcard::from_bytes::<(Proof, CommitmentHash)>(&t) {
            let r = verify_standalone_with_pcs_policy(p, c, &PcsPolicy::STANDARD);
            if r.is_err() {
                std::fs::write(dir.join("tamper.bin"), &t).expect("write tamper");
                eprintln!(
                    "tamper.bin: flipped bit 0 of byte {probe}/{} — decodes, native verify rejects ({})",
                    bytes.len(),
                    r.unwrap_err()
                );
                return;
            }
            eprintln!("offset {probe}: decoded AND verified?! trying next offset");
        } else {
            eprintln!("offset {probe}: breaks postcard decode; trying next offset");
        }
        probe += 1;
    }
}

/// Settlement-binding fixture: a proof whose bound io-hash window holds a
/// caller-supplied hash.
///
/// Produces a REAL, STANDARD-policy zkpvm proof whose bound io-hash window
/// (`final_state.registers[9..13]`, read back by `Proof::public_io_hash`) holds a
/// caller-supplied 32-byte hash `H` — typically `H = vos::zk::compute_io_hash(
/// public_bytes, [])` computed with `cargo run -p vos --example
/// io_hash_vectors -- <public_bytes_hex>`.
///
/// The guest is hand-assembled (like the add-ladder bench guest): a 1019-step
/// Add64 ladder over φ0..φ8, then four `LoadImm64` placing H's little-endian
/// u64 words into φ9..φ12, then Trap. PROVENANCE NOTE: the guest LOADS the
/// precomputed hash as immediates rather than computing it from witness bytes
/// in-guest — a downstream verifier checks exactly the same property either
/// way (the proof's BOUND final registers equal the recomputed io-hash over the
/// asserted public inputs); the discipline that an attested production actor
/// derives H from its actual I/O is deployment/allowlist vocabulary, exercised
/// by the full vos prove pipeline, not by this fixture.
///
/// Outputs (postcard `Proof` ONLY — the on-chain `Submit.proof` wire; the
/// commitment travels separately, it is chain state):
///   settlement_zk_proof_valid.bin      the proof
///   settlement_zk_proof_tampered.bin   bit-flipped: still postcard-decodes, verify rejects
///   settlement_zk_commitment.bin       32 raw bytes: proof.stark_proof.commitments[0]
fn binding_fixture(dir: &std::path::Path, io_hash_hex: &str) {
    let hex = io_hash_hex.strip_prefix("0x").unwrap_or(io_hash_hex);
    assert_eq!(hex.len(), 64, "io-hash must be 32 bytes of hex");
    let mut h = [0u8; 32];
    for (i, byte) in h.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("valid hex");
    }

    // Add64 ladder over φ0..φ8 only (φ9..φ12 are the io-hash window).
    let mut code = Vec::new();
    let mut bitmask = Vec::new();
    let (mut ra, mut rb, mut rd): (u8, u8, u8) = (0, 1, 2);
    for _ in 0..1019 {
        code.push(Opcode::Add64 as u8);
        code.push(ra | (rb << 4));
        code.push(rd);
        bitmask.extend_from_slice(&[1, 0, 0]);
        ra = (ra + 1) % 9;
        rb = (rb + 1) % 9;
        rd = (rd + 1) % 9;
    }
    // Materialise each 64-bit hash word into φ9..φ12 through the 4-byte
    // sign-extended immediate scheme (LoadImm + shifts + Add64) — the exact
    // instruction shapes compiled actors emit, all constrained by the AIR.
    // (`LoadImm64`'s raw 8-byte immediate is NOT provable by the current
    // CpuChip immediate reconstruction — found empirically here — so the
    // words are assembled from two 32-bit halves instead:
    //   s = sext(hi) << 32; u = (sext(lo) << 32) >> 32; t = s + u
    // with disjoint halves, so the add is exact. Every instruction uses a
    // DISTINCT dest register (no in-place dest==source shapes).)
    const V: u8 = 6; // φ6..φ8 scratches — outside the io-hash window
    const U: u8 = 7;
    const S: u8 = 8;
    for (i, word) in h.chunks_exact(8).enumerate() {
        let t = 9 + i as u8; // φ9..φ12
        let w = u64::from_le_bytes(word.try_into().unwrap());
        let (hi, lo) = ((w >> 32) as u32, w as u32);
        // LoadImm u, hi — [51][reg][imm: 4 bytes LE], sign-extended by decode.
        code.push(Opcode::LoadImm as u8);
        code.push(U);
        code.extend_from_slice(&hi.to_le_bytes());
        bitmask.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
        // ShloLImm64 s ← u << 32 — [151][ra=dest | rb=src<<4][shift].
        code.push(Opcode::ShloLImm64 as u8);
        code.push(S | (U << 4));
        code.push(32);
        bitmask.extend_from_slice(&[1, 0, 0]);
        // LoadImm v, lo.
        code.push(Opcode::LoadImm as u8);
        code.push(V);
        code.extend_from_slice(&lo.to_le_bytes());
        bitmask.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
        // ShloLImm64 u ← v << 32; ShloRImm64 v ← u >> 32 (zero-extend lo).
        code.push(Opcode::ShloLImm64 as u8);
        code.push(U | (V << 4));
        code.push(32);
        bitmask.extend_from_slice(&[1, 0, 0]);
        code.push(Opcode::ShloRImm64 as u8);
        code.push(V | (U << 4));
        code.push(32);
        bitmask.extend_from_slice(&[1, 0, 0]);
        // Add64 t ← s + v — [Add64][ra=s | rb=v<<4][rd=t].
        code.push(Opcode::Add64 as u8);
        code.push(S | (V << 4));
        code.push(t);
        bitmask.extend_from_slice(&[1, 0, 0]);
    }
    code.push(Opcode::Trap as u8);
    bitmask.push(1);

    let mut regs = [0u64; PVM_REGISTER_COUNT];
    for (i, r) in regs.iter_mut().enumerate().take(13) {
        *r = (i as u64) + 1;
    }
    let pvm = Interpreter::new(
        code.clone(),
        bitmask.clone(),
        vec![],
        regs,
        vec![0u8; 64 * 1024],
        1_000_000,
        16,
    );
    let mut tracing = TracingPvm::new(pvm);
    let _exit = tracing.run();
    let steps = tracing.into_trace();
    let mut side_note = SideNote::new(steps, code, bitmask);

    if std::env::var("VWB_DUMP_STEPS").is_ok() {
        for s in &side_note.steps {
            eprintln!(
                "ts={} pc={} {:?} ra={} rb={} rd={} imm={:#x} write={:?}",
                s.timestamp, s.pc, s.opcode, s.reg_a, s.reg_b, s.reg_d, s.imm, s.reg_write,
            );
        }
        for (row, e) in zkpvm::chips::register_memory::build_entries_from_side_note(&side_note)
            .iter()
            .enumerate()
        {
            eprintln!(
                "ledger row {row}: reg={} ts={} {} value={:#x}",
                e.reg_addr,
                e.timestamp,
                if e.is_write { "W" } else { "R" },
                e.value,
            );
        }
    }

    // With `--features debug-internals`, pinpoint the failing chip/row/constraint
    // before proving. IMPORTANT: replicate `prove`'s side-note preparation
    // (closing-chip activation + initial/final register backfill) — without it
    // the debug pass asserts against all-zero boundary registers and reports
    // phantom read-consistency failures.
    #[cfg(feature = "debug-internals")]
    {
        side_note.closing_chip_active = true;
        if let (Some(first), Some(last)) = (side_note.steps.first(), side_note.steps.last()) {
            side_note.initial_regs = first.regs_before;
            side_note.final_regs = last.regs_after;
        }
        let components = zkpvm::active_components(&side_note);
        zkpvm::debug_assert_constraints_explicit(&mut side_note, &components);
        eprintln!("debug-internals: all constraints satisfied");
        if std::env::var("VWB_DEBUG_ONLY").is_ok() {
            return;
        }
    }

    let t = Instant::now();
    let proof =
        prove_with_config(&mut side_note, production_pcs_config()).expect("proving failed");
    eprintln!("prove: {:.1}s", t.elapsed().as_secs_f64());

    // The proof's bound io-hash window must reconstruct exactly H.
    assert_eq!(proof.public_io_hash(), h, "φ9..φ12 do not reconstruct the requested io-hash");

    let commitment = program_commitment_of_proof(&proof);
    let proof_bytes = postcard::to_allocvec(&proof).expect("postcard proof");

    // Native cross-check on the exact on-chain verification path: postcard
    // decode of the PROOF ALONE + strict STANDARD PcsPolicy + a commitment
    // supplied out-of-band (on a chain it is state, never proof-carried).
    let decoded: Proof = postcard::from_bytes(&proof_bytes).expect("proof decode");
    verify_standalone_with_pcs_policy(decoded, commitment, &PcsPolicy::STANDARD)
        .expect("native verify failed");

    // Tampered variant: flip one bit deep in the STARK body such that postcard
    // still decodes but verification rejects (same scan as `tamper`).
    let mut probe = proof_bytes.len() / 2;
    let tampered = loop {
        assert!(probe < proof_bytes.len(), "no decodable tamper offset found");
        let mut t = proof_bytes.clone();
        t[probe] ^= 0x01;
        if let Ok(p) = postcard::from_bytes::<Proof>(&t) {
            if verify_standalone_with_pcs_policy(p, commitment, &PcsPolicy::STANDARD).is_err() {
                eprintln!("tamper: flipped bit 0 of byte {probe}/{}", proof_bytes.len());
                break t;
            }
        }
        probe += 1;
    };

    let commitment_bytes: [u8; 32] = commitment.into();
    std::fs::write(dir.join("settlement_zk_proof_valid.bin"), &proof_bytes).expect("write proof");
    std::fs::write(dir.join("settlement_zk_proof_tampered.bin"), &tampered).expect("write tamper");
    std::fs::write(dir.join("settlement_zk_commitment.bin"), commitment_bytes)
        .expect("write commitment");
    eprintln!(
        "settlement_zk_proof_valid.bin: {} bytes\ncommitment: {}",
        proof_bytes.len(),
        commitment_bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dir = std::path::PathBuf::from(args.first().expect("first arg: fixtures dir"));
    std::fs::create_dir_all(&dir).expect("create fixtures dir");
    match args.get(1).map(String::as_str) {
        Some("prove") => {
            let log: u32 = args[2].parse().expect("log size");
            prove_fixture(&dir, log, &args[3]);
        }
        Some("tamper") => tamper(&dir),
        Some("binding") => binding_fixture(&dir, args.get(2).expect("io-hash hex")),
        _ => eprintln!(
            "usage: vwb-gen <fixtures-dir> prove <log> <standard|mobile> | tamper | binding <io_hash_hex>"
        ),
    }
}
