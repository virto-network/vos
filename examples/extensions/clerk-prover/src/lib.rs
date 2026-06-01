//! ClerkProverExtension — host-side prover + verifier for cipher-clerk
//! Mode::External voucher proofs.
//!
//! ## Why a host extension
//!
//! zkpvm-verifier can't build for `riscv64em-javm` today (blocked by
//! `javm → grey-crypto → blst`'s C-build pipeline + workspace `stwo`
//! feature inheritance; see task #1 spike). Until those upstream
//! blockers are resolved, in-PVM-actor verification isn't viable, so
//! the verifier runs natively here and clerk-bridge dispatches into
//! it via the typed Ref API.
//!
//! ## Message handlers
//!
//! - `prove_voucher() -> Vec<u8>` — loads `voucher-check.elf`, traces
//!   it through the PVM interpreter, calls `zkpvm::prove`,
//!   bincode-serializes the resulting `zkpvm::Proof`. v0: hardcoded
//!   witness (matches the actor's `start` handler). v1 (gated on
//!   cipher-clerk rkyv-deriving `Public`/`Secret`): takes the witness
//!   bytes, writes them into a deterministic flat-mem layout, traces
//!   with those inputs.
//!
//! - `verify_voucher_proof(public_bytes, proof_hash) -> u8` —
//!   `proof_hash` is the 32-byte content address of the proof bytes
//!   in the host's proof-blob store. The extension does
//!   `ctx.blob_get(hash)` to retrieve the bytes (~1.4 MiB STARK
//!   today), bincode-deserializes, then runs
//!   `verify_standalone_with_pcs_policy` against the baked program
//!   commitment. Returning bytes inline through the PVM bridge isn't
//!   viable — the bridge's 4 KiB input buffer + 64 KiB heap cap that
//!   path at ~few-KB voucher payloads, so the bridge ships only the
//!   hash and the extension does the heavy I/O host-side.
//!
//! - `program_commitment() -> Vec<u8>` — returns the 32-byte
//!   program-commitment hash a verifier needs. Read once at startup
//!   by running the prover on the hardcoded witness; cached after.
//!
//! ## v0 cryptographic path
//!
//! `prove_voucher` ignores `public_bytes` and proves the actor's
//! hardcoded (Public, Secret) witness.  The proof is cryptographically
//! sound — a valid STARK over voucher-check.elf's execution trace —
//! but does NOT yet bind to the caller's `public_bytes`.  A v1 swap to
//! patch the witness from `public_bytes`/`secret_bytes` is gated on
//! the rkyv-derives for `Public`/`Secret` (already in cipher-clerk
//! commit `856a6f7`); see the `trace_with_witness` handler for the
//! wiring template.
//!
//! Returns `1` on accept, `0` on reject for `verify_voucher_proof`.

use std::path::PathBuf;
use std::sync::OnceLock;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use cipher_clerk::voucher::proof::{self as voucher_proof, Public};
use javm::PVM_REGISTER_COUNT;
use javm::interpreter::Interpreter;
use javm::program::{self, CapEntryType};
use object::{Object, ObjectSymbol};
use vos::prelude::*;
use zkpvm::SideNote;
use zkpvm::core::tracing::TracingPvm;
use zkpvm::{Proof, program_commitment_of_proof, prove_mobile};
use zkpvm_verifier::{PcsPolicy, verify_standalone_with_pcs_policy};

#[actor]
struct ClerkProver;

#[messages]
impl ClerkProver {
    fn new() -> Self {
        ClerkProver
    }

    /// Produce a Mode::External proof for cipher-clerk's voucher
    /// transition. v0: hardcoded witness (matches voucher-check actor's
    /// `start` handler). Returns bincode-serialized `zkpvm::Proof`
    /// bytes ready to drop into `cipher_clerk::proof::Proof.bytes`.
    ///
    /// v0: ignores `public_bytes` and proves the actor's hardcoded
    /// witness.  Cached on first call.
    #[msg]
    async fn prove_voucher(&self, _ctx: &mut Context<Self>, public_bytes: Vec<u8>) -> Vec<u8> {
        let _ = public_bytes; // v0 ignores; v1 will patch WITNESS_BUFFER from it.
        match cached_proof_bytes() {
            Some(b) => b.clone(),
            None => Vec::new(),
        }
    }

    /// Verify a Mode::External voucher proof against the cached
    /// program commitment. `proof_hash` is the 32-byte content
    /// address of the actual proof bytes in the host's proof-blob
    /// store; the extension fetches them via `ctx.blob_get` so the
    /// bridge dispatch never has to ferry multi-MB bytes through
    /// the PVM input ABI.
    ///
    /// `peer_prefix` is an optional `node_prefix` hint: when
    /// non-zero, the host tries that specific peer first before
    /// falling back to fan-out. The bridge knows which peer
    /// issued the voucher and threads it through here so a
    /// 100-peer space doesn't pay 100 roundtrips per voucher.
    ///
    /// `public_bytes` is currently unused — v0 proofs are bound to
    /// the actor's hardcoded witness, not the caller's public.
    /// Returns `1` on accept, `0` on reject (including the
    /// "proof bytes not in the local CAS / cross-node fetch failed"
    /// case — which is indistinguishable from "the bytes were
    /// tampered with" from a security standpoint).
    #[msg]
    async fn verify_voucher_proof(
        &self,
        ctx: &mut Context<Self>,
        public_bytes: Vec<u8>,
        proof_hash: Vec<u8>,
        peer_prefix: u32,
    ) -> u8 {
        let _ = public_bytes;
        if proof_hash.len() != 32 {
            return 0;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&proof_hash);
        let hint: u16 = (peer_prefix & 0xFFFF) as u16;
        let Some(proof_bytes) = ctx.blob_get(hash, hint).await else {
            return 0;
        };
        let Ok(proof) = bincode::deserialize::<Proof>(&proof_bytes) else {
            return 0;
        };
        let Some(program_commitment) = cached_program_commitment() else {
            return 0;
        };
        match verify_standalone_with_pcs_policy(proof, program_commitment, &PcsPolicy::MOBILE) {
            Ok(()) => 1,
            Err(_) => 0,
        }
    }

    /// Return the 32-byte program-commitment hash the verifier
    /// checks proofs against.  Computed once at first call by running
    /// `prove` over the hardcoded witness, then cached.  Empty if the
    /// underlying prove fails (e.g. ELF missing).
    #[msg]
    async fn program_commitment(&self, _ctx: &mut Context<Self>) -> Vec<u8> {
        match cached_program_commitment() {
            Some(c) => c.0.to_vec(),
            None => Vec::new(),
        }
    }

    /// Diagnostic — does the voucher-check ELF load + trace cleanly?
    /// Returns the step count, or 0 if the ELF can't be loaded.
    /// Useful for the federation test to assert the underlying PVM
    /// path is wired before running the prove/verify dance.
    #[msg]
    async fn trace_step_count(&self, _ctx: &mut Context<Self>) -> u32 {
        match load_and_trace_voucher_check(None) {
            Some((steps, _)) => steps as u32,
            None => 0,
        }
    }

    /// Trace voucher-check with a dynamic witness patched into the
    /// actor's `WITNESS_BUFFER` BSS region. Returns the 32-byte
    /// blake2b-256 of the post-trace flat_mem — the same digest the
    /// future prove path would commit to via
    /// `proof.initial_state.memory_commitment`. Different (public,
    /// secret) inputs → different return.
    ///
    /// `0` on any failure path (ELF missing, WITNESS_BUFFER symbol
    /// not found, witness too large for the static buffer, trace
    /// panicked).
    ///
    /// Demonstrates the dynamic-witness wiring end-to-end without
    /// requiring the actual STARK prove path (which is blocked on
    /// task #7). When the prove path lands, swap `flat_mem_digest`
    /// for `bincode::serialize(&zkpvm::prove(&mut side_note))`.
    #[msg]
    async fn trace_with_witness(
        &self,
        _ctx: &mut Context<Self>,
        public_bytes: Vec<u8>,
        secret_bytes: Vec<u8>,
    ) -> Vec<u8> {
        let witness = encode_witness_buffer(&public_bytes, &secret_bytes);
        let Some(witness) = witness else {
            return Vec::new();
        };
        match load_and_trace_voucher_check(Some(witness)) {
            Some((_steps, flat_mem_digest)) => flat_mem_digest.to_vec(),
            None => Vec::new(),
        }
    }
}

/// One-shot prove on the actor's hardcoded witness.  Cached so
/// repeated `prove_voucher` / `program_commitment` calls within a
/// process don't re-trace + re-prove (~9 s release).  Returns `None`
/// if the ELF isn't built — extension callers see an empty Vec.
fn cached_proof() -> Option<&'static Proof> {
    static CACHE: OnceLock<Option<Proof>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let path = voucher_check_elf_path();
            let elf = std::fs::read(&path).ok()?;
            let blob = grey_transpiler::link_elf(&elf).ok()?;
            let mut side_note = side_note_for_blob(&blob)?;
            prove_mobile(&mut side_note).ok()
        })
        .as_ref()
}

fn cached_proof_bytes() -> Option<&'static Vec<u8>> {
    static CACHE: OnceLock<Option<Vec<u8>>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let proof = cached_proof()?;
            bincode::serialize(proof).ok()
        })
        .as_ref()
}

fn cached_program_commitment() -> Option<zkpvm_verifier::CommitmentHash> {
    cached_proof().map(program_commitment_of_proof)
}

/// Build a fully-populated SideNote for voucher-check.elf with the
/// hardcoded witness (the actor falls back to it when WITNESS_BUFFER
/// is zero).  Mirrors `zkpvm/tests/voucher_check_smoke.rs`'s
/// `side_note_for_trace`.
fn side_note_for_blob(blob: &[u8]) -> Option<SideNote> {
    let (interp, flat_mem) = interpreter_from_blob(blob, 100_000_000)?;
    let parsed = program::parse_blob(blob)?;
    let mut code_data = None;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Code {
            code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
            break;
        }
    }
    let code_blob = program::parse_code_blob(&code_data?)?;
    let mut tracing = TracingPvm::new(interp);
    let _ = tracing.run_with_vos_stubs();
    let blake2b_calls: Vec<_> = tracing.blake2b_calls().to_vec();
    let blake2b_mem_ops = tracing.blake2b_mem_ops.clone();
    let ristretto_calls: Vec<_> = tracing.ristretto_calls().to_vec();
    let ristretto_mem_ops = tracing.ristretto_mem_ops.clone();
    let ristretto_add_records = tracing.ristretto_add_records.clone();
    let ristretto_add_mem_ops = tracing.ristretto_add_mem_ops.clone();
    let scalar_reduce_records = tracing.scalar_reduce_wide_records.clone();
    let scalar_reduce_mem_ops = tracing.scalar_reduce_wide_mem_ops.clone();
    let scalar_binop_records = tracing.scalar_binop_records.clone();
    let scalar_binop_mem_ops = tracing.scalar_binop_mem_ops.clone();
    let steps = tracing.into_trace();
    let mut side_note = SideNote::new(steps, code_blob.code.to_vec(), code_blob.bitmask.to_vec())
        .with_memory(flat_mem)
        .with_jump_table(code_blob.jump_table.to_vec());
    for c in &blake2b_calls {
        side_note
            .blake2b_calls
            .push(zkpvm::chips::blake2b::Blake2bCall {
                h: c.h,
                m: c.m,
                t: c.t,
                f: c.f,
            });
    }
    side_note.blake2b_mem_ops = blake2b_mem_ops;
    side_note.ristretto_calls = ristretto_calls;
    side_note.ristretto_mem_ops = ristretto_mem_ops;
    side_note.ristretto_add_calls = ristretto_add_records;
    side_note.ristretto_add_mem_ops = ristretto_add_mem_ops;
    side_note.scalar_reduce_wide_calls = scalar_reduce_records;
    side_note.scalar_reduce_wide_mem_ops = scalar_reduce_mem_ops;
    side_note.scalar_binop_calls = scalar_binop_records;
    side_note.scalar_binop_mem_ops = scalar_binop_mem_ops;
    side_note.ingest_ristretto_boundary();
    Some(side_note)
}

/// Resolve the voucher-check.elf path relative to this extension's
/// build location. Honors the `VOUCHER_CHECK_ELF` environment
/// variable for tests that point to a non-canonical location.
fn voucher_check_elf_path() -> PathBuf {
    if let Ok(p) = std::env::var("VOUCHER_CHECK_ELF") {
        return PathBuf::from(p);
    }
    // CARGO_MANIFEST_DIR is `<repo>/examples/extensions/clerk-prover`;
    // go up two levels to `<repo>/examples`, then `actors/voucher-
    // check/target/...`.
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest)
        .join("..")
        .join("..")
        .join("actors")
        .join("voucher-check")
        .join("target")
        .join("riscv64em-javm")
        .join("release")
        .join("voucher-check.elf")
}

/// Load voucher-check.elf, transpile, optionally patch WITNESS_BUFFER
/// with `witness_bytes`, trace, and return the step count plus the
/// blake2b-256 of the post-trace flat_mem.
///
/// `witness_bytes`: if `Some`, written to flat_mem at the address of
/// WITNESS_BUFFER (looked up from the ELF symbol table). If `None`,
/// the actor's `start` handler reads zeros and falls back to its
/// hardcoded witness.
fn load_and_trace_voucher_check(witness_bytes: Option<Vec<u8>>) -> Option<(usize, [u8; 32])> {
    let path = voucher_check_elf_path();
    let elf = std::fs::read(&path).ok()?;
    let witness_addr = witness_bytes
        .as_ref()
        .and_then(|_| find_symbol_addr(&elf, "WITNESS_BUFFER"));
    let blob = grey_transpiler::link_elf(&elf).ok()?;
    let (interp, mut flat_mem) = interpreter_from_blob(&blob, 100_000_000)?;
    // Patch the witness BEFORE TracingPvm takes ownership.
    if let (Some(bytes), Some(addr)) = (&witness_bytes, witness_addr) {
        let addr = addr as usize;
        let end = addr.checked_add(bytes.len())?;
        if end > flat_mem.len() {
            return None;
        }
        flat_mem[addr..end].copy_from_slice(bytes);
    }
    let mut interp = interp;
    interp.flat_mem = flat_mem.clone();
    let mut tracing = TracingPvm::new(interp);
    let _ = tracing.run_with_vos_stubs();
    let step_count = tracing.steps.len();
    // Snapshot the final flat_mem post-trace and compute its
    // blake2b-256 digest. Mirrors what
    // `proof.initial_state.memory_commitment` carries today (blake2b
    // of the initial flat_mem), but on post-trace mem so the digest
    // also covers the witness side effects.
    let final_mem = tracing.pvm.flat_mem.clone();
    let mut h = Blake2bVar::new(32).ok()?;
    h.update(&final_mem);
    let mut digest = [0u8; 32];
    h.finalize_variable(&mut digest).ok()?;
    Some((step_count, digest))
}

/// Find the address of an exported symbol in an ELF binary. Returns
/// `None` if the file isn't an ELF, the symbol doesn't exist, or
/// the symbol address is 0 (unresolved).
fn find_symbol_addr(elf: &[u8], name: &str) -> Option<u64> {
    let obj = object::File::parse(elf).ok()?;
    for sym in obj.symbols() {
        if sym.name().ok() == Some(name) {
            let addr = sym.address();
            if addr != 0 {
                return Some(addr);
            }
        }
    }
    None
}

/// Encode (public_bytes, secret_bytes) into the static-buffer layout
/// the actor reads:
///   bytes  0..4    public_bytes length (`u32` LE)
///   bytes  4..N    public_bytes
///   bytes  N..N+4  secret_bytes length (`u32` LE)
///   bytes  N+4..M  secret_bytes
///
/// Returns `None` if the combined size would exceed the actor's
/// 1024-byte WITNESS_BUFFER.
fn encode_witness_buffer(public_bytes: &[u8], secret_bytes: &[u8]) -> Option<Vec<u8>> {
    let needed = 4 + public_bytes.len() + 4 + secret_bytes.len();
    if needed > 1024 {
        return None;
    }
    let mut v = Vec::with_capacity(needed);
    v.extend_from_slice(&(public_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(public_bytes);
    v.extend_from_slice(&(secret_bytes.len() as u32).to_le_bytes());
    v.extend_from_slice(secret_bytes);
    Some(v)
}

/// Build an `Interpreter` from a parsed PVM blob's CODE + DATA caps.
/// Cribbed from `zkpvm/tests/voucher_check_smoke.rs` — same shape
/// because the prove path here will eventually call this then
/// `zkpvm::prove`.
fn interpreter_from_blob(blob: &[u8], gas: u64) -> Option<(Interpreter, Vec<u8>)> {
    let parsed = program::parse_blob(blob)?;
    let mut code_data = None;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Code {
            code_data = Some(program::cap_data(entry, parsed.data_section).to_vec());
            break;
        }
    }
    let code_data = code_data?;
    let code_blob = program::parse_code_blob(&code_data)?;
    let mut flat_mem_size: usize = 0;
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let end = (entry.base_page as usize + entry.page_count as usize)
                * javm::PVM_PAGE_SIZE as usize;
            flat_mem_size = flat_mem_size.max(end);
        }
    }
    let mut flat_mem = vec![0u8; flat_mem_size];
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let addr = entry.base_page as usize * javm::PVM_PAGE_SIZE as usize;
            let data = program::cap_data(entry, parsed.data_section);
            let len = data.len().min(flat_mem.len().saturating_sub(addr));
            if len > 0 {
                flat_mem[addr..addr + len].copy_from_slice(&data[..len]);
            }
        }
    }
    let mut registers = [0u64; PVM_REGISTER_COUNT];
    for entry in &parsed.caps {
        if entry.cap_type == CapEntryType::Data {
            let top =
                (entry.base_page as u64 + entry.page_count as u64) * javm::PVM_PAGE_SIZE as u64;
            if top > registers[1] {
                registers[1] = top;
            }
        }
    }
    let mem_cycles = javm::compute_mem_cycles(parsed.header.memory_pages);
    let flat_mem_copy = flat_mem.clone();
    let interp = Interpreter::new(
        code_blob.code.to_vec(),
        code_blob.bitmask.to_vec(),
        code_blob.jump_table.to_vec(),
        registers,
        flat_mem,
        gas,
        mem_cycles,
    );
    Some((interp, flat_mem_copy))
}

// `Public` / `voucher_proof::public_bytes` aren't used yet — they
// become live once `prove_voucher` patches WITNESS_BUFFER from
// caller-supplied `public_bytes` (v1).  Keep the imports referenced.
#[allow(dead_code)]
fn _keep_imports_for_v1() {
    let _ = voucher_proof::public_bytes(&Public {
        issuer: cipher_clerk::crypto::AuthKey([0u8; 32]),
        amount_commit: cipher_clerk::crypto::Amount::ZERO,
        state_root_before: [0u8; 32],
        state_root_after: [0u8; 32],
    });
}
