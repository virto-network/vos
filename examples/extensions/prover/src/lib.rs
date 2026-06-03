//! ProverExtension — general-purpose, program-agnostic host-side zkpvm
//! prover + verifier.
//!
//! ## What it does
//!
//! Three message handlers, keyed by an opaque `program_id`:
//!
//! - `prove(program_id, witness_bytes) -> Vec<u8>` — resolve `program_id`
//!   to an actor ELF, patch the caller's OPAQUE `witness_bytes` into the
//!   actor's `__VOS_WITNESS` buffer (located by ELF symbol name — see
//!   `vos::zk::witness_buffer!`), trace, `prove_mobile`, and return the
//!   bincode-serialized `zkpvm::Proof`. The prover never interprets the
//!   witness — the actor owns its own layout — so this stays
//!   program-agnostic. The reply is the proof *bytes*; the caller content-
//!   addresses them into the host proof-blob store (`put_proof_blob`) and
//!   ships the 32-byte hash, because there is no extension-side CAS *put*
//!   (only `ctx.blob_get`).
//!
//! - `verify(program_commitment, proof_hash, public_bytes, return_bytes,
//!   peer_prefix) -> u8` — fetch the proof from the host CAS by
//!   `proof_hash` (`ctx.blob_get`, with `peer_prefix` as a fan-out hint),
//!   then return `1` iff BOTH hold:
//!     1. `verify_standalone(proof, program_commitment)` — the proof is a
//!        valid STARK of the program the caller trusts (WHICH PROGRAM).
//!     2. `proof.public_io_hash() == vos::zk::compute_io_hash(public,
//!        return)` — the tagless io-binding (WHICH I/O).
//!
//!   Composing the two means the io-binding can never be checked without
//!   validity, and program identity rests entirely on the caller-supplied
//!   commitment (the tagless design — no actor/message tag in the hash).
//!
//! - `program_commitment(program_id) -> Vec<u8>` — the 32-byte trusted
//!   program commitment a verifier checks against. This is PROVENANCE, not
//!   something the prover recomputes: it pins a specific program build's
//!   cryptographic identity (the preprocessed-trace Merkle root). v1 bakes
//!   it; the general path reads it from the catalog (published at
//!   publish-time by running a representative proof).
//!
//! ## Program resolution (v1)
//!
//! `program_id` is opaque bytes; v1 bakes the single known program:
//! `b"voucher-check" -> (ELF path, trusted commitment)`. The general path
//! resolves both via the space-registry catalog / CAS (program name ->
//! commitment + blob); the ABI doesn't change when it lands.
//!
//! ## Why the commitment must be pinned, not computed witness-free
//!
//! A proof's commitment depends on its execution shape (`log_sizes`). A
//! provable actor takes its witness through `__VOS_WITNESS` (an rkyv-decode
//! path); when that buffer is empty the actor runs a DIFFERENT fallback
//! path (e.g. a hardcoded witness) with a different shape — and therefore a
//! different commitment. So the trusted commitment must come from a
//! representative REAL (witness-injected) run, established once at
//! publish-time and pinned here — never recomputed from an empty witness.
//! (Across different witness *values* on the injected path the commitment
//! is stable, so one pinned commitment verifies every real proof; the
//! `prove_verify` e2e test pins both facts.)

use std::path::PathBuf;

use object::{Object, ObjectSymbol};
use vos::prelude::*;
use zkpvm::{Proof, program_commitment_of_proof, prove_mobile};
use zkpvm_verifier::{CommitmentHash, PcsPolicy, verify_standalone_with_pcs_policy};

/// Gas bound for tracing a provable actor. Generous — the voucher-check
/// workload traces in well under this; an actor that exceeds it traces to
/// `OutOfGas` and the prove fails (empty reply).
const TRACE_GAS: u64 = 100_000_000;

#[actor]
struct Prover;

#[messages]
impl Prover {
    fn new() -> Self {
        Prover
    }

    /// Prove `program_id` over the caller-supplied opaque `witness_bytes`.
    /// Returns bincode-serialized `zkpvm::Proof` bytes, or an empty `Vec`
    /// on any failure (unknown program / ELF missing / prove failed). The
    /// caller CASes the bytes via the host proof-blob store.
    #[msg]
    async fn prove(
        &self,
        _ctx: &mut Context<Self>,
        program_id: Vec<u8>,
        witness_bytes: Vec<u8>,
    ) -> Vec<u8> {
        prove_program(&program_id, &witness_bytes).unwrap_or_default()
    }

    /// Verify a proof fetched from the host CAS by `proof_hash`, composing
    /// STARK validity against `program_commitment` with the tagless
    /// io-binding (`public_bytes`, `return_bytes`). `peer_prefix` is an
    /// optional `node_prefix` fan-out hint for the blob fetch. Returns `1`
    /// on accept, `0` on reject (including "proof bytes unavailable",
    /// which is indistinguishable from tampering for security purposes).
    #[msg]
    async fn verify(
        &self,
        ctx: &mut Context<Self>,
        program_commitment: Vec<u8>,
        proof_hash: Vec<u8>,
        public_bytes: Vec<u8>,
        return_bytes: Vec<u8>,
        peer_prefix: u32,
    ) -> u8 {
        if proof_hash.len() != 32 {
            return 0;
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&proof_hash);
        let hint: u16 = (peer_prefix & 0xFFFF) as u16;
        let Some(proof_bytes) = ctx.blob_get(hash, hint).await else {
            return 0;
        };
        verify_proof_bytes(
            &program_commitment,
            &proof_bytes,
            &public_bytes,
            &return_bytes,
        ) as u8
    }

    /// Return the 32-byte trusted program commitment for `program_id` (the
    /// verifier's identity anchor). Empty `Vec` if the program can't be
    /// resolved or proved.
    #[msg]
    async fn program_commitment(&self, _ctx: &mut Context<Self>, program_id: Vec<u8>) -> Vec<u8> {
        match program_commitment_bytes(&program_id) {
            Some(c) => c.to_vec(),
            None => Vec::new(),
        }
    }
}

// ── Core logic (Context-free, unit-testable) ─────────────────────────

/// Prove `program_id` over `witness_bytes` and return the bincode-encoded
/// proof bytes. `None` on any failure.
pub fn prove_program(program_id: &[u8], witness_bytes: &[u8]) -> Option<Vec<u8>> {
    let proof = prove_to_proof(program_id, witness_bytes)?;
    bincode::serialize(&proof).ok()
}

/// Diagnostic: prove and return `(proof_bytes, proof's own program
/// commitment, proof's public_io_hash)`. Lets a caller/test compare a
/// witness-injected proof's commitment against a canonical one and inspect
/// the bound io-hash without re-deserializing.
pub fn prove_with_details(
    program_id: &[u8],
    witness_bytes: &[u8],
) -> Option<(Vec<u8>, [u8; 32], [u8; 32])> {
    let proof = prove_to_proof(program_id, witness_bytes)?;
    let commitment = program_commitment_of_proof(&proof).0;
    let io_hash = proof.public_io_hash();
    let bytes = bincode::serialize(&proof).ok()?;
    Some((bytes, commitment, io_hash))
}

/// Resolve `program_id` to an ELF, inject the opaque `witness_bytes` into
/// its `__VOS_WITNESS` buffer (empty = no injection; the actor uses its
/// own default), trace, and prove. `None` on any failure.
fn prove_to_proof(program_id: &[u8], witness_bytes: &[u8]) -> Option<Proof> {
    let path = program_id_to_elf_path(program_id)?;
    let elf = std::fs::read(&path).ok()?;
    let blob = grey_transpiler::link_elf(&elf).ok()?;
    let mut side_note = if witness_bytes.is_empty() {
        zkpvm::actor::trace_blob(&blob, TRACE_GAS)?
    } else {
        let addr = find_symbol_addr(&elf, "__VOS_WITNESS")? as usize;
        zkpvm::actor::trace_blob_with_patches(&blob, TRACE_GAS, &[(addr, witness_bytes)])?
    };
    prove_mobile(&mut side_note).ok()
}

/// Verify proof bytes against a trusted 32-byte `commitment_bytes` and the
/// asserted `(public_bytes, return_bytes)`. Composes the two checks so the
/// io-binding can't be validated without STARK validity:
///   1. `verify_standalone(proof, commitment)` — which program.
///   2. `proof.public_io_hash() == compute_io_hash(public, return)` —
///      which I/O (tagless).
///
/// Returns `false` on any malformed input, decode failure, or rejection.
pub fn verify_proof_bytes(
    commitment_bytes: &[u8],
    proof_bytes: &[u8],
    public_bytes: &[u8],
    return_bytes: &[u8],
) -> bool {
    // `CommitmentHash::from(&[u8])` panics on a non-32-byte slice — guard.
    if commitment_bytes.len() != 32 {
        return false;
    }
    let Ok(proof) = bincode::deserialize::<Proof>(proof_bytes) else {
        return false;
    };
    let commitment = CommitmentHash::from(commitment_bytes);
    // 1. STARK validity against the program the caller trusts. `prove_mobile`
    //    proofs verify only under the MOBILE policy — keep them paired.
    if verify_standalone_with_pcs_policy(proof.clone(), commitment, &PcsPolicy::MOBILE).is_err() {
        return false;
    }
    // 2. Tagless io-binding: the proof's STARK-bound public output must
    //    equal the hash recomputed over the asserted I/O bytes.
    proof.public_io_hash() == vos::zk::compute_io_hash(public_bytes, return_bytes)
}

/// The 32-byte trusted program commitment for `program_id` — the program
/// build's pinned cryptographic identity (preprocessed-trace Merkle root
/// of a representative real run). `None` for an unknown program.
///
/// v1 bakes the value (see [`baked_commitment`]); the general path reads
/// it from the catalog. It is deliberately NOT recomputed here from an
/// empty witness — that would take the actor's fallback path and bind a
/// different shape (see the module docs). A rebuilt or tampered ELF whose
/// commitment differs from the pinned value is correctly rejected by
/// `verify_standalone`; the `prove_verify` test guards against accidental
/// drift after an intentional ELF change.
pub fn program_commitment_bytes(program_id: &[u8]) -> Option<[u8; 32]> {
    baked_commitment(program_id)
}

/// v1 baked `program_id -> trusted commitment` map. The commitment is the
/// preprocessed-trace Merkle root of a representative witness-injected
/// proof of the program; stable across witness values, so it verifies
/// every real proof of that build.
fn baked_commitment(program_id: &[u8]) -> Option<[u8; 32]> {
    match program_id {
        b"voucher-check" => Some(VOUCHER_CHECK_COMMITMENT),
        _ => None,
    }
}

/// Pinned program commitment for the v1 `voucher-check` build (the
/// preprocessed-trace Merkle root of any witness-injected proof). Re-pin
/// via the `prove_verify` drift-guard if voucher-check.elf is rebuilt with
/// a shape-changing source/toolchain change.
const VOUCHER_CHECK_COMMITMENT: [u8; 32] = [
    0xdc, 0x5c, 0xe5, 0x75, 0x76, 0x2e, 0x59, 0x05, 0x49, 0xd6, 0x45, 0x6a, 0xe1, 0x65, 0x92, 0xa9,
    0xda, 0x0c, 0xad, 0x2f, 0xd7, 0x06, 0x03, 0x39, 0x12, 0xa9, 0x12, 0x64, 0x3d, 0x4a, 0x39, 0x85,
];

/// Resolve an opaque `program_id` to an actor ELF path.
///
/// v1 bakes the single known program. The general path resolves via the
/// space-registry catalog (program name -> blob hash -> bytes); that lands
/// in a later commit without changing this signature.
fn program_id_to_elf_path(program_id: &[u8]) -> Option<PathBuf> {
    match program_id {
        b"voucher-check" => Some(voucher_check_elf_path()),
        _ => None,
    }
}

/// Resolve the voucher-check.elf path. Honors `VOUCHER_CHECK_ELF` for
/// tests that point at a non-canonical location, else a build-relative
/// path (CARGO_MANIFEST_DIR = `<repo>/examples/extensions/prover`).
fn voucher_check_elf_path() -> PathBuf {
    if let Ok(p) = std::env::var("VOUCHER_CHECK_ELF") {
        return PathBuf::from(p);
    }
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

/// Find the address of an exported symbol in an ELF binary. `None` if the
/// file isn't an ELF, the symbol is absent, or its address is 0
/// (unresolved).
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
