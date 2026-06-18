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
use zkpvm::{Proof, program_commitment_of_proof, prove_canonical, prove_mobile};
use zkpvm_verifier::{
    CommitmentHash, DEFAULT_MAX_LOG_SIZE, PcsPolicy, verify_chain_standalone_allowlist,
    verify_standalone_with_pcs_policy,
};

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

    /// Prove `program_id` over `witness_bytes` as a canonical-shape SEGMENT
    /// CHAIN — the federation path for traces too large for a single proof
    /// (the conservation transition is millions of steps). Segments at a
    /// fixed step bound, proves each with canonical-shape proving against the
    /// program's pinned profile, and returns `bincode(Vec<Vec<u8>>)` — the
    /// per-segment `bincode(Proof)` bytes (one entry per segment, in chain
    /// order). Empty `Vec` on any failure.
    ///
    /// The caller content-addresses each segment SEPARATELY (`put_proof_blob`),
    /// assembles + CASes a [`ChainManifest`] of the hashes, and ships the
    /// manifest's single 32-byte hash in the voucher's `proof.bytes` (unchanged
    /// wire shape — one hash). Per-segment delivery keeps every cross-node blob
    /// under the 8 MiB frame cap, which the single concatenated chain blob
    /// cannot. Heavy + offline (the issuing bank proves before sending the
    /// voucher).
    #[msg]
    async fn prove_chain(
        &self,
        _ctx: &mut Context<Self>,
        program_id: Vec<u8>,
        witness_bytes: Vec<u8>,
    ) -> Vec<u8> {
        match prove_chain_segments(&program_id, &witness_bytes) {
            Some(segments) => bincode::serialize(&segments).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Verify a canonical-shape chain delivered as a MANIFEST. `proof_hash`
    /// addresses a [`ChainManifest`] blob in the host CAS; the extension fetches
    /// the manifest (tiny — one frame), then fetches each listed per-segment
    /// proof blob (each ~3 MiB — one frame, well under the 8 MiB cross-node
    /// frame cap), and composes: (1) every segment's program commitment is in
    /// the published canonical ALLOWLIST resolved from `program_commitment` (a
    /// from-scratch prover splicing a foreign program matches none); (2) chain
    /// continuity + entering-image anchor (`verify_chain_standalone_allowlist`);
    /// (3) the tagless io-binding on the FINAL segment
    /// (`compute_io_hash(public_bytes, return_bytes)`), which the chain verifier
    /// does NOT check itself. Returns 1/0 (0 includes "manifest or any segment
    /// unavailable", indistinguishable from tampering). `peer_prefix` is the
    /// `node_prefix` fan-out hint for every blob fetch (manifest + segments).
    #[msg]
    async fn verify_chain(
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
        // 1) Fetch the manifest (the single voucher hash addresses it).
        let Some(manifest_bytes) = ctx.blob_get(hash, hint).await else {
            return 0;
        };
        let Some(manifest) = decode_chain_manifest(&manifest_bytes) else {
            return 0;
        };
        if manifest.is_empty() {
            return 0;
        }
        // 2) Fetch each per-segment proof blob (any miss ⇒ reject — the verifier
        //    must see EVERY listed segment for the continuity check to bind).
        let mut segment_blobs: Vec<Vec<u8>> = Vec::with_capacity(manifest.len());
        for seg_hash in &manifest {
            let Some(blob) = ctx.blob_get(*seg_hash, hint).await else {
                return 0;
            };
            segment_blobs.push(blob);
        }
        verify_chain_segments(
            &program_commitment,
            &segment_blobs,
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
    let commitment = zkpvm::recursion_pcs::commitment_bytes(&program_commitment_of_proof(&proof));
    let io_hash = proof.public_io_hash();
    let bytes = bincode::serialize(&proof).ok()?;
    Some((bytes, commitment, io_hash))
}

/// Resolve `program_id` to an ELF, inject the opaque `witness_bytes` into
/// its `__VOS_WITNESS` buffer (empty = no injection; the actor uses its
/// own default), and TRACE only (no prove). Lets a caller size the trace /
/// inspect the per-chip op breakdown before committing to a (potentially
/// memory-heavy) prove. `None` on any failure.
pub fn trace_program(program_id: &[u8], witness_bytes: &[u8]) -> Option<zkpvm::SideNote> {
    let path = program_id_to_elf_path(program_id)?;
    let elf = std::fs::read(&path).ok()?;
    let blob = grey_transpiler::link_elf(&elf).ok()?;
    if witness_bytes.is_empty() {
        zkpvm::actor::trace_blob(&blob, TRACE_GAS)
    } else {
        let addr = find_symbol_addr(&elf, "__VOS_WITNESS")? as usize;
        zkpvm::actor::trace_blob_with_patches(&blob, TRACE_GAS, &[(addr, witness_bytes)])
    }
}

fn prove_to_proof(program_id: &[u8], witness_bytes: &[u8]) -> Option<Proof> {
    let mut side_note = trace_program(program_id, witness_bytes)?;
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

/// Per-segment step bound for canonical chain proving. MUST match the bound
/// the canonical profile + commitment allowlist were measured/pinned against
/// (the W0 `measure_canonical_profile` / `canonical_commitment_allowlist`
/// runs used 100_000) — a different segment size reshapes the segments and
/// lands the chain on commitments outside the published allowlist.
const CHAIN_SEG_STEPS: usize = 100_000;

/// Prove `program_id` over `witness_bytes` as a canonical-shape segment chain,
/// returning the per-segment `bincode(Proof)` bytes — one `Vec<u8>` per segment,
/// in chain order. Trace, segment at [`CHAIN_SEG_STEPS`], prove each segment
/// with [`zkpvm::prove_canonical`] against the program's pinned profile. `None`
/// on any failure. Each segment's side note is dropped after its proof, so peak
/// memory holds the full trace + one segment.
///
/// PER-SEGMENT DELIVERY: the caller content-addresses each segment SEPARATELY
/// (`put_proof_blob`), assembles a [`ChainManifest`] of the resulting hashes,
/// CASes the manifest, and ships the manifest's single 32-byte hash in the
/// voucher (unchanged wire shape — one hash). This keeps every cross-node blob
/// under the 8 MiB frame cap (`MAX_FRAME_BYTES`): one canonical segment proof is
/// ~3 MiB, whereas the single concatenated `bincode(Vec<Proof>)` chain blob
/// (~N × 3 MiB ≈ hundreds of MiB) is not deliverable in one frame. The verifier
/// re-assembles the chain by fetching each segment via the manifest (see
/// [`verify_chain_segments`]).
pub fn prove_chain_segments(program_id: &[u8], witness_bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let profile = baked_profile(program_id)?;
    let full = trace_program(program_id, witness_bytes)?;
    let bounds = zkpvm::segment::segment_bounds(full.steps.len(), CHAIN_SEG_STEPS);
    let mut segments: Vec<Vec<u8>> = Vec::with_capacity(bounds.len());
    for (a, b) in bounds {
        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
        let proof = prove_canonical(&mut sn, profile).ok()?;
        segments.push(bincode::serialize(&proof).ok()?);
    }
    Some(segments)
}

/// A chain delivered as per-segment proof CAS hashes, in chain order. The
/// producer puts each segment proof into the host proof-blob store SEPARATELY
/// and lists the resulting 32-byte hashes here; the manifest is itself CASed and
/// its single hash rides in the voucher's `proof.bytes`. Because the manifest is
/// content-addressed, its segment list (count + order) is integrity-bound to
/// that hash — a verifier that fetches and verifies EVERY listed segment, plus
/// the chain's boundary-continuity + entering-root anchor + final io-binding,
/// cannot be fooled by a truncated, reordered, or spliced manifest.
pub type ChainManifest = Vec<[u8; 32]>;

/// Encode a [`ChainManifest`] for the proof-blob store. Tiny (`32·N` bytes;
/// ~2.4 KiB for the ~76-segment conservation transition), so it always rides a
/// single cross-node frame.
pub fn encode_chain_manifest(segment_hashes: &[[u8; 32]]) -> Vec<u8> {
    bincode::serialize(&segment_hashes.to_vec()).unwrap_or_default()
}

/// Decode a [`ChainManifest`] blob. `None` on a malformed blob.
pub fn decode_chain_manifest(bytes: &[u8]) -> Option<ChainManifest> {
    bincode::deserialize::<ChainManifest>(bytes).ok()
}

/// Verify a chain delivered as per-segment proof bytes (each fetched from the
/// host CAS via the manifest) against the trusted `commitment_bytes` (one of the
/// program's canonical allowlist entries) and the asserted `(public_bytes,
/// return_bytes)`. Composes three checks so none is meaningful without the
/// others:
///   1. allowlist membership — every segment's commitment must be in the
///      canonical allowlist that CONTAINS `commitment_bytes` (a foreign
///      program matches no entry);
///   2. chain validity — `verify_chain_standalone_allowlist` (per-segment
///      STARK validity + continuity + the self-anchored entering root);
///   3. tagless io-binding on the FINAL segment — `public_io_hash() ==
///      compute_io_hash(public, return)` (the chain verifier itself does NOT
///      check the io-hash; the guest binds it at halt, i.e. the last segment).
///
/// Verifying a canonical proof (all 31 components + forced large log_sizes)
/// overflows the default ~2 MiB stack, so the chain verification runs on a
/// large-stack thread. Returns `false` on any malformed input, missing/garbled
/// segment, or rejection.
pub fn verify_chain_segments(
    commitment_bytes: &[u8],
    segment_blobs: &[Vec<u8>],
    public_bytes: &[u8],
    return_bytes: &[u8],
) -> bool {
    if commitment_bytes.len() != 32 {
        return false;
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(commitment_bytes);
    let Some(allowed) = allowlist_for_commitment(&commitment) else {
        return false;
    };
    if segment_blobs.is_empty() {
        return false;
    }
    let mut segments: Vec<Proof> = Vec::with_capacity(segment_blobs.len());
    for blob in segment_blobs {
        let Ok(proof) = bincode::deserialize::<Proof>(blob) else {
            return false;
        };
        segments.push(proof);
    }
    // 3. The final segment carries the guest's halt-bound io-hash.
    if segments.last().unwrap().public_io_hash()
        != vos::zk::compute_io_hash(public_bytes, return_bytes)
    {
        return false;
    }
    let allowlist: Vec<CommitmentHash> = allowed
        .iter()
        .map(|c| CommitmentHash::from(&c[..]))
        .collect();
    let expected_root = segments[0].initial_state.memory_root;
    // 1 + 2: allowlist membership + chain validity, on a large stack.
    let verdict = std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(move || {
            verify_chain_standalone_allowlist(
                &segments,
                &allowlist,
                expected_root,
                DEFAULT_MAX_LOG_SIZE,
                &PcsPolicy::MOBILE,
            )
            .is_ok()
        });
    match verdict {
        Ok(handle) => handle.join().unwrap_or(false),
        Err(_) => false,
    }
}

/// The canonical `min_log_size` profile [`prove_chain`] pads each forcing-set
/// chip to, per program. `None` for an unknown program.
fn baked_profile(program_id: &[u8]) -> Option<&'static [u32]> {
    match program_id {
        b"voucher-check" => Some(&VOUCHER_CHECK_CANONICAL_PROFILE),
        _ => None,
    }
}

/// The published canonical commitment allowlist that CONTAINS `commitment`
/// (reverse lookup over the baked programs). `None` if no program's allowlist
/// contains it — so a commitment outside every published canonical shape
/// cannot be chain-verified. Lets the bridge keep passing the single
/// `program_commitment` it already holds (the primary shape) while the chain
/// is verified against the full allowlist.
fn allowlist_for_commitment(commitment: &[u8; 32]) -> Option<&'static [[u8; 32]]> {
    for program in [b"voucher-check".as_slice()] {
        if let Some(commitments) = baked_commitments(program) {
            if commitments.iter().any(|c| c == commitment) {
                return Some(commitments);
            }
        }
    }
    None
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

/// Canonical-shape forcing profile for `voucher-check` (federation wire-through
/// W0), indexed by [`zkpvm::chip_idx`]. `zkpvm::prove_canonical` pads each
/// forcing-set chip's main trace up to `PROFILE[chip_idx]` so every segment's
/// preprocessed-bearing chips share one `log_size`; `0` = not forced (the chip
/// proves at its natural / fixed-table size).
///
/// Locked by `measure_canonical_profile` (the per-chip MAX natural `log_size`
/// over the whole conservation transition at SEG_STEPS = 100_000) — re-measure
/// and re-pin (and re-pin [`VOUCHER_CHECK_COMMITMENTS`]) if the segment-step
/// bound or the voucher-check ELF changes. Forcing set: BLAKE2B(1),
/// BLAKE2B_BOUNDARY(2), MEMORY_PAGE(4), RISTRETTO(23), RIST_ECALL(24),
/// FIXED_BASE_CONSUMER(26), COMB_ANCHOR(27), COMB_SCALAR_BOUNDARY(28),
/// COMB_COMPRESS(29), COMB_COMPRESS_OUTPUT(30).
pub const VOUCHER_CHECK_CANONICAL_PROFILE: [u32; zkpvm::chip_idx::COUNT] = [
    0, 14, 17, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 7, 0, 11, 6, 5, 6, 5,
];

/// Published canonical-shape program-commitment ALLOWLIST for `voucher-check`
/// (federation wire-through W0). The commitment is the preprocessed-trace
/// Merkle root; under canonical proving (`zkpvm::prove_canonical` with
/// [`VOUCHER_CHECK_CANONICAL_PROFILE`]) every segment of the conservation
/// transition collapses to one of these — `[0]` = a comb-free segment (the
/// vast majority), `[1]` = a segment carrying one fixed-base scalar mult. The
/// two comb chips' `real_n_rows`-gated preprocessed content is the ONLY
/// remaining shape variation, so the set is small and witness-independent;
/// `zkpvm_verifier::verify_chain_standalone_allowlist` accepts a chain whose
/// every segment commitment is in this set. (Larger transfer batches with more
/// comb calls per segment extend the allowlist with `C_2, …`.) Re-pinned by
/// the `canonical_commitment_drift_guard` test.
#[cfg(not(feature = "poseidon2-channel"))]
pub const VOUCHER_CHECK_COMMITMENTS: [[u8; 32]; 2] = [
    // C_0 — comb-free canonical shape (75 of 76 segments).
    // blake2s 35a231e8f5317023f5637f603becd36122fe9e6945f169f5a5d6177c4bb0ee90
    [
        0x35, 0xa2, 0x31, 0xe8, 0xf5, 0x31, 0x70, 0x23, 0xf5, 0x63, 0x7f, 0x60, 0x3b, 0xec, 0xd3,
        0x61, 0x22, 0xfe, 0x9e, 0x69, 0x45, 0xf1, 0x69, 0xf5, 0xa5, 0xd6, 0x17, 0x7c, 0x4b, 0xb0,
        0xee, 0x90,
    ],
    // C_1 — one-comb-call canonical shape (the fixed-base scalar mult segment).
    // blake2s 1de878a78374b8a14c5700e6cfeda13bbcd67edb6398a10d7ffb3e77e9a15567
    [
        0x1d, 0xe8, 0x78, 0xa7, 0x83, 0x74, 0xb8, 0xa1, 0x4c, 0x57, 0x00, 0xe6, 0xcf, 0xed, 0xa1,
        0x3b, 0xbc, 0xd6, 0x7e, 0xdb, 0x63, 0x98, 0xa1, 0x0d, 0x7f, 0xfb, 0x3e, 0x77, 0xe9, 0xa1,
        0x55, 0x67,
    ],
];

/// Poseidon2-M31 variant of the canonical allowlist (native-recursion Stage-0).
/// The commitment is the preprocessed-trace Merkle root under the Poseidon2-M31
/// PCS — a `P2Hash` (8 M31 limbs) serialized as little-endian `u32`s, NOT a
/// Blake2s digest. Re-pinned 2026-06-18 by `canonical_commitment_allowlist` /
/// `canonical_commitment_drift_guard` under `--features poseidon2-channel`
/// (comb segment #57 of 76; seg 0 and seg 75 both collapse to C_0).
#[cfg(feature = "poseidon2-channel")]
pub const VOUCHER_CHECK_COMMITMENTS: [[u8; 32]; 2] = [
    // C_0 — comb-free canonical shape (75 of 76 segments).
    // P2Hash LE c8ebc64c73b600790984c72c87c2e0502750510f2d46cf5fa6afe71bc5cfdb7a
    [
        0xc8, 0xeb, 0xc6, 0x4c, 0x73, 0xb6, 0x00, 0x79, 0x09, 0x84, 0xc7, 0x2c, 0x87, 0xc2, 0xe0,
        0x50, 0x27, 0x50, 0x51, 0x0f, 0x2d, 0x46, 0xcf, 0x5f, 0xa6, 0xaf, 0xe7, 0x1b, 0xc5, 0xcf,
        0xdb, 0x7a,
    ],
    // C_1 — one-comb-call canonical shape (the fixed-base scalar mult segment).
    // P2Hash LE 5b1cdb6ec0409e2221859f4916ef76381fa41d1e8cf9e43f51abe80c26925538
    [
        0x5b, 0x1c, 0xdb, 0x6e, 0xc0, 0x40, 0x9e, 0x22, 0x21, 0x85, 0x9f, 0x49, 0x16, 0xef, 0x76,
        0x38, 0x1f, 0xa4, 0x1d, 0x1e, 0x8c, 0xf9, 0xe4, 0x3f, 0x51, 0xab, 0xe8, 0x0c, 0x26, 0x92,
        0x55, 0x38,
    ],
];

/// The published canonical commitment allowlist for `program_id` (or `None`
/// for an unknown program). Chain verification pins every segment to one of
/// these via `verify_chain_standalone_allowlist`.
pub fn baked_commitments(program_id: &[u8]) -> Option<&'static [[u8; 32]]> {
    match program_id {
        b"voucher-check" => Some(&VOUCHER_CHECK_COMMITMENTS),
        _ => None,
    }
}

/// Single-commitment view of the canonical allowlist: the PRIMARY shape
/// (`[0]`, the comb-free segment that the vast majority of segments hit). The
/// single-shot `verify` API + the `program_commitment` message use this; chain
/// verification uses the full allowlist via [`baked_commitments`].
fn baked_commitment(program_id: &[u8]) -> Option<[u8; 32]> {
    baked_commitments(program_id).map(|cs| cs[0])
}

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
