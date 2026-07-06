//! ProverExtension — general-purpose, program-agnostic host-side zkpvm
//! prover + verifier over transpiled PVM blobs.
//!
//! ## What it does
//!
//! Four message handlers. The prover is a PURE PVM prover — it never
//! sees a RISC-V ELF, never transpiles, and never looks up a symbol. The
//! caller delivers the already-transpiled PVM `pvm_blob` plus the
//! `witness_addr` (the flat-memory offset of the actor's `__VOS_WITNESS`
//! buffer, which equals its ELF symbol address) and the opaque
//! `witness_bytes`. The prover patches the witness into the blob's initial
//! image and traces — it never interprets the witness, so it stays
//! program-agnostic.
//!
//! - `prove(pvm_blob, witness_bytes, witness_addr) -> Vec<u8>` — patch
//!   `witness_bytes` at `witness_addr` (skipped when empty), trace,
//!   `prove_mobile`, and return the bincode-serialized `zkpvm::Proof`.
//!   Empty `Vec` on any failure. The caller content-addresses the bytes
//!   into the host proof-blob store (`put_proof_blob`) and ships the
//!   32-byte hash, because there is no extension-side CAS *put* (only
//!   `ctx.blob_get`).
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
//! - `prove_chain(pvm_blob, witness_bytes, witness_addr, seg_steps,
//!   profile) -> Vec<u8>` — the segment-chain analog of `prove` for traces
//!   too large for a single proof. The caller also supplies `seg_steps`
//!   (the per-segment step bound) and the canonical `profile` (the
//!   `[u32; chip_idx::COUNT]` forcing profile). Returns `bincode(Vec<Vec<u8>>)`.
//!
//! - `verify_chain(allowlist, proof_hash, public_bytes, return_bytes,
//!   peer_prefix) -> u8` — the chain analog of `verify`. `allowlist` is the
//!   caller-supplied set of accepted canonical program commitments,
//!   delivered as the concatenation of 32-byte commitments (`32·N` bytes). It
//!   STREAMS the chain — fetch + verify + drop one segment proof at a time — so
//!   peak memory holds ~one proof regardless of chain length (a phone-class
//!   node can verify a many-hundred-segment chain).
//!
//! ## Commitment / allowlist provenance
//!
//! A verifier's `program_commitment` (and the chain `allowlist`) is
//! PROVENANCE, supplied by the caller — it pins a specific program build's
//! cryptographic identity (the preprocessed-trace Merkle root). It must
//! come from a representative REAL (witness-injected) run: a provable actor
//! takes its witness through `__VOS_WITNESS`, and when that buffer is empty
//! the actor runs a DIFFERENT fallback path with a different execution
//! shape — and therefore a different commitment. So the trusted commitment
//! is established once at publish-time and pinned by the caller, never
//! recomputed from an empty witness. (Across different witness *values* on
//! the injected path the commitment is stable, so one pinned commitment
//! verifies every real proof.)

use vos::prelude::*;
use zkpvm::{Proof, SegmentState, prove_canonical, prove_mobile};
use zkpvm_verifier::{CommitmentHash, PcsPolicy, verify_standalone_with_pcs_policy};

/// Gas bound for tracing a provable actor. Generous — an actor that
/// exceeds it traces to `OutOfGas` and the prove fails (empty reply).
const TRACE_GAS: u64 = 100_000_000;

#[actor]
struct Prover;

#[messages]
impl Prover {
    fn new() -> Self {
        Prover
    }

    /// Prove `pvm_blob` over the caller-supplied opaque `witness_bytes`,
    /// injected at `witness_addr`. Returns bincode-serialized
    /// `zkpvm::Proof` bytes, or an empty `Vec` on any failure (unparseable
    /// blob / patch out of range / prove failed). The caller CASes the
    /// bytes via the host proof-blob store.
    #[msg]
    async fn prove(
        &self,
        _ctx: &mut Context<Self>,
        pvm_blob: Vec<u8>,
        witness_bytes: Vec<u8>,
        witness_addr: u64,
    ) -> Vec<u8> {
        prove_blob(&pvm_blob, &witness_bytes, witness_addr as usize).unwrap_or_default()
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

    /// Prove `pvm_blob` over `witness_bytes` as a canonical-shape SEGMENT
    /// CHAIN — the federation path for traces too large for a single proof
    /// (the conservation transition is millions of steps). Segments at
    /// `seg_steps`, proves each with canonical-shape proving against the
    /// caller-supplied `profile`, and returns `bincode(Vec<Vec<u8>>)` — the
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
        pvm_blob: Vec<u8>,
        witness_bytes: Vec<u8>,
        witness_addr: u64,
        seg_steps: u64,
        profile: Vec<u32>,
    ) -> Vec<u8> {
        match prove_chain_segments(
            &pvm_blob,
            &witness_bytes,
            witness_addr as usize,
            seg_steps as usize,
            &profile,
        ) {
            Some(segments) => bincode::serialize(&segments).unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Verify a canonical-shape chain delivered as a MANIFEST. `proof_hash`
    /// addresses a [`ChainManifest`] blob in the host CAS; the extension fetches
    /// the manifest (tiny — one frame), then STREAMS the chain: it fetches each
    /// listed per-segment proof (~3 MiB — one frame, under the 8 MiB cross-node
    /// frame cap), verifies it, and DROPS it before fetching the next. Peak
    /// memory therefore holds ~one proof regardless of chain length — a
    /// phone-class node can verify a many-hundred-segment chain. Per segment it
    /// composes: (1) the program commitment is in the caller-supplied `allowlist`
    /// (a from-scratch prover splicing a foreign program matches none);
    /// (2) STARK validity (`verify_standalone`, MOBILE) + boundary continuity
    /// onto the previous segment; and, on the FINAL segment, (3) the tagless
    /// io-binding (`compute_io_hash(public_bytes, return_bytes)`), which the
    /// guest binds at halt. Returns 1/0 (0 includes "manifest or any segment
    /// unavailable", indistinguishable from tampering). `peer_prefix` is the
    /// `node_prefix` fan-out hint for every blob fetch (manifest + segments).
    ///
    /// `allowlist` is the concatenation of the accepted 32-byte canonical
    /// commitments (`32·N` bytes) — the caller holds the program's published
    /// allowlist and passes it directly.
    #[msg]
    async fn verify_chain(
        &self,
        ctx: &mut Context<Self>,
        allowlist: Vec<u8>,
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
        // The allowlist is the concatenation of accepted 32-byte commitments.
        if allowlist.is_empty() || allowlist.len() % 32 != 0 {
            return 0;
        }
        let allowlist: Vec<CommitmentHash> =
            allowlist.chunks_exact(32).map(CommitmentHash::from).collect();
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
        // 2) STREAM the chain: fetch each per-segment proof, verify it, and DROP
        //    it before fetching the next — so peak memory holds ~ONE proof
        //    regardless of chain length (a phone-class verifier can check a
        //    600-segment chain). Any missing segment rejects — the verifier must
        //    see EVERY listed segment for the continuity chain to bind. Boundary
        //    continuity carries forward in `prev_final` (a small `SegmentState`);
        //    the io-binding is checked on the FINAL segment.
        let n = manifest.len();
        let mut prev_final: Option<SegmentState> = None;
        for (i, seg_hash) in manifest.iter().enumerate() {
            let Some(blob) = ctx.blob_get(*seg_hash, hint).await else {
                return 0;
            };
            match verify_segment_on_large_stack(
                blob,
                &allowlist,
                prev_final.take(),
                i == n - 1,
                &public_bytes,
                &return_bytes,
            ) {
                Some(final_state) => prev_final = Some(final_state),
                None => return 0,
            }
        }
        1
    }
}

// ── Core logic (Context-free, unit-testable) ─────────────────────────

/// Prove `pvm_blob` over `witness_bytes` (injected at `witness_addr`) and
/// return the bincode-encoded proof bytes. `None` on any failure.
pub fn prove_blob(pvm_blob: &[u8], witness_bytes: &[u8], witness_addr: usize) -> Option<Vec<u8>> {
    let proof = prove_to_proof(pvm_blob, witness_bytes, witness_addr)?;
    bincode::serialize(&proof).ok()
}

/// Trace `pvm_blob`, injecting the opaque `witness_bytes` at `witness_addr`
/// (empty = no injection; the actor uses its own default). `None` on any
/// failure.
fn trace_blob(pvm_blob: &[u8], witness_bytes: &[u8], witness_addr: usize) -> Option<zkpvm::SideNote> {
    if witness_bytes.is_empty() {
        zkpvm::actor::trace_blob(pvm_blob, TRACE_GAS)
    } else {
        zkpvm::actor::trace_blob_with_patches(pvm_blob, TRACE_GAS, &[(witness_addr, witness_bytes)])
    }
}

fn prove_to_proof(pvm_blob: &[u8], witness_bytes: &[u8], witness_addr: usize) -> Option<Proof> {
    let mut side_note = trace_blob(pvm_blob, witness_bytes, witness_addr)?;
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

/// Prove `pvm_blob` over `witness_bytes` as a canonical-shape segment chain,
/// returning the per-segment `bincode(Proof)` bytes — one `Vec<u8>` per segment,
/// in chain order. Trace, segment at `seg_steps`, prove each segment with
/// [`zkpvm::prove_canonical`] against the caller-supplied `profile`. `None`
/// on any failure. Each segment's side note is dropped after its proof, so peak
/// memory holds the full trace + one segment.
///
/// `seg_steps` and `profile` MUST match the values the program's canonical
/// commitment allowlist was measured/pinned against — a different segment size
/// reshapes the segments and lands the chain on commitments outside the
/// published allowlist.
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
pub fn prove_chain_segments(
    pvm_blob: &[u8],
    witness_bytes: &[u8],
    witness_addr: usize,
    seg_steps: usize,
    profile: &[u32],
) -> Option<Vec<Vec<u8>>> {
    let full = trace_blob(pvm_blob, witness_bytes, witness_addr)?;
    let bounds = zkpvm::segment::segment_bounds(full.steps.len(), seg_steps);
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

/// Verify a chain delivered as per-segment proof bytes against the
/// caller-supplied `allowlist` (the concatenation of accepted 32-byte canonical
/// commitments, `32·N` bytes) and the asserted `(public_bytes, return_bytes)`.
/// Composes, per segment, three checks so none is meaningful without the
/// others:
///   1. allowlist membership — every segment's commitment must be in
///      `allowlist` (a foreign program matches no entry);
///   2. chain validity — per-segment STARK validity (`verify_standalone`,
///      MOBILE) + boundary continuity (each segment's `initial_state` equals
///      the previous segment's `final_state`);
///   3. tagless io-binding on the FINAL segment — `public_io_hash() ==
///      compute_io_hash(public, return)` (the guest binds it at halt, i.e. the
///      last segment).
///
/// STREAMING: proofs are verified + DROPPED one at a time (each on a large
/// stack — a canonical proof's verify overflows the default ~2 MiB), so peak
/// memory holds ~one proof regardless of chain length. This is the offline/test
/// mirror of the `verify_chain` handler, which streams the CAS fetch too.
/// `segment_blobs` are still all held by the caller here; the handler bounds the
/// fetch as well. Returns `false` on any malformed input, missing/garbled
/// segment, or rejection.
pub fn verify_chain_segments(
    allowlist_bytes: &[u8],
    segment_blobs: &[Vec<u8>],
    public_bytes: &[u8],
    return_bytes: &[u8],
) -> bool {
    // The allowlist is the concatenation of 32-byte commitments; empty or a
    // non-multiple-of-32 length can't be a valid allowlist.
    if allowlist_bytes.is_empty() || allowlist_bytes.len() % 32 != 0 {
        return false;
    }
    if segment_blobs.is_empty() {
        return false;
    }
    let allowlist: Vec<CommitmentHash> = allowlist_bytes
        .chunks_exact(32)
        .map(CommitmentHash::from)
        .collect();
    let n = segment_blobs.len();
    let mut prev_final: Option<SegmentState> = None;
    for (i, blob) in segment_blobs.iter().enumerate() {
        match verify_segment_on_large_stack(
            blob.clone(),
            &allowlist,
            prev_final.take(),
            i == n - 1,
            public_bytes,
            return_bytes,
        ) {
            Some(final_state) => prev_final = Some(final_state),
            None => return false,
        }
    }
    true
}

/// Verify ONE chain segment on a large-stack thread and return its `final_state`
/// (for the next segment's continuity check), or `None` on any failure. The
/// blob is moved in and dropped when the thread returns, so a caller looping
/// over segments holds only one proof at a time. A canonical proof's verify
/// overflows the default ~2 MiB test/handler stack, hence the 512 MiB thread.
fn verify_segment_on_large_stack(
    blob: Vec<u8>,
    allowlist: &[CommitmentHash],
    prev_final: Option<SegmentState>,
    is_last: bool,
    public_bytes: &[u8],
    return_bytes: &[u8],
) -> Option<SegmentState> {
    // The spawned thread needs `'static` data; the blob + prev move in, and the
    // small refs (allowlist ~32·N bytes, io bytes) are cloned. The blob is the
    // only large allocation and it drops when the thread returns.
    let allowlist = allowlist.to_vec();
    let public = public_bytes.to_vec();
    let return_bytes = return_bytes.to_vec();
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(move || {
            verify_one_segment(
                &blob,
                &allowlist,
                prev_final.as_ref(),
                is_last,
                &public,
                &return_bytes,
            )
        })
        .ok()?
        .join()
        .ok()?
}

/// Pure per-segment verify (no threading): decode the proof, check its
/// commitment is in `allowlist`, that it chains onto `prev_final` (or is the
/// entering segment when `prev_final` is `None`), the io-binding when it's the
/// final segment, and that it verifies standalone (MOBILE) against its own
/// commitment. Returns the segment's `final_state` on success. MUST run on a
/// large stack — call via [`verify_segment_on_large_stack`].
fn verify_one_segment(
    blob: &[u8],
    allowlist: &[CommitmentHash],
    prev_final: Option<&SegmentState>,
    is_last: bool,
    public_bytes: &[u8],
    return_bytes: &[u8],
) -> Option<SegmentState> {
    let proof: Proof = bincode::deserialize(blob).ok()?;
    // 1. Program identity: the segment's commitment is in the allowlist.
    let commitment = proof.stark_proof.commitments[0];
    if !allowlist.contains(&commitment) {
        return None;
    }
    // 2a. Boundary continuity: this segment enters where the last one exited.
    if let Some(pf) = prev_final {
        if *pf != proof.initial_state {
            return None;
        }
    }
    // 3. The final segment carries the guest's halt-bound io-hash.
    if is_last
        && proof.public_io_hash() != vos::zk::compute_io_hash(public_bytes, return_bytes)
    {
        return None;
    }
    let final_state = proof.final_state.clone();
    // 2b. Per-segment STARK validity against its own commitment.
    verify_standalone_with_pcs_policy(proof, commitment, &PcsPolicy::MOBILE).ok()?;
    Some(final_state)
}
