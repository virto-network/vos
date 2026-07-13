//! ProverExtension — general-purpose, program-agnostic host-side zkpvm
//! prover + verifier over transpiled PVM blobs.
//!
//! ## What it does
//!
//! The prover is a PURE PVM prover — it never
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
//!   Empty `Vec` on any failure. A single proof is one deliverable
//!   payload, so the caller content-addresses the bytes into the host
//!   proof-blob store (`put_proof_blob`) and ships the 32-byte hash.
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
//!   page_budget, profile) -> Vec<u8>` — the segment-chain analog of `prove`
//!   for traces too large for a single proof. The caller also supplies
//!   `seg_steps` (the per-segment step bound), `page_budget` (per-segment
//!   touched-page budget; `0` = uniform step cut), and the canonical
//!   `profile` (the `[u32; chip_idx::COUNT]` forcing profile). STREAMS the
//!   chain out as it proves: each segment's `bincode(Proof)` is published
//!   into the host proof-blob CAS via `ctx.blob_put` the moment it is
//!   proven and only its 32-byte hash is retained, so peak memory holds
//!   ~one segment regardless of chain length. Returns the anchored
//!   [`ChainManifest`] input (`[entering_root:32][seg_hash:32]…`, i.e.
//!   [`encode_chain_manifest_anchored`]); the caller CASes that manifest
//!   and ships its single hash. Empty `Vec` on any failure.
//!
//! - `verify_chain(allowlist, proof_hash, public_bytes, return_bytes,
//!   peer_prefix) -> u8` — the chain analog of `verify`. `allowlist` is the
//!   caller-supplied set of accepted canonical program commitments,
//!   delivered as the concatenation of 32-byte commitments (`32·N` bytes). It
//!   STREAMS the chain — fetch + verify + drop one segment proof at a time — so
//!   peak memory holds ~one proof regardless of chain length (a phone-class
//!   node can verify a many-hundred-segment chain). The chain `manifest` also
//!   carries the ENTERING-IMAGE root, which segment 0 is anchored to (the memory
//!   analogue of the allowlist — closes the doctored-initial-image splice).
//!
//! - `measure_catalog(pvm_blob, witness_bytes, witness_addr, seg_steps, page_budget,
//!   profile, gas) -> Vec<u8>` — the heavy zkpvm measurement behind
//!   `vosx zk pin`: the entering-image root over the UNPATCHED image and, when
//!   a representative `witness_bytes` is supplied, the canonical commitment
//!   allowlist (`image_root(32) ++ commitment(32)…`). Blob-in like the rest —
//!   the CLI does the ELF transpile + `__VOS_WITNESS` lookup and writes the
//!   catalog TOML; this handler only proves.
//!
//! Plus the async prove-job set (`prove_chain_job` / `tick` / `job_poll` /
//! `job_release`) described below.
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

use vos::jobs::JobQueue;
use vos::prelude::*;
use zkpvm::{Proof, SegmentState, prove_canonical, prove_mobile};
use zkpvm_verifier::{CommitmentHash, PcsPolicy, verify_standalone_with_pcs_policy};

/// Gas bound for tracing a provable actor. Generous — an actor that
/// exceeds it traces to `OutOfGas` and the prove fails (empty reply).
const TRACE_GAS: u64 = 100_000_000;

/// Defensive ceiling on the number of segments a chain manifest may list.
/// A verifier fetches + STARK-verifies every listed segment, so an
/// oversized manifest is an unbounded-work (DoS) lever. Legitimate chains
/// are tens of segments (the conservation transition is ~76); this cap is
/// far above any real chain — a belt-and-suspenders bound over the invoke's
/// own gas metering. Bump it if a deployment segments a genuinely larger
/// batch.
const MAX_CHAIN_SEGMENTS: usize = 65_536;

/// Spawn `f` on a dedicated 512 MiB-stack thread WITHOUT joining it. A
/// canonical prove/verify overflows the default ~2 MiB stack, so every heavy
/// zkpvm entry point runs on such a thread. The streaming chain paths use
/// this directly (the spawner drains segments while the thread proves);
/// everything else goes through the join-immediately [`run_on_large_stack`].
/// `None` when the thread can't spawn.
fn spawn_on_large_stack<T: Send + 'static>(
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<std::thread::JoinHandle<Option<T>>> {
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .ok()
}

/// Run `f` on a dedicated 512 MiB-stack thread and hand back its result.
/// `None` when the thread can't spawn or `f` panics — the fail-soft the
/// callers' empty replies map to.
fn run_on_large_stack<T: Send + 'static>(
    f: impl FnOnce() -> Option<T> + Send + 'static,
) -> Option<T> {
    spawn_on_large_stack(f)?.join().ok()?
}

// ── Async prove jobs ────────────────────────────────────────────
//
// `prove_chain` is a SYNCHRONOUS gas-metered invoke: a caller that asks it
// blocks for the whole (minutes-long) canonical chain prove, which no real
// actor dispatch can wait out. The async path decouples proving from the ask:
// `prove_chain_job` (a `#[msg(job)]` begin) enqueues a job and returns a job id
// IMMEDIATELY; a later host `tick()` advances one job and TELLS the requester a
// callback carrying the job id. The requester then pulls the result
// (`job_poll`).
//
// Job STATE (output bytes / done / error) lives in a `vos::jobs::JobQueue`,
// driving the standard `job_poll` / `job_release` surface. The queue holds no
// inputs, so a separate FIFO `pending` list carries each unproved job's inputs
// (blob / witness / profile) + its callback target until `tick` proves it.
//
// STREAMING PUBLISH: both chain paths (the sync `prove_chain` invoke and the
// job's `tick`) prove on a large-stack worker thread and PUBLISH each segment's
// proof bytes into the host proof-blob CAS (`ctx.blob_put`) the moment it is
// proven, retaining only the 32-byte hashes — peak memory holds ~one segment
// (~3 MiB) instead of the whole chain (~N × 3 MiB, ~0.9 GB at 293 segments)
// parked in the JobQueue until `job_release`. The job result / sync reply is
// the tiny anchored-manifest input (`encode_chain_manifest_anchored(root,
// hashes)`, 32·(N+1) bytes); the requester CASes that manifest and ships its
// single hash — the per-segment `put_proof_blob` dance it used to run over the
// full proof bytes is gone.

/// Terminal outcome codes carried in the completion callback's `status` field
/// (`1` = proved, `2` = failed). Wire-preserved from the retired `JobStatus`
/// enum so the federation callback's shape is unchanged; job STATE otherwise
/// lives in the [`JobQueue`] (`job_poll` reports `done` / `error`).
const JOB_DONE: u64 = 1;
const JOB_FAILED: u64 = 2;

/// Inputs for one queued prove-chain job that `tick` hasn't proved yet. The
/// job's output + terminal state live in the [`JobQueue`]; this record holds
/// only what proving consumes — blob / witness / profile — plus the callback
/// target, retained in a FIFO `pending` list and dropped once proved.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct PendingProve {
    /// Job id (allocated by the queue's `begin`).
    id: u64,
    /// ServiceId to callback on completion (`0` = no callback).
    reply_to: u32,
    /// Dynamic `Msg` method name (UTF-8) to send the callback as.
    reply_msg: Vec<u8>,
    /// Transpiled PVM blob to prove.
    pvm_blob: Vec<u8>,
    /// Opaque witness to inject at `witness_addr`.
    witness_bytes: Vec<u8>,
    /// `__VOS_WITNESS` flat-memory address.
    witness_addr: u64,
    /// Per-segment step bound for canonical proving.
    seg_steps: u64,
    /// Per-segment touched-page budget (0 = uniform step cut).
    page_budget: u64,
    /// Canonical forcing profile.
    profile: Vec<u32>,
}

#[actor]
struct Prover {
    /// Async prove-job state (output bytes + done/error), driving the standard
    /// `job_poll` / `job_release` surface.
    queue: JobQueue,
    /// Inputs for jobs not yet proved (FIFO); `tick` drains one per tick.
    pending: Vec<PendingProve>,
}

#[messages]
impl Prover {
    fn new() -> Self {
        Prover {
            queue: JobQueue::new(),
            pending: Vec::new(),
        }
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
    /// CHAIN — for traces too large for a single proof (the conservation-of-
    /// value transition, say, is millions of steps). Segments at `seg_steps`,
    /// proves each with canonical-shape proving against the caller-supplied
    /// `profile`, and STREAMS the chain out: each segment's `bincode(Proof)`
    /// is published into the host proof-blob CAS (`ctx.blob_put`) as it is
    /// proven and dropped, so peak memory holds ~one segment (~3 MiB)
    /// regardless of chain length. Returns the anchored [`ChainManifest`]
    /// input — [`encode_chain_manifest_anchored`]`(entering_root,
    /// segment_hashes)`, `32·(N+1)` bytes. Empty `Vec` on any failure
    /// (including a failed publish, which aborts the remaining prove).
    ///
    /// The caller CASes the returned manifest bytes (`put_proof_blob`) and
    /// ships the manifest's single 32-byte hash wherever its protocol carries
    /// a proof reference (unchanged wire shape — one hash). Per-segment CAS
    /// delivery keeps every cross-node blob under the 8 MiB frame cap, which
    /// a single concatenated chain blob cannot. Heavy + offline (the producer
    /// proves before shipping).
    #[msg]
    async fn prove_chain(
        &self,
        ctx: &mut Context<Self>,
        pvm_blob: Vec<u8>,
        witness_bytes: Vec<u8>,
        witness_addr: u64,
        seg_steps: u64,
        page_budget: u64,
        profile: Vec<u32>,
    ) -> Vec<u8> {
        match prove_chain_publishing(
            pvm_blob,
            witness_bytes,
            witness_addr as usize,
            seg_steps as usize,
            page_budget as usize,
            profile,
            async |seg| ctx.blob_put(seg).await,
        )
        .await
        {
            Some((root, hashes)) => encode_chain_manifest_anchored(root, &hashes),
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
    /// onto the previous segment; (2a) the ENTERING-IMAGE ANCHOR — segment 0's
    /// `initial_state.memory_root` equals the manifest's `initial_root` (skipped
    /// only when the manifest is unanchored — the all-zero sentinel), which
    /// rejects a chain spliced onto a doctored initial RAM image; and, on the
    /// FINAL segment, (3) the tagless io-binding
    /// (`compute_io_hash(public_bytes, return_bytes)`), which the guest binds at
    /// halt. Returns 1/0 (0 includes "manifest or any segment unavailable",
    /// indistinguishable from tampering). `peer_prefix` is the `node_prefix`
    /// fan-out hint for every blob fetch (manifest + segments).
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
        // 1) Fetch the manifest (the single caller-supplied hash addresses it).
        let Some(manifest_bytes) = ctx.blob_get(hash, hint).await else {
            return 0;
        };
        let Some(manifest) = decode_chain_manifest(&manifest_bytes) else {
            return 0;
        };
        if manifest.segments.is_empty() || manifest.segments.len() > MAX_CHAIN_SEGMENTS {
            return 0;
        }
        // The entering-image anchor: segment 0 must start from the manifest's
        // declared entering root (skipped when the manifest is unanchored — the
        // all-zero sentinel). See `ChainManifest::initial_root`.
        let expected_initial_root = (manifest.initial_root != UNANCHORED_ROOT).then_some(manifest.initial_root);
        // 2) STREAM the chain: fetch each per-segment proof, verify it, and DROP
        //    it before fetching the next — so peak memory holds ~ONE proof
        //    regardless of chain length (a phone-class verifier can check a
        //    600-segment chain). Any missing segment rejects — the verifier must
        //    see EVERY listed segment for the continuity chain to bind. Boundary
        //    continuity carries forward in `prev_final` (a small `SegmentState`);
        //    the entering-root anchor binds segment 0, the io-binding the FINAL
        //    segment.
        let n = manifest.segments.len();
        let mut prev_final: Option<SegmentState> = None;
        for (i, seg_hash) in manifest.segments.iter().enumerate() {
            let Some(blob) = ctx.blob_get(*seg_hash, hint).await else {
                return 0;
            };
            match verify_segment_on_large_stack(
                blob,
                &allowlist,
                prev_final.take(),
                expected_initial_root,
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

    /// ASYNC analog of `prove_chain` (a `#[msg(job)]` begin): enqueue a
    /// canonical-chain prove job and return a job id IMMEDIATELY, without
    /// blocking the caller for the (minutes-long) prove. A later host `tick()`
    /// proves the job — publishing each segment to the host CAS as it lands
    /// (see the module's async-jobs note) — and TELLS `reply_to` the dynamic
    /// message named `reply_msg` carrying `{job_id, status, segments}`
    /// (skipped when `reply_to == 0`). The requester then pulls the
    /// anchored-manifest input with `job_poll`.
    ///
    /// `seg_steps` + `profile` MUST match the program's pinned catalog values,
    /// exactly as for the synchronous `prove_chain`. Returns the job id.
    #[msg(job)]
    async fn prove_chain_job(
        &mut self,
        _ctx: &mut Context<Self>,
        pvm_blob: Vec<u8>,
        witness_bytes: Vec<u8>,
        witness_addr: u64,
        seg_steps: u64,
        page_budget: u64,
        profile: Vec<u32>,
        reply_to: u32,
        reply_msg: Vec<u8>,
    ) -> u64 {
        let id = self.queue.begin();
        self.pending.push(PendingProve {
            id,
            reply_to,
            reply_msg,
            pvm_blob,
            witness_bytes,
            witness_addr,
            seg_steps,
            page_budget,
            profile,
        });
        id
    }

    /// Host periodic tick: advance AT MOST ONE pending prove job
    /// and, on completion, `tell` the requester.
    ///
    /// BLOCKING NOTE: proving runs SYNCHRONOUSLY here (a large-stack worker
    /// thread this tick drains segment-by-segment and then `join`s), so a tick
    /// that picks up a job blocks the extension for the whole (minutes-long)
    /// prove — `verify_chain` / `job_*` are served only BETWEEN jobs (an idle
    /// tick returns immediately), not during one. The async win is that the
    /// requester's `prove_chain_job` returns a job id at once instead of
    /// blocking on the prove; making the prove itself non-blocking (a
    /// background thread polled across ticks) is a further step a busy prover
    /// would want.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        // Publishing rides this task: the worker thread proves, and each
        // segment crossing the channel is `blob_put` here before the next is
        // accepted — so the job retains hashes, never proof bytes.
        let put = async |seg| ctx.blob_put(seg).await;
        let Some(cb) = advance_one_job(&mut self.pending, &mut self.queue, put).await else {
            return;
        };
        if cb.reply_to != 0 {
            let name = String::from_utf8_lossy(&cb.reply_msg).into_owned();
            let msg = vos::value::Msg::new(&name)
                .with("job_id", cb.job_id)
                .with("status", cb.status)
                .with("segments", cb.segments);
            ctx.tell(vos::abi::service::ServiceId(cb.reply_to), &msg);
        }
    }

    /// Drain an async prove job's output — the standard `job_poll` reply
    /// (`Args { data, done, error }`). For a completed job `data` is the
    /// anchored [`ChainManifest`] input ([`encode_chain_manifest_anchored`]
    /// bytes, `32·(N+1)` — the per-segment proofs are already in the host CAS,
    /// published by `tick` as they were proven); the requester CASes the
    /// manifest and ships its hash. `done` flips at the terminal state;
    /// `error` is non-empty on a failed prove or publish.
    #[msg]
    async fn job_poll(&mut self, _ctx: &mut Context<Self>, job_id: u64) -> Vec<u8> {
        self.queue.poll_reply(job_id).encode()
    }

    /// Drop a job, freeing its retained output AND its still-pending inputs
    /// (so a release before `tick` proves it cancels the prove instead of
    /// leaving orphaned inputs `advance_one_job` would still run into a
    /// discarded queue slot). Idempotent — returns `1` if the queue held the
    /// job, `0` if the id was already gone.
    #[msg]
    async fn job_release(&mut self, _ctx: &mut Context<Self>, job_id: u64) -> u8 {
        self.pending.retain(|p| p.id != job_id);
        u8::from(self.queue.release(job_id))
    }

    /// Measure the pinnable CATALOG fields for a provable PVM program — the
    /// heavy zkpvm work behind `vosx zk pin`. The CLI transpiles the ELF and
    /// reads `__VOS_WITNESS` itself (this extension stays a pure PVM prover,
    /// blob-in), then invokes this to measure:
    ///   * the ENTERING-IMAGE page-Merkle root over the UNPATCHED image
    ///     (diagnostic — see `ChainManifest::initial_root`),
    ///   * when `profile` is EMPTY, the canonical forcing profile itself
    ///     ([`zkpvm::canonical_profile_for`] over the witness run — same
    ///     derivation as `measure_floors`, from the one trace this
    ///     measurement already makes), and
    ///   * when a representative `witness_bytes` is supplied, the canonical
    ///     COMMITMENT allowlist (prove one segment per distinct canonical shape)
    ///     under the supplied-or-derived profile.
    ///
    /// Returns `image_root(32) ++ n(u32 LE) ++ profile(u32 LE × n) ++
    /// commitment(32)…` — the profile the measurement ran under is always
    /// echoed, so a deriving caller pins exactly what was measured. An empty
    /// `witness_bytes` (the `--allowlist` re-pin path, where the caller records
    /// a known allowlist) yields no commitments and skips all proving. Empty
    /// `Vec` on any failure. SYNCHRONOUS + heavy (minutes, tens of GB): a
    /// publish-time invoke, so the caller drives it with an extended timeout;
    /// it runs on this extension's own thread, so a busy measure doesn't
    /// freeze the node's other services.
    #[msg]
    async fn measure_catalog(
        &self,
        _ctx: &mut Context<Self>,
        pvm_blob: Vec<u8>,
        witness_bytes: Vec<u8>,
        witness_addr: u64,
        seg_steps: u64,
        page_budget: u64,
        profile: Vec<u32>,
        gas: u64,
    ) -> Vec<u8> {
        measure_catalog(
            &pvm_blob,
            &witness_bytes,
            witness_addr as usize,
            seg_steps as usize,
            page_budget as usize,
            &profile,
            gas,
        )
        .unwrap_or_default()
    }

    /// Derive the canonical forcing profile for `seg_steps`-step windows —
    /// the `profile` input `measure_catalog` and `prove_chain` consume.
    /// Traces the witness-injected run, segments it, and returns the
    /// per-chip elementwise MAX of every window's natural main-trace
    /// `log_size` (`[u32; zkpvm::chip_idx::COUNT]`). Trace + trace-gen only
    /// (no commit, no FRI), so it is far lighter than `measure_catalog` —
    /// but still minutes on a multi-million-step trace, so callers drive it
    /// with the same extended timeout. The floors are the observed
    /// per-window maxima for this witness's op pattern, not a proven bound;
    /// the drift guard + allowlist-coverage gate catch a reshaped
    /// transition. Empty list on any failure.
    #[msg]
    async fn measure_floors(
        &self,
        _ctx: &mut Context<Self>,
        pvm_blob: Vec<u8>,
        witness_bytes: Vec<u8>,
        witness_addr: u64,
        seg_steps: u64,
        page_budget: u64,
        gas: u64,
    ) -> Vec<u32> {
        measure_floors(
            &pvm_blob,
            &witness_bytes,
            witness_addr as usize,
            seg_steps as usize,
            page_budget as usize,
            gas,
        )
        .unwrap_or_default()
    }
}

// ── Core logic (Context-free, unit-testable) ─────────────────────────

/// The heavy measurement behind [`Prover::measure_catalog`] — traces + proves,
/// so it runs on a 512 MiB thread (a canonical prove overflows the default
/// ~2 MiB, same reason `verify` uses a large stack). Returns
/// `image_root(32) ++ n(u32 LE) ++ profile(u32 LE × n) ++ commitment(32)…`
/// (no commitments when `witness` is empty; the profile is derived when the
/// supplied one is empty); `None` on any failure.
pub fn measure_catalog(
    pvm_blob: &[u8],
    witness: &[u8],
    witness_addr: usize,
    seg_steps: usize,
    page_budget: usize,
    profile: &[u32],
    gas: u64,
) -> Option<Vec<u8>> {
    // Own everything on the heap so the large-stack thread is 'static.
    let pvm_blob = pvm_blob.to_vec();
    let witness = witness.to_vec();
    let profile = profile.to_vec();
    run_on_large_stack(move || {
        measure_catalog_inner(
            &pvm_blob,
            &witness,
            witness_addr,
            seg_steps,
            page_budget,
            &profile,
            gas,
        )
    })
}

fn measure_catalog_inner(
    pvm_blob: &[u8],
    witness: &[u8],
    witness_addr: usize,
    seg_steps: usize,
    page_budget: usize,
    profile: &[u32],
    gas: u64,
) -> Option<Vec<u8>> {
    if seg_steps == 0 {
        return None;
    }
    // Entering-image root over the UNPATCHED image (witness buffer all-zero):
    // trace with no patches and page-Merkle its initial memory. DIAGNOSTIC —
    // NOT the verifier's entering-image pin (a witness-injecting program's live
    // segment-0 root is the PATCHED root); see `ChainManifest::initial_root`.
    let unpatched = zkpvm::actor::trace_blob_compact(pvm_blob, gas)?;
    let image_root = zkpvm::page_merkle::image_root(&unpatched.initial_memory);
    drop(unpatched);
    // Measure the commitment allowlist only when a representative witness is
    // supplied; the `--allowlist` re-pin path passes an empty witness and
    // records its own already-trusted allowlist. An empty profile means
    // DERIVE it from the same witness trace the allowlist probe uses — one
    // trace serves both, and the echo below pins exactly what was measured.
    let mut floors = profile.to_vec();
    let mut commitments = Vec::new();
    if !witness.is_empty() {
        let full = trace_blob_compact(pvm_blob, witness, witness_addr, gas)?;
        let bounds = chain_bounds(&full, seg_steps, page_budget);
        if floors.is_empty() {
            floors = zkpvm::canonical_profile_for_bounds_compact(&full, &bounds)?;
        }
        commitments = measure_commitments(&full, &bounds, &floors)?;
    }
    let mut out = Vec::with_capacity(32 + 4 + floors.len() * 4 + commitments.len() * 32);
    out.extend_from_slice(&image_root);
    out.extend_from_slice(&(floors.len() as u32).to_le_bytes());
    for f in &floors {
        out.extend_from_slice(&f.to_le_bytes());
    }
    for c in &commitments {
        out.extend_from_slice(c);
    }
    Some(out)
}

/// Segment the traced witness run and prove one representative canonical
/// segment per distinct shape (seg 0, the last/short segment, and the
/// first segment of each distinct fixed-base-scalar-mult "comb" count), yielding
/// the distinct program commitments — the canonical allowlist. Mirrors the
/// federation e2e's `voucher_check_allowlist_coverage` probe so the pinned
/// allowlist is complete without proving all ~N segments. MUST run on a large
/// stack — reached via [`measure_catalog`]. `None` on any failure.
fn measure_commitments(
    full: &zkpvm::CompactTrace,
    bounds: &[(usize, usize)],
    profile: &[u32],
) -> Option<Vec<[u8; 32]>> {
    let n = bounds.len();
    if n == 0 {
        return None;
    }
    // Both passes ride a forward cursor over the compact holder — O(N)
    // total slicing instead of the per-window prefix replay's O(N²): the
    // comb scan walks every window in order; the probe pass (a fresh
    // cursor — the image can't rewind) skips straight between the sparse
    // probe windows.
    let mut scan = zkpvm::segment::CompactSegmentCursor::new(full);
    let comb_counts: Vec<usize> = bounds
        .iter()
        .map(|&(a, b)| scan.side_note(a, b).ristretto_comb_calls.len())
        .collect();

    // Probe seg 0, the last (possibly short) segment, and the first segment of
    // each distinct comb count — one representative per distinct canonical shape.
    let mut probe = std::collections::BTreeSet::new();
    probe.insert(0);
    probe.insert(n - 1);
    for i in 0..n {
        if comb_counts[..i].iter().all(|&x| x != comb_counts[i]) {
            probe.insert(i);
        }
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    let mut cursor = zkpvm::segment::CompactSegmentCursor::new(full);
    for i in probe {
        let (a, b) = bounds[i];
        let mut sn = cursor.side_note(a, b);
        let proof = prove_canonical(&mut sn, profile).ok()?;
        let c = zkpvm::recursion_pcs::commitment_bytes(&zkpvm::program_commitment_of_proof(&proof));
        if seen.insert(c) {
            out.push(c);
        }
    }
    Some(out)
}

/// The floors measurement behind [`Prover::measure_floors`] — trace-gen of
/// every component over every window, so it runs on a large-stack thread
/// like the other measure/prove paths. An empty `witness` traces the
/// unpatched image (a program that takes no witness); a witness-taking
/// program MUST supply a representative witness, because its empty-buffer
/// fallback path has a different execution shape and would yield the wrong
/// floors. `None` on any failure.
pub fn measure_floors(
    pvm_blob: &[u8],
    witness: &[u8],
    witness_addr: usize,
    seg_steps: usize,
    page_budget: usize,
    gas: u64,
) -> Option<Vec<u32>> {
    if seg_steps == 0 {
        return None;
    }
    let pvm_blob = pvm_blob.to_vec();
    let witness = witness.to_vec();
    run_on_large_stack(move || {
        let full = trace_blob_compact(&pvm_blob, &witness, witness_addr, gas)?;
        let bounds = chain_bounds(&full, seg_steps, page_budget);
        zkpvm::canonical_profile_for_bounds_compact(&full, &bounds)
    })
}

// ── Async job-queue logic (Context-free, unit-testable) ──────────────

/// What the tick handler should `tell` the requester after advancing a job.
struct JobCallback {
    /// Requester ServiceId (`0` = no callback).
    reply_to: u32,
    /// Dynamic `Msg` method name (UTF-8).
    reply_msg: Vec<u8>,
    /// The advanced job's id.
    job_id: u64,
    /// Terminal outcome code: [`JOB_DONE`] (`1`) or [`JOB_FAILED`] (`2`).
    status: u64,
    /// Segment count on success (`0` on failure).
    segments: u64,
}

/// Advance AT MOST ONE pending job: prove the FIFO-oldest job in `pending`
/// STREAMING — each proved segment is handed to `put` (the host CAS publish)
/// and only its 32-byte hash is retained — then push the job's result (the
/// anchored-manifest input, [`encode_chain_manifest_anchored`]) or failure
/// into `queue`, and return the callback intent (`None` when nothing is
/// pending). Generic over the async `put` so the prove→publish→state→callback
/// logic is unit-testable without a host `Context`; the tick handler passes
/// `ctx.blob_put`. A failed prove (unparseable blob / patch out of range /
/// prove error) or a failed publish resolves the job via `queue.fail(...)`
/// with no result.
async fn advance_one_job(
    pending: &mut Vec<PendingProve>,
    queue: &mut JobQueue,
    put: impl AsyncFnMut(Vec<u8>) -> Option<[u8; 32]>,
) -> Option<JobCallback> {
    if pending.is_empty() {
        return None;
    }
    // FIFO: take the oldest queued job (and its large blob) out of `pending`;
    // its inputs move into the prove worker and drop when it finishes.
    let job = pending.remove(0);
    let (status, segments) = match prove_chain_publishing(
        job.pvm_blob,
        job.witness_bytes,
        job.witness_addr as usize,
        job.seg_steps as usize,
        job.page_budget as usize,
        job.profile,
        put,
    )
    .await
    {
        Some((root, hashes)) => {
            queue.push(job.id, &encode_chain_manifest_anchored(root, &hashes));
            queue.finish(job.id);
            (JOB_DONE, hashes.len() as u64)
        }
        None => {
            queue.fail(job.id, "prove or publish failed");
            (JOB_FAILED, 0)
        }
    };
    Some(JobCallback {
        reply_to: job.reply_to,
        reply_msg: job.reply_msg,
        job_id: job.id,
        status,
        segments,
    })
}

/// Prove a canonical chain STREAMING ITS PROOFS OUT: the prove runs on a
/// large-stack worker thread ([`prove_chain_segments_with`]), each segment's
/// `bincode(Proof)` crosses a bounded channel to this task, which hands it to
/// `put` (the host CAS publish) and retains only the returned 32-byte hash.
/// Peak retention is therefore ~one segment in flight (the channel holds one
/// while the worker proves the next) instead of the whole chain. Returns
/// `(entering_root, segment_hashes)` — exactly the
/// [`encode_chain_manifest_anchored`] inputs; `None` on any failure. A failed
/// `put` drops the receiver, which fails the worker's next send and so aborts
/// the remaining prove instead of letting it run unobserved.
async fn prove_chain_publishing(
    pvm_blob: Vec<u8>,
    witness_bytes: Vec<u8>,
    witness_addr: usize,
    seg_steps: usize,
    page_budget: usize,
    profile: Vec<u32>,
    mut put: impl AsyncFnMut(Vec<u8>) -> Option<[u8; 32]>,
) -> Option<([u8; 32], Vec<[u8; 32]>)> {
    // Capacity 1 pipelines prove and publish without accumulation: the worker
    // proves segment i+1 while this task publishes segment i, and blocks once
    // the slot is full.
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let worker = spawn_on_large_stack(move || {
        prove_chain_segments_with(
            &pvm_blob,
            &witness_bytes,
            witness_addr,
            seg_steps,
            page_budget,
            &profile,
            |seg| tx.send(seg).ok(),
        )
    })?;
    let mut hashes = Vec::new();
    let mut publish_ok = true;
    while let Ok(seg) = rx.recv() {
        match put(seg).await {
            Some(h) => hashes.push(h),
            None => {
                publish_ok = false;
                break;
            }
        }
    }
    // Explicit for the failure path: dropping the receiver fails the worker's
    // next send, aborting the rest of the chain before the join below.
    drop(rx);
    let root = worker.join().ok()??;
    // The worker can finish (all segments sent) before a trailing publish
    // fails, so a successful join alone doesn't mean every hash landed.
    publish_ok.then_some((root, hashes))
}

/// The entering-image root of a proved chain: segment 0's
/// `initial_state.memory_root`. `None` if the chain is empty or segment 0 won't
/// decode. A producer feeds this to [`encode_chain_manifest_anchored`] so the
/// shipped manifest anchors segment 0 — the value `verify_chain` checks it
/// against. Serves producers holding already-proved segment bytes;
/// [`prove_chain_segments_with`] returns the same root directly.
pub fn segment_initial_root(segments: &[Vec<u8>]) -> Option<[u8; 32]> {
    let proof: Proof = bincode::deserialize(segments.first()?).ok()?;
    Some(proof.initial_state.memory_root)
}

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

/// [`trace_blob`] in chain form: the traced run as a [`zkpvm::CompactTrace`]
/// (steps without register snapshots, ~2.6× smaller resident) — what every
/// CHAIN path here holds across its segment loop, expanding one window at a
/// time via [`zkpvm::segment::CompactSegmentCursor`]. Single-proof paths
/// keep the full `SideNote`.
fn trace_blob_compact(
    pvm_blob: &[u8],
    witness_bytes: &[u8],
    witness_addr: usize,
    gas: u64,
) -> Option<zkpvm::CompactTrace> {
    if witness_bytes.is_empty() {
        zkpvm::actor::trace_blob_compact(pvm_blob, gas)
    } else {
        zkpvm::actor::trace_blob_compact_with_patches(
            pvm_blob,
            gas,
            &[(witness_addr, witness_bytes)],
        )
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
/// STREAMING each segment's `bincode(Proof)` bytes into `sink` as it is
/// proven (in chain order) and returning the chain's ENTERING-IMAGE root —
/// segment 0's `initial_state.memory_root`, the
/// [`encode_chain_manifest_anchored`] anchor. Trace, cut windows
/// ([`chain_bounds`]: uniform `seg_steps`, or content-budgeted when
/// `page_budget > 0`), prove each segment with [`zkpvm::prove_canonical`]
/// against the caller-supplied `profile`. The sink owns each segment's bytes
/// and decides their fate (publish to a CAS, collect, discard); returning
/// `None` from it ABORTS the remaining chain. `None` on any failure —
/// including a sink abort or an empty chain. Nothing is retained across
/// segments beyond the compact trace, so peak memory holds the trace + the
/// one segment in flight — the producer-side mirror of `verify_chain`'s
/// fetch-verify-drop streaming.
///
/// `seg_steps`, `page_budget`, and `profile` MUST match the values the
/// program's canonical commitment allowlist was measured/pinned against — a
/// different cut reshapes the segments and lands the chain on commitments
/// outside the published allowlist.
///
/// PER-SEGMENT DELIVERY: a producer sink content-addresses each segment
/// SEPARATELY (the host CAS — `put_proof_blob` / `ctx.blob_put`), then
/// assembles + CASes a [`ChainManifest`] of the hashes and ships the
/// manifest's single 32-byte hash as its protocol's proof reference
/// (unchanged wire shape — one hash). This keeps every cross-node blob under
/// the 8 MiB frame cap (`MAX_FRAME_BYTES`): one canonical segment proof is
/// ~3 MiB, whereas the single concatenated `bincode(Vec<Proof>)` chain blob
/// (~N × 3 MiB ≈ hundreds of MiB) is not deliverable in one frame. The
/// verifier re-assembles the chain by fetching each segment via the manifest
/// (see [`verify_chain_segments`]).
pub fn prove_chain_segments_with(
    pvm_blob: &[u8],
    witness_bytes: &[u8],
    witness_addr: usize,
    seg_steps: usize,
    page_budget: usize,
    profile: &[u32],
    mut sink: impl FnMut(Vec<u8>) -> Option<()>,
) -> Option<[u8; 32]> {
    if seg_steps == 0 {
        return None;
    }
    // The chain holder is the COMPACT trace — full register snapshots are
    // materialized only window-locally by the cursor, so the resident
    // floor under every segment prove is ~2.6× smaller than a full
    // `SideNote`'s.
    let full = trace_blob_compact(pvm_blob, witness_bytes, witness_addr, TRACE_GAS)?;
    let bounds = chain_bounds(&full, seg_steps, page_budget);
    let mut entering_root: Option<[u8; 32]> = None;
    // One forward cursor pass threads the entering memory image + register
    // file across the windows — O(N) total slicing instead of the
    // per-window prefix replay's O(N²).
    let mut cursor = zkpvm::segment::CompactSegmentCursor::new(&full);
    for (a, b) in bounds {
        let mut sn = cursor.side_note(a, b);
        let proof = prove_canonical(&mut sn, profile).ok()?;
        entering_root.get_or_insert(proof.initial_state.memory_root);
        sink(bincode::serialize(&proof).ok()?)?;
    }
    entering_root
}

/// [`prove_chain_segments_with`] with a collecting sink: returns the
/// per-segment `bincode(Proof)` bytes — one `Vec<u8>` per segment, in chain
/// order. Retains the WHOLE chain (~N × 3 MiB), so callers that publish or
/// verify per segment should prefer the sink form; this shape suits offline
/// verification over in-memory segments ([`verify_chain_segments`]). All
/// parameter contracts are the sink form's.
pub fn prove_chain_segments(
    pvm_blob: &[u8],
    witness_bytes: &[u8],
    witness_addr: usize,
    seg_steps: usize,
    page_budget: usize,
    profile: &[u32],
) -> Option<Vec<Vec<u8>>> {
    let mut segments: Vec<Vec<u8>> = Vec::new();
    prove_chain_segments_with(
        pvm_blob,
        witness_bytes,
        witness_addr,
        seg_steps,
        page_budget,
        profile,
        |seg| {
            segments.push(seg);
            Some(())
        },
    )?;
    Some(segments)
}

/// The chain's window cut: uniform `seg_steps` windows, or the content-budgeted
/// cut ([`zkpvm::segment::segment_bounds_budgeted_compact`]) when
/// `page_budget > 0`. Deterministic in `(trace, seg_steps, page_budget)` —
/// producer, catalog measurement, and re-measurement must all cut identically,
/// which is why the budget is pinned in the catalog beside `seg_steps` and the
/// profile (and why the budgeted walk is one code path across the full and
/// compact holders).
fn chain_bounds(
    full: &zkpvm::CompactTrace,
    seg_steps: usize,
    page_budget: usize,
) -> Vec<(usize, usize)> {
    if page_budget > 0 {
        zkpvm::segment::segment_bounds_budgeted_compact(full, seg_steps, page_budget)
    } else {
        zkpvm::segment::segment_bounds(full.num_steps(), seg_steps)
    }
}

/// A chain delivered as per-segment proof CAS hashes (in chain order) plus the
/// ENTERING-IMAGE root the chain must start from. The producer puts each segment
/// proof into the host proof-blob store SEPARATELY and lists the resulting
/// 32-byte hashes in [`Self::segments`]; the manifest is itself CASed and its
/// single hash rides in the caller's proof reference.
///
/// [`Self::initial_root`] is the entering-image ANCHOR: the page-Merkle root of
/// the RAM image segment 0 runs against (`zkpvm::page_merkle::image_root` over
/// the producer's initial image, which for an honest chain equals
/// `proofs[0].initial_state.memory_root`). [`verify_chain`] checks segment 0's
/// `initial_state.memory_root` against it — the memory analogue of the
/// allowlist's program-identity anchor. Without ANY anchor, allowlist membership
/// + boundary continuity + the final io-binding say nothing about the RAM the
/// entering segment starts from, so a chain running from a doctored initial image
/// slips through; binding segment 0 to the manifest's declared root closes that
/// (and brings the streaming path to parity with the library's
/// `verify_chain_standalone_allowlist`, which anchors the same way). The root is
/// content-addressed into the manifest (hence signed wherever the manifest hash
/// rides), so it is a COMMITTED, auditable part of the statement — but because a
/// producer builds it to match its own segment 0, the anchor's full teeth come
/// from a verifier that ALSO pins this root against the program's published
/// entering image (the `vosx zk pin` catalog's `unpatched_image_root`, modulo
/// the witness the live run injects). An all-zero `initial_root` is the "no
/// anchor" sentinel (a real image root is never all-zero) that the legacy
/// [`encode_chain_manifest`] carries, and the anchor check is then skipped — an
/// out-of-band-anchored deployment's opt-out.
///
/// Because the manifest is content-addressed, `initial_root` + the segment list
/// (count + order) are integrity-bound to the manifest hash — the value a caller
/// (e.g. a settlement bridge) ships as its single proof reference — so a verifier
/// that fetches and verifies EVERY listed segment, plus the entering-root anchor,
/// boundary continuity, and the final io-binding, cannot be fooled by a
/// truncated, reordered, spliced, or re-anchored manifest.
pub struct ChainManifest {
    /// Entering-image page-Merkle root anchor; the all-zero sentinel = unanchored.
    pub initial_root: [u8; 32],
    /// Per-segment proof CAS hashes, in chain order.
    pub segments: Vec<[u8; 32]>,
}

/// The all-zero "no entering-image anchor" sentinel (see [`ChainManifest`]).
/// A genuine page-Merkle image root is never all-zero, so it can't collide with
/// a real anchor.
const UNANCHORED_ROOT: [u8; 32] = [0u8; 32];

/// Encode an UNANCHORED [`ChainManifest`] — segment hashes with no
/// entering-image anchor (`initial_root` = the all-zero sentinel), so the
/// streaming verifier SKIPS the anchor check. Kept for callers that anchor the
/// entering image out-of-band; prefer [`encode_chain_manifest_anchored`] so a
/// chain spliced onto a doctored initial image is rejected. Tiny
/// (`32·(N+1)` bytes), so it always rides a single cross-node frame.
pub fn encode_chain_manifest(segment_hashes: &[[u8; 32]]) -> Vec<u8> {
    encode_chain_manifest_anchored(UNANCHORED_ROOT, segment_hashes)
}

/// Encode an ANCHORED [`ChainManifest`]: the entering-image page-Merkle root
/// followed by the per-segment proof CAS hashes (flat `[root:32][seg:32]…`).
/// [`verify_chain`] checks segment 0's `initial_state.memory_root` against
/// `initial_root`. Compute `initial_root` via `zkpvm::page_merkle::image_root`
/// over the initial image the chain was traced from — equivalently, the first
/// segment proof's `initial_state.memory_root`.
pub fn encode_chain_manifest_anchored(initial_root: [u8; 32], segment_hashes: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * (segment_hashes.len() + 1));
    out.extend_from_slice(&initial_root);
    for h in segment_hashes {
        out.extend_from_slice(h);
    }
    out
}

/// Decode a [`ChainManifest`] blob (`[initial_root:32][seg:32]…`). `None` on a
/// malformed blob — one whose length is not a positive multiple of 32 carrying a
/// root plus at least one segment (< 64 bytes, or not 32-aligned).
pub fn decode_chain_manifest(bytes: &[u8]) -> Option<ChainManifest> {
    if bytes.len() < 64 || bytes.len() % 32 != 0 {
        return None;
    }
    let mut chunks = bytes.chunks_exact(32);
    let mut initial_root = [0u8; 32];
    initial_root.copy_from_slice(chunks.next()?);
    let segments = chunks
        .map(|c| {
            let mut h = [0u8; 32];
            h.copy_from_slice(c);
            h
        })
        .collect();
    Some(ChainManifest { initial_root, segments })
}

/// Verify a chain delivered as per-segment proof bytes against the
/// caller-supplied `allowlist` (the concatenation of accepted 32-byte canonical
/// commitments, `32·N` bytes) and the asserted `(public_bytes, return_bytes)`.
/// Composes, per segment, these checks so none is meaningful without the
/// others:
///   1. allowlist membership — every segment's commitment must be in
///      `allowlist` (a foreign program matches no entry);
///   2. chain validity — per-segment STARK validity (`verify_standalone`,
///      MOBILE) + boundary continuity (each segment's `initial_state` equals
///      the previous segment's `final_state`);
///   2a. entering-image anchor — segment 0's `initial_state.memory_root` equals
///      the caller's `expected_initial_root` (via
///      [`verify_chain_segments_anchored`]; skipped in this un-anchored form);
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
    // No entering-image anchor — the caller anchors the entering image
    // out-of-band (or not at all). Use [`verify_chain_segments_anchored`] to
    // reject a chain spliced onto a doctored initial image.
    verify_chain_segments_anchored(allowlist_bytes, segment_blobs, None, public_bytes, return_bytes)
}

/// [`verify_chain_segments`] plus the entering-image anchor: when
/// `expected_initial_root` is `Some`, segment 0's `initial_state.memory_root`
/// must equal it (the offline mirror of the `verify_chain` handler's
/// manifest-carried anchor). `None` restores the un-anchored behaviour. See
/// [`ChainManifest::initial_root`] for why the anchor matters.
pub fn verify_chain_segments_anchored(
    allowlist_bytes: &[u8],
    segment_blobs: &[Vec<u8>],
    expected_initial_root: Option<[u8; 32]>,
    public_bytes: &[u8],
    return_bytes: &[u8],
) -> bool {
    // The allowlist is the concatenation of 32-byte commitments; empty or a
    // non-multiple-of-32 length can't be a valid allowlist.
    if allowlist_bytes.is_empty() || allowlist_bytes.len() % 32 != 0 {
        return false;
    }
    if segment_blobs.is_empty() || segment_blobs.len() > MAX_CHAIN_SEGMENTS {
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
            expected_initial_root,
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
    expected_initial_root: Option<[u8; 32]>,
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
    run_on_large_stack(move || {
        verify_one_segment(
            &blob,
            &allowlist,
            prev_final.as_ref(),
            expected_initial_root,
            is_last,
            &public,
            &return_bytes,
        )
    })
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
    expected_initial_root: Option<[u8; 32]>,
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
    } else if let Some(root) = expected_initial_root {
        // Entering-image anchor: the FIRST segment (no predecessor) must start
        // from the caller/manifest-declared entering root — the memory analogue
        // of the allowlist's program-identity anchor. This is what makes the
        // in-AIR page-Merkle binding of `initial_state.memory_root` count: it
        // rejects a chain spliced onto a doctored initial RAM image.
        if proof.initial_state.memory_root != root {
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

#[cfg(test)]
mod anchor_tests {
    //! Entering-image anchor accept/reject over ONE real proved segment — the
    //! cheap, non-`#[ignore]` counterpart to the heavy `voucher_check_chain_
    //! anchor_path`. Proving a tiny program yields a genuine `Proof` (real
    //! commitment + `initial_state.memory_root`); we then drive the SAME
    //! per-segment check `verify_chain` runs (`verify_segment_on_large_stack` →
    //! `verify_one_segment`) with `is_last = false`, so the io-binding is out of
    //! the picture and the entering root is the ONLY variable — isolating the
    //! anchor as the accept/reject cause.
    use super::*;
    use test_trace::straight_line_side_note;
    use zkpvm::prove_mobile;

    /// Prove a tiny 2-op program as one MOBILE segment; return its bincode(Proof)
    /// blob, its program commitment, and its entering-image root.
    fn tiny_segment() -> (Vec<u8>, CommitmentHash, [u8; 32]) {
        let mut sn = straight_line_side_note(2);
        let proof = prove_mobile(&mut sn).expect("prove tiny segment (MOBILE)");
        let commitment = proof.stark_proof.commitments[0];
        let root = proof.initial_state.memory_root;
        (bincode::serialize(&proof).expect("encode proof"), commitment, root)
    }

    #[test]
    fn entering_image_anchor_accepts_correct_rejects_wrong() {
        let (blob, commitment, root) = tiny_segment();
        let allowlist = vec![commitment];
        // Non-final segment (`is_last = false`) ⇒ no io-binding, so the entering
        // root is the only thing that changes across the three calls.
        let verify = |expected: Option<[u8; 32]>| {
            verify_segment_on_large_stack(blob.clone(), &allowlist, None, expected, false, &[], &[])
                .is_some()
        };
        assert!(verify(None), "no anchor must not reject (anchor is opt-in)");
        assert!(verify(Some(root)), "the correct entering root must pass the anchor");
        let mut wrong = root;
        wrong[0] ^= 0xFF;
        assert!(
            !verify(Some(wrong)),
            "a wrong entering root must reject — the deployed verify_chain anchor"
        );

        // End-to-end via the MANIFEST the handler decodes: an anchored manifest
        // declaring a mismatched entering root makes verify_chain reject segment
        // 0. This is the exact extraction `verify_chain` performs
        // (`(root != UNANCHORED).then_some(root)`), minus the CAS fetch.
        let manifest = decode_chain_manifest(&encode_chain_manifest_anchored(wrong, &[[7u8; 32]]))
            .expect("anchored manifest decodes");
        assert_eq!(manifest.initial_root, wrong);
        let handler_anchor =
            (manifest.initial_root != UNANCHORED_ROOT).then_some(manifest.initial_root);
        assert!(
            !verify(handler_anchor),
            "verify_chain rejects when the manifest declares a mismatched entering root"
        );
    }
}

#[cfg(test)]
mod test_trace {
    //! Shared tiny-trace fixture: a straight-line `Add64` program traced
    //! into a [`SideNote`] (or packaged as a JAR blob), small enough to
    //! prove in-test.
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::SideNote;
    use zkpvm::core::tracing::TracingPvm;

    /// The straight-line program bytes: `n_adds` `Add64` ops followed by
    /// `Trap`, plus the instruction-start bitmask.
    fn straight_line_code(n_adds: u8) -> (Vec<u8>, Vec<u8>) {
        let mut code = Vec::new();
        for imm in 1..=n_adds {
            code.extend_from_slice(&[Opcode::Add64 as u8, 0x10, imm]);
        }
        code.push(Opcode::Trap as u8);
        let mut bitmask = vec![0; code.len()];
        for i in (0..code.len()).step_by(3) {
            bitmask[i] = 1;
        }
        (code, bitmask)
    }

    /// Trace `n_adds` `Add64` ops followed by `Trap` into a `SideNote`.
    pub fn straight_line_side_note(n_adds: u8) -> SideNote {
        let (code, bitmask) = straight_line_code(n_adds);
        let mut regs = [0u64; PVM_REGISTER_COUNT];
        regs[0] = 100;
        regs[1] = 1;
        let mem = vec![0u8; 4 * 1024 * 1024];
        let pvm =
            Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, mem.clone(), 10_000, 25);
        let mut tracing = TracingPvm::new(pvm);
        assert_eq!(tracing.run(), javm::ExitReason::Trap);
        SideNote::new(tracing.into_trace(), code, bitmask).with_memory(mem)
    }

    /// The same straight-line program packaged as a JAR blob, so the
    /// deployed blob→trace→cut→prove chain pipeline
    /// (`prove_chain_segments_with` and the job path over it) runs
    /// end-to-end on a REAL, cheap program.
    pub fn straight_line_blob(n_adds: u8) -> Vec<u8> {
        let (code, bitmask) = straight_line_code(n_adds);
        javm::program::build_simple_blob(&code, &bitmask, &[])
    }
}

#[cfg(test)]
mod floors_tests {
    //! Floors derivation (`zkpvm::canonical_profile_for` behind
    //! `measure_floors`) — the derived profile must make a chain's windows
    //! collapse onto one commitment, and the blob/seg_steps paths must fail
    //! soft. The heavy real-program run (voucher-check floors per
    //! `seg_steps`) lives with the rest of the provenance gates in
    //! `vos/tests/elf_integration.rs`.
    use super::*;
    use test_trace::straight_line_side_note;

    #[test]
    fn windows_collapse_to_one_commitment_under_derived_floors() {
        // Canonical proving needs a large stack, same as the deployed paths.
        std::thread::Builder::new()
            .stack_size(512 * 1024 * 1024)
            .spawn(|| {
                let full = straight_line_side_note(6);
                let n = full.steps.len();
                let seg = n.div_ceil(2);
                let bounds = zkpvm::segment::segment_bounds(n, seg);
                assert_eq!(bounds.len(), 2, "the trace must split into two windows");

                let floors = zkpvm::canonical_profile_for(&full, seg).expect("floors derive");
                assert_eq!(floors.len(), zkpvm::chip_idx::COUNT);

                // Monotonicity: a window's events are a subset of the whole
                // trace's, so whole-trace naturals dominate windowed floors.
                let whole = zkpvm::canonical_profile_for(&full, n).expect("whole-trace floors");
                for (i, (w, f)) in whole.iter().zip(&floors).enumerate() {
                    assert!(w >= f, "chip {i}: whole-trace natural {w} < windowed floor {f}");
                }

                // The property the tool exists for: same-shape windows prove
                // to ONE canonical commitment under the derived floors.
                let commitments: Vec<_> = bounds
                    .iter()
                    .map(|&(a, b)| {
                        let mut sn = zkpvm::segment::segment_side_note(&full, a, b);
                        let proof = prove_canonical(&mut sn, &floors)
                            .expect("canonical prove under derived floors");
                        zkpvm::recursion_pcs::commitment_bytes(
                            &zkpvm::program_commitment_of_proof(&proof),
                        )
                    })
                    .collect();
                assert_eq!(
                    commitments[0], commitments[1],
                    "windows with equal comb counts must share one commitment"
                );
            })
            .expect("spawn")
            .join()
            .expect("join");
    }

    #[test]
    fn floors_fail_soft_on_bad_inputs() {
        assert_eq!(
            measure_floors(&[0xDE, 0xAD, 0xBE, 0xEF], &[], 0, 100, 0, 1_000),
            None,
            "an unparseable blob yields None, not a panic"
        );
        let full = straight_line_side_note(2);
        assert_eq!(
            zkpvm::canonical_profile_for(&full, 0),
            None,
            "seg_steps = 0 must refuse, not panic"
        );
    }
}

#[cfg(test)]
mod chain_stream_tests {
    //! Streaming chain prove ([`prove_chain_segments_with`]): the sink form
    //! must stream exactly the bytes the collecting form returns (canonical
    //! proving is deterministic), return segment 0's entering-image root,
    //! and honor a sink abort. Proves a real (tiny) straight-line chain, so
    //! it runs the deployed blob→trace→cut→prove pipeline end-to-end.
    use super::*;
    use test_trace::straight_line_blob;

    /// The tiny chain's fixed cut: 6 adds + trap = 7 steps, seg_steps 4 →
    /// two windows ([0,4), [4,7)) — enough for a root + a continuity edge.
    pub const SEG_STEPS: usize = 4;

    /// Derive the canonical floors for the tiny chain — the profile every
    /// prove in these tests runs under.
    pub fn tiny_floors(blob: &[u8]) -> Vec<u32> {
        measure_floors(blob, &[], 0, SEG_STEPS, 0, 1_000_000).expect("derive tiny-chain floors")
    }

    #[test]
    fn sink_streams_the_collected_chain_and_returns_segment_zeros_root() {
        // Canonical proving needs a large stack, same as the deployed paths.
        run_on_large_stack(move || {
            let blob = straight_line_blob(6);
            let floors = tiny_floors(&blob);

            let segments = prove_chain_segments(&blob, &[], 0, SEG_STEPS, 0, &floors)
                .expect("collecting chain prove");
            assert!(segments.len() >= 2, "the fixture must cut into a real chain");

            let mut streamed: Vec<Vec<u8>> = Vec::new();
            let root =
                prove_chain_segments_with(&blob, &[], 0, SEG_STEPS, 0, &floors, |seg| {
                    streamed.push(seg);
                    Some(())
                })
                .expect("streaming chain prove");

            assert_eq!(
                streamed, segments,
                "the sink must receive exactly the bytes the collect adapter returns"
            );
            assert_eq!(
                Some(root),
                segment_initial_root(&segments),
                "the returned entering root is segment 0's initial_state.memory_root"
            );
            Some(())
        })
        .expect("large-stack test body");
    }

    #[test]
    fn aborting_sink_cancels_the_chain() {
        run_on_large_stack(move || {
            let blob = straight_line_blob(6);
            let floors = tiny_floors(&blob);
            let mut calls = 0usize;
            let aborted = prove_chain_segments_with(&blob, &[], 0, SEG_STEPS, 0, &floors, |_seg| {
                calls += 1;
                None
            });
            assert_eq!(aborted, None, "a sink abort fails the whole chain prove");
            assert_eq!(calls, 1, "the abort stops the chain after the aborting segment");
            Some(())
        })
        .expect("large-stack test body");
    }
}

#[cfg(test)]
mod job_tests {
    //! Prover-specific async-job tests: `advance_one_job` drains the FIFO
    //! `pending` list, proves one job STREAMING its segments through the
    //! caller's `put`, and writes its outcome into the `JobQueue` (whose
    //! lifecycle is covered by `vos::jobs`). Bad-blob jobs fail fast at
    //! trace, so those stay cheap (no real STARK work); the streaming
    //! result-shape test proves a real tiny chain.
    use super::*;

    /// Drive a future to completion on this thread. The `put` futures these
    /// tests supply are immediately ready (and `prove_chain_publishing`'s
    /// channel recv blocks synchronously inside the poll, exactly as it does
    /// under the host tick), so a noop-waker poll loop suffices.
    fn block_on<F: core::future::Future>(fut: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let mut cx = Context::from_waker(Waker::noop());
        let mut fut = core::pin::pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn pending_job(id: u64, reply_to: u32, reply_msg: &[u8]) -> PendingProve {
        PendingProve {
            id,
            reply_to,
            reply_msg: reply_msg.to_vec(),
            // Not a valid PVM blob → proving fails fast at trace (cheap).
            pvm_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
            witness_bytes: Vec::new(),
            witness_addr: 0,
            seg_steps: 100,
            page_budget: 0,
            profile: Vec::new(),
        }
    }

    #[test]
    fn advance_drains_fifo() {
        let mut queue = JobQueue::new();
        let id1 = queue.begin();
        let id2 = queue.begin();
        let mut pending = vec![pending_job(id1, 0, b""), pending_job(id2, 0, b"")];

        // FIFO: the first-enqueued job is advanced first, and leaves `pending`.
        let cb1 = block_on(advance_one_job(&mut pending, &mut queue, async |_seg| {
            Some([0u8; 32])
        }))
        .expect("first job advances");
        assert_eq!(cb1.job_id, id1);
        assert_eq!(pending.len(), 1);
        let cb2 = block_on(advance_one_job(&mut pending, &mut queue, async |_seg| {
            Some([0u8; 32])
        }))
        .expect("second job advances");
        assert_eq!(cb2.job_id, id2);
        assert!(pending.is_empty());
    }

    #[test]
    fn empty_pending_advances_to_none() {
        let mut queue = JobQueue::new();
        let mut pending: Vec<PendingProve> = Vec::new();
        assert!(
            block_on(advance_one_job(&mut pending, &mut queue, async |_seg| {
                Some([0u8; 32])
            }))
            .is_none()
        );
    }

    #[test]
    fn release_before_advance_cancels_the_prove() {
        // Releasing a job before `tick` advances it must drop it from BOTH the
        // queue and the pending inputs (what job_release does), so the next
        // advance runs nothing — no orphaned prove into a discarded queue slot.
        let mut queue = JobQueue::new();
        let id = queue.begin();
        let mut pending = vec![pending_job(id, 0, b"")];
        pending.retain(|p| p.id != id);
        assert!(queue.release(id));
        assert!(
            block_on(advance_one_job(&mut pending, &mut queue, async |_seg| {
                Some([0u8; 32])
            }))
            .is_none()
        );
        assert!(pending.is_empty());
    }

    #[test]
    fn bad_blob_job_fails_and_emits_callback() {
        // A job whose blob is not a valid PVM blob: proving fails fast at trace,
        // so this stays cheap (no real STARK work) — the negative path a tick
        // takes when a prove can't complete. The publish is never reached.
        let mut queue = JobQueue::new();
        let id = queue.begin();
        let mut pending = vec![pending_job(id, 42, b"proved")];

        let mut puts = 0usize;
        let cb = block_on(advance_one_job(&mut pending, &mut queue, async |_seg| {
            puts += 1;
            Some([0u8; 32])
        }))
        .expect("the pending job is advanced");
        // The callback the tick handler `tell`s to the requester.
        assert_eq!(cb.reply_to, 42);
        assert_eq!(cb.reply_msg, b"proved");
        assert_eq!(cb.job_id, id);
        assert_eq!(cb.status, JOB_FAILED);
        assert_eq!(cb.segments, 0);
        assert_eq!(puts, 0, "a failed trace publishes nothing");
        assert!(pending.is_empty(), "the advanced job leaves `pending`");

        // The queue reports the failure via the standard job_poll surface.
        let (data, done, error) = queue.poll(id);
        assert!(data.is_empty(), "a failed job has no result bytes");
        assert!(done);
        assert!(!error.is_empty(), "a failed job carries an error message");
    }

    #[test]
    fn streamed_job_publishes_segments_and_results_in_manifest_input() {
        // The success path over a REAL tiny chain: every proved segment goes
        // through `put` (only its hash retained) and the job result is the
        // anchored-manifest input over exactly those hashes.
        let blob = super::test_trace::straight_line_blob(6);
        let floors = super::chain_stream_tests::tiny_floors(&blob);
        let seg_steps = super::chain_stream_tests::SEG_STEPS as u64;

        let mut queue = JobQueue::new();
        let id = queue.begin();
        let mut pending = vec![PendingProve {
            id,
            reply_to: 7,
            reply_msg: b"proved".to_vec(),
            pvm_blob: blob,
            witness_bytes: Vec::new(),
            witness_addr: 0,
            seg_steps,
            page_budget: 0,
            profile: floors,
        }];

        // Fake CAS: record each published segment, hand back hash [i+1; 32].
        let mut published: Vec<Vec<u8>> = Vec::new();
        let cb = block_on(advance_one_job(&mut pending, &mut queue, async |seg| {
            let n = published.len() as u8;
            published.push(seg);
            Some([n + 1; 32])
        }))
        .expect("the pending job is advanced");

        assert_eq!(cb.status, JOB_DONE);
        assert!(published.len() >= 2, "the fixture must cut into a real chain");
        assert_eq!(cb.segments as usize, published.len());

        let (data, done, error) = queue.poll(id);
        assert!(done);
        assert!(error.is_empty());
        let manifest =
            decode_chain_manifest(&data).expect("the job result is an anchored-manifest input");
        let expected_hashes: Vec<[u8; 32]> =
            (1..=published.len() as u8).map(|i| [i; 32]).collect();
        assert_eq!(
            manifest.segments, expected_hashes,
            "the manifest lists the published hashes in chain order"
        );
        assert_eq!(
            Some(manifest.initial_root),
            segment_initial_root(&published),
            "the manifest anchor is segment 0's entering-image root"
        );
    }

    #[test]
    fn failed_publish_fails_the_job() {
        // A `put` that refuses (host CAS unavailable) must fail the job — and
        // abort the remaining prove — rather than report success with proofs
        // nobody can fetch.
        let blob = super::test_trace::straight_line_blob(6);
        let floors = super::chain_stream_tests::tiny_floors(&blob);

        let mut queue = JobQueue::new();
        let id = queue.begin();
        let mut pending = vec![PendingProve {
            id,
            reply_to: 0,
            reply_msg: Vec::new(),
            pvm_blob: blob,
            witness_bytes: Vec::new(),
            witness_addr: 0,
            seg_steps: super::chain_stream_tests::SEG_STEPS as u64,
            page_budget: 0,
            profile: floors,
        }];

        let mut puts = 0usize;
        let cb = block_on(advance_one_job(&mut pending, &mut queue, async |_seg| {
            puts += 1;
            None
        }))
        .expect("the pending job is advanced");
        assert_eq!(cb.status, JOB_FAILED);
        assert_eq!(cb.segments, 0);
        assert_eq!(puts, 1, "the first refused publish aborts the chain");
        let (_, done, error) = queue.poll(id);
        assert!(done);
        assert!(!error.is_empty(), "a failed publish reports through job_poll");
    }

    #[test]
    fn entering_root_rejects_empty_and_undecodable_chains() {
        assert_eq!(segment_initial_root(&[]), None, "an empty chain has no entering root");
        assert_eq!(
            segment_initial_root(&[vec![0xABu8; 16]]),
            None,
            "an undecodable segment 0 yields None, not a panic"
        );
    }

    #[test]
    fn measure_catalog_rejects_garbage_blob() {
        // A non-PVM blob fails fast at trace (no STARK work), so this stays
        // cheap — the negative path `measure_catalog` returns on a bad blob.
        assert_eq!(
            measure_catalog(&[0xDE, 0xAD, 0xBE, 0xEF], &[], 0, 100, 0, &[], 1_000),
            None,
            "an unparseable blob yields None, not a panic"
        );
    }
}
