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
//!   node can verify a many-hundred-segment chain). The chain `manifest` also
//!   carries the ENTERING-IMAGE root, which segment 0 is anchored to (the memory
//!   analogue of the allowlist — closes the doctored-initial-image splice).
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

/// Defensive ceiling on the number of segments a chain manifest may list.
/// A verifier fetches + STARK-verifies every listed segment, so an
/// oversized manifest is an unbounded-work (DoS) lever. Legitimate chains
/// are tens of segments (the conservation transition is ~76); this cap is
/// far above any real chain — a belt-and-suspenders bound over the invoke's
/// own gas metering. Bump it if a deployment segments a genuinely larger
/// batch.
const MAX_CHAIN_SEGMENTS: usize = 65_536;

// ── Async prove jobs ────────────────────────────────────────────
//
// `prove_chain` is a SYNCHRONOUS gas-metered invoke: a caller that asks it
// blocks for the whole (minutes-long) canonical chain prove, which no real
// actor dispatch can wait out. The async path decouples proving from the ask:
// `prove_chain_async` enqueues a job and returns a job id IMMEDIATELY; a later
// host `tick()` advances one job (proving on a large-stack thread), records the
// per-segment proof bytes + the entering-image root, and TELLS the requester a
// callback carrying the job id. The requester then pulls the result
// (`job_result`) and content-addresses it into the host proof-blob store.
//
// PUBLISH SPLIT: the extension cannot itself CAS-`put` (the host exposes only
// `blob_get` to extensions — a `put` effect is host-side, `node.rs`-owned). So
// the worker PRODUCES the segment bytes + a ready-to-anchor manifest input
// (segments + entering root) and the node-side requester PUBLISHES them via
// `VosNode::put_proof_blob` + `encode_chain_manifest_anchored` — exactly the
// steps the federation e2e already runs after a synchronous prove, now off the
// ask path. When a host `blob_put` effect lands (Workstream A), `tick()` can
// publish directly and callback the manifest hash instead.

/// Lifecycle of an async prove job. `#[repr(u8)]` + rkyv because it is
/// wire-carried in the persisted [`ProveJob`] (reordering variants would shift
/// the bytes any peer decodes). "Unknown" is deliberately NOT a variant — it is
/// a query-boundary concern (an id never enqueued, or already released),
/// surfaced by `job_state` as [`JOB_STATUS_UNKNOWN`].
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Copy, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum JobStatus {
    /// Queued, not yet proved.
    Pending = 0,
    /// Proved; result bytes retained for `job_result`.
    Done = 1,
    /// Prove failed (bad blob / patch / prove error); result empty.
    Failed = 2,
}

/// `job_state` reply for an id that isn't (or is no longer) queued — a
/// query-boundary sentinel distinct from the three real [`JobStatus`] codes.
const JOB_STATUS_UNKNOWN: u8 = 255;

/// One async prove-chain job. Inputs (`pvm_blob`/`witness_bytes`/`profile`) are
/// retained only while `Pending` and cleared once the job resolves, so a `Done`
/// job holds just its `result`. `result` (set on `Done`) is
/// `bincode((initial_root: [u8; 32], segments: Vec<Vec<u8>>))` — the entering
/// root the requester feeds to [`encode_chain_manifest_anchored`] and the
/// per-segment proof bytes it content-addresses.
#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Clone, Debug, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
pub struct ProveJob {
    /// Monotonic job id (returned by `prove_chain_async`).
    pub id: u64,
    /// Lifecycle code — see [`JobStatus`].
    pub status: JobStatus,
    /// ServiceId to callback on completion (`0` = no callback).
    pub reply_to: u32,
    /// Dynamic `Msg` method name (UTF-8) to send the callback as.
    pub reply_msg: Vec<u8>,
    /// Transpiled PVM blob to prove (cleared once resolved).
    pub pvm_blob: Vec<u8>,
    /// Opaque witness to inject at `witness_addr` (cleared once resolved).
    pub witness_bytes: Vec<u8>,
    /// `__VOS_WITNESS` flat-memory address.
    pub witness_addr: u64,
    /// Per-segment step bound for canonical proving.
    pub seg_steps: u64,
    /// Canonical forcing profile (cleared once resolved).
    pub profile: Vec<u32>,
    /// `bincode((initial_root, segments))` once `DONE`; empty otherwise.
    pub result: Vec<u8>,
}

#[actor]
struct Prover {
    /// Async prove-job queue. `prove_chain_async` pushes here; `tick()`
    /// advances one job per tick and callbacks the requester.
    jobs: Vec<ProveJob>,
    /// Next job id to hand out (monotonic, never reused within a run).
    next_job_id: u64,
}

#[messages]
impl Prover {
    fn new() -> Self {
        Prover {
            jobs: Vec::new(),
            next_job_id: 1,
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
    /// `profile`, and returns `bincode(Vec<Vec<u8>>)` — the per-segment
    /// `bincode(Proof)` bytes (one entry per segment, in chain order). Empty
    /// `Vec` on any failure.
    ///
    /// The caller content-addresses each segment SEPARATELY (`put_proof_blob`),
    /// assembles + CASes a [`ChainManifest`] of the hashes, and ships the
    /// manifest's single 32-byte hash wherever its protocol carries a proof
    /// reference (unchanged wire shape — one hash). Per-segment delivery keeps
    /// every cross-node blob under the 8 MiB frame cap, which the single
    /// concatenated chain blob cannot. Heavy + offline (the producer proves
    /// before shipping).
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

    /// ASYNC analog of `prove_chain`: enqueue a canonical-chain prove job
    /// and return a job id IMMEDIATELY, without blocking the caller for the
    /// (minutes-long) prove. A later host `tick()` proves the job and TELLS
    /// `reply_to` the dynamic message named `reply_msg` carrying
    /// `{job_id, status, segments}` (skipped when `reply_to == 0`). The
    /// requester then pulls the result with `job_result` and content-addresses
    /// it (see the module's async-jobs note on the publish split).
    ///
    /// `seg_steps` + `profile` MUST match the program's pinned catalog values,
    /// exactly as for the synchronous `prove_chain`. Returns the job id.
    #[msg]
    async fn prove_chain_async(
        &mut self,
        _ctx: &mut Context<Self>,
        pvm_blob: Vec<u8>,
        witness_bytes: Vec<u8>,
        witness_addr: u64,
        seg_steps: u64,
        profile: Vec<u32>,
        reply_to: u32,
        reply_msg: Vec<u8>,
    ) -> u64 {
        let id = self.next_job_id;
        self.next_job_id = self.next_job_id.wrapping_add(1);
        self.jobs.push(ProveJob {
            id,
            status: JobStatus::Pending,
            reply_to,
            reply_msg,
            pvm_blob,
            witness_bytes,
            witness_addr,
            seg_steps,
            profile,
            result: Vec::new(),
        });
        id
    }

    /// Host periodic tick: advance AT MOST ONE pending prove job
    /// and, on completion, `tell` the requester.
    ///
    /// BLOCKING NOTE: proving runs SYNCHRONOUSLY here (a large-stack thread this
    /// tick `join`s), so a tick that picks up a job blocks the extension for the
    /// whole (minutes-long) prove — `verify_chain` / `job_*` are served only
    /// BETWEEN jobs (an idle tick returns immediately), not during one. The async
    /// win B8 delivers is that the requester's `prove_chain_async` returns a job
    /// id at once instead of blocking on the prove; making the prove itself
    /// non-blocking (a background thread polled across ticks) is a further step
    /// that a busy prover would want.
    #[msg]
    async fn tick(&mut self, ctx: &mut Context<Self>) {
        let Some(cb) = advance_one_job(&mut self.jobs) else {
            return;
        };
        if cb.reply_to != 0 {
            let name = String::from_utf8_lossy(&cb.reply_msg).into_owned();
            let msg = vos::value::Msg::new(&name)
                .with("job_id", cb.job_id)
                .with("status", cb.status as u64)
                .with("segments", cb.segments);
            ctx.tell(vos::abi::service::ServiceId(cb.reply_to), &msg);
        }
    }

    /// Poll an async prove job's state as a [`JobStatus`] byte
    /// (`Pending`=0 / `Done`=1 / `Failed`=2), or [`JOB_STATUS_UNKNOWN`] (`255`)
    /// for an id that isn't queued (never enqueued, or already `job_release`d).
    /// (Named `job_state` so the handler's generated `JobState` message type
    /// doesn't collide with the [`JobStatus`] enum.)
    #[msg]
    async fn job_state(&self, _ctx: &mut Context<Self>, job_id: u64) -> u8 {
        job_status_of(&self.jobs, job_id)
    }

    /// Fetch a `DONE` job's result — `bincode((initial_root: [u8; 32],
    /// segments: Vec<Vec<u8>>))`. The requester decodes it, `put_proof_blob`s
    /// each segment, and builds the anchored manifest with
    /// [`encode_chain_manifest_anchored`] over `initial_root`. Empty `Vec` if
    /// the job is unknown or not yet `DONE` (poll `job_state` first).
    #[msg]
    async fn job_result(&self, _ctx: &mut Context<Self>, job_id: u64) -> Vec<u8> {
        job_result_of(&self.jobs, job_id)
    }

    /// Drop a finished job, freeing its retained result. Idempotent — returns
    /// `1` if a job was removed, `0` if the id was already gone. The requester
    /// calls this once it has pulled + published the result.
    #[msg]
    async fn job_release(&mut self, _ctx: &mut Context<Self>, job_id: u64) -> u8 {
        u8::from(release_job(&mut self.jobs, job_id))
    }
}

// ── Core logic (Context-free, unit-testable) ─────────────────────────

// ── Async job-queue logic (Context-free, unit-testable) ──────────────

/// Index of the first `Pending` job, or `None` if the queue has none.
fn next_pending_index(jobs: &[ProveJob]) -> Option<usize> {
    jobs.iter().position(|j| j.status == JobStatus::Pending)
}

/// Status byte of `job_id`, or [`JOB_STATUS_UNKNOWN`] if it isn't queued.
fn job_status_of(jobs: &[ProveJob], job_id: u64) -> u8 {
    jobs.iter()
        .find(|j| j.id == job_id)
        .map_or(JOB_STATUS_UNKNOWN, |j| j.status as u8)
}

/// A `Done` job's result bytes, or empty if the id is unknown or not yet `Done`.
fn job_result_of(jobs: &[ProveJob], job_id: u64) -> Vec<u8> {
    jobs.iter()
        .find(|j| j.id == job_id && j.status == JobStatus::Done)
        .map(|j| j.result.clone())
        .unwrap_or_default()
}

/// Remove `job_id` from the queue; `true` if a job was dropped, `false` if the
/// id was already gone (idempotent release).
fn release_job(jobs: &mut Vec<ProveJob>, job_id: u64) -> bool {
    let before = jobs.len();
    jobs.retain(|j| j.id != job_id);
    jobs.len() != before
}

/// What the tick handler should `tell` the requester after advancing a job.
struct JobCallback {
    /// Requester ServiceId (`0` = no callback).
    reply_to: u32,
    /// Dynamic `Msg` method name (UTF-8).
    reply_msg: Vec<u8>,
    /// The advanced job's id.
    job_id: u64,
    /// Terminal status ([`JobStatus::Done`] / [`JobStatus::Failed`]).
    status: JobStatus,
    /// Segment count on success (`0` on failure).
    segments: u64,
}

/// Advance AT MOST ONE pending job: prove it (freeing its inputs), record the
/// terminal status + retained result, and return the callback intent (`None`
/// when the queue has no pending job). Context-free so the prove→status→callback
/// logic is unit-testable; the handler performs the actual `tell`. A failed
/// prove (unparseable blob / patch out of range / prove error) resolves the job
/// to [`JobStatus::Failed`] with an empty result.
fn advance_one_job(jobs: &mut [ProveJob]) -> Option<JobCallback> {
    let i = next_pending_index(jobs)?;
    // Move the inputs out so the (large) blob isn't held twice and the resolved
    // job retains only its result.
    let job_id = jobs[i].id;
    let reply_to = jobs[i].reply_to;
    let reply_msg = core::mem::take(&mut jobs[i].reply_msg);
    let pvm_blob = core::mem::take(&mut jobs[i].pvm_blob);
    let witness_bytes = core::mem::take(&mut jobs[i].witness_bytes);
    let witness_addr = jobs[i].witness_addr as usize;
    let seg_steps = jobs[i].seg_steps as usize;
    let profile = core::mem::take(&mut jobs[i].profile);

    let (status, segments) =
        match run_prove_chain_job(&pvm_blob, &witness_bytes, witness_addr, seg_steps, &profile) {
            Some((root, segments)) => {
                let n = segments.len() as u64;
                match bincode::serialize(&(root, segments)) {
                    Ok(result) => {
                        jobs[i].result = result;
                        jobs[i].status = JobStatus::Done;
                        (JobStatus::Done, n)
                    }
                    Err(_) => {
                        jobs[i].status = JobStatus::Failed;
                        (JobStatus::Failed, 0)
                    }
                }
            }
            None => {
                jobs[i].status = JobStatus::Failed;
                (JobStatus::Failed, 0)
            }
        };
    Some(JobCallback { reply_to, reply_msg, job_id, status, segments })
}

/// Prove a queued chain job on a large stack, returning `(entering_root,
/// per-segment proof bytes)`. `None` on any failure. Mirrors the synchronous
/// `prove_chain` path; the entering root is read back from segment 0's proof so
/// the requester can anchor the manifest ([`encode_chain_manifest_anchored`]).
/// A canonical prove overflows the default stack (same reason `verify` uses a
/// large-stack thread), so it runs on its own 512 MiB thread.
fn run_prove_chain_job(
    pvm_blob: &[u8],
    witness_bytes: &[u8],
    witness_addr: usize,
    seg_steps: usize,
    profile: &[u32],
) -> Option<([u8; 32], Vec<Vec<u8>>)> {
    let pvm_blob = pvm_blob.to_vec();
    let witness_bytes = witness_bytes.to_vec();
    let profile = profile.to_vec();
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(move || {
            let segments =
                prove_chain_segments(&pvm_blob, &witness_bytes, witness_addr, seg_steps, &profile)?;
            let root = segment_initial_root(&segments)?;
            Some((root, segments))
        })
        .ok()?
        .join()
        .ok()?
}

/// The entering-image root of a proved chain: segment 0's
/// `initial_state.memory_root`. `None` if the chain is empty or segment 0 won't
/// decode. A producer feeds this to [`encode_chain_manifest_anchored`] so the
/// shipped manifest anchors segment 0 — the value `verify_chain` checks it
/// against.
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
/// CASes the manifest, and ships the manifest's single 32-byte hash as its
/// protocol's proof reference (unchanged wire shape — one hash). This keeps
/// every cross-node blob under the 8 MiB frame cap (`MAX_FRAME_BYTES`): one
/// canonical segment proof is
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
    std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(move || {
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
    use javm::PVM_REGISTER_COUNT;
    use javm::instruction::Opcode;
    use javm::interpreter::Interpreter;
    use zkpvm::core::tracing::TracingPvm;
    use zkpvm::{SideNote, prove_mobile};

    /// Prove a tiny 2-op program as one MOBILE segment; return its bincode(Proof)
    /// blob, its program commitment, and its entering-image root.
    fn tiny_segment() -> (Vec<u8>, CommitmentHash, [u8; 32]) {
        let code = vec![
            Opcode::Add64 as u8, 0x10, 2,
            Opcode::Add64 as u8, 0x12, 3,
            Opcode::Trap as u8,
        ];
        let bitmask = vec![1, 0, 0, 1, 0, 0, 1];
        let mut regs = [0u64; PVM_REGISTER_COUNT];
        regs[0] = 100;
        regs[1] = 1;
        let mem = vec![0u8; 4 * 1024 * 1024];
        let pvm = Interpreter::new(code.clone(), bitmask.clone(), vec![], regs, mem.clone(), 10_000, 25);
        let mut tracing = TracingPvm::new(pvm);
        assert_eq!(tracing.run(), javm::ExitReason::Trap);
        let steps = tracing.into_trace();
        let mut sn = SideNote::new(steps, code, bitmask).with_memory(mem);
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
mod job_tests {
    //! Async prove-job state-machine unit tests. Exercise the Context-free
    //! queue logic — enqueue → pick → complete/fail → poll → release — without a
    //! runtime or any real proving (the heavy prove path rides the existing
    //! `prove_chain_segments` coverage).
    use super::*;

    fn pending(id: u64) -> ProveJob {
        ProveJob {
            id,
            status: JobStatus::Pending,
            reply_to: 0,
            reply_msg: Vec::new(),
            pvm_blob: vec![1, 2, 3],
            witness_bytes: Vec::new(),
            witness_addr: 0,
            seg_steps: 100,
            profile: Vec::new(),
            result: Vec::new(),
        }
    }

    #[test]
    fn queue_lifecycle_enqueue_complete_poll_release() {
        let mut jobs = vec![pending(1), pending(2)];
        // FIFO: the first pending job is picked.
        assert_eq!(next_pending_index(&jobs), Some(0));

        // Complete job 1 (as `tick` does): retain result, free inputs.
        jobs[0].status = JobStatus::Done;
        jobs[0].result = vec![9, 9, 9];
        jobs[0].pvm_blob = Vec::new();
        // Now the next pending job is 2.
        assert_eq!(next_pending_index(&jobs), Some(1));

        // Status + result lookups (status byte = the JobStatus discriminant).
        assert_eq!(job_status_of(&jobs, 1), JobStatus::Done as u8);
        assert_eq!(job_status_of(&jobs, 2), JobStatus::Pending as u8);
        assert_eq!(job_status_of(&jobs, 999), JOB_STATUS_UNKNOWN);
        assert_eq!(job_result_of(&jobs, 1), vec![9, 9, 9]);
        assert!(job_result_of(&jobs, 2).is_empty(), "a pending job has no result yet");
        assert!(job_result_of(&jobs, 999).is_empty(), "an unknown job has no result");

        // Release is idempotent and drops the job.
        assert!(release_job(&mut jobs, 1));
        assert!(!release_job(&mut jobs, 1), "releasing twice is a no-op");
        assert_eq!(job_status_of(&jobs, 1), JOB_STATUS_UNKNOWN, "a released job is gone");
        assert_eq!(next_pending_index(&jobs), Some(0), "job 2 is still pending");
    }

    #[test]
    fn failed_job_is_terminal_and_resultless() {
        let mut j = pending(7);
        j.status = JobStatus::Failed;
        let jobs = vec![j];
        assert_eq!(next_pending_index(&jobs), None, "a failed job is never re-run");
        assert_eq!(job_status_of(&jobs, 7), JobStatus::Failed as u8);
        assert!(job_result_of(&jobs, 7).is_empty(), "a failed job exposes no result");
    }

    #[test]
    fn empty_queue_has_nothing_pending() {
        let jobs: Vec<ProveJob> = Vec::new();
        assert_eq!(next_pending_index(&jobs), None);
        assert_eq!(job_status_of(&jobs, 1), JOB_STATUS_UNKNOWN);
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
    fn bad_blob_job_fails_and_emits_callback() {
        // A job whose blob is not a valid PVM blob: proving fails fast at trace,
        // so this stays cheap (no real STARK work) — the negative path a tick
        // takes when a prove can't complete.
        let mut jobs = vec![ProveJob {
            id: 5,
            status: JobStatus::Pending,
            reply_to: 42,
            reply_msg: b"proved".to_vec(),
            pvm_blob: vec![0xDE, 0xAD, 0xBE, 0xEF],
            witness_bytes: Vec::new(),
            witness_addr: 0,
            seg_steps: 100,
            profile: Vec::new(),
            result: Vec::new(),
        }];
        let cb = advance_one_job(&mut jobs).expect("the pending job is advanced");
        // The job resolved to Failed with no retained result.
        assert_eq!(jobs[0].status, JobStatus::Failed);
        assert_eq!(job_status_of(&jobs, 5), JobStatus::Failed as u8);
        assert!(job_result_of(&jobs, 5).is_empty(), "a failed job retains no result");
        // The tick handler `tell`s exactly this callback to the requester.
        assert_eq!(cb.reply_to, 42);
        assert_eq!(cb.reply_msg, b"proved");
        assert_eq!(cb.job_id, 5);
        assert_eq!(cb.status, JobStatus::Failed);
        assert_eq!(cb.segments, 0);
        // No pending work remains.
        assert_eq!(next_pending_index(&jobs), None);
    }
}
