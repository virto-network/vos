//! VosRuntime — thin native host driving VOS services.
//!
//! Manages per-service invocations of the JAVM `InvocationKernel`,
//! handles protocol-cap hostcalls, and routes cross-service transfers
//! across ticks.
//!
//! ## Execution model (JAM-aligned, refine-only top level)
//!
//! The JAVM kernel runs a single entry at PC=0 — the JAR refine body.
//! VOS drives top-level services exclusively in refine:
//!
//!   * **Refine is the hot loop.** State-mutating hostcalls issued
//!     during refine (`WRITE`, `TRANSFER`, `PROVIDE`, `PREIMAGE_PROVIDE`)
//!     are **journaled** by the runtime, not applied immediately. The
//!     framework instead buffers them into the guest's halt
//!     `RefinePayload` — post-dispatch actor state included, as an
//!     ordinary final `Write{STATE_KEY}` effect — which the runtime
//!     verifies and absorbs into the same journal
//!     ([`absorb_work_result`]). There is no host state special-case:
//!     the work-result bytes are the whole truth.
//!   * **The anchor chain.** Each v3 work-result carries an anchor
//!     committing to the state it ran against. The host checks it
//!     against the *effective* state — the journal-overlay view
//!     ([`RefineJournal::journaled_read`]) falling back to committed
//!     storage — because one tick runs up to [`MAX_REFINE_ITERATIONS`]
//!     re-entries whose work-results chain: iteration N anchors the hash
//!     of iteration N−1's final state, which only reaches storage at end
//!     of tick. A mismatch rejects the work-result whole: nothing from
//!     it applies, its reply is dropped so the caller retries, and the
//!     guest is cold-restarted (warm holder dropped). Mid-chain,
//!     iterations before the rejected one stand.
//!   * **The journal drain is the commit boundary — accumulate on VOS.**
//!     After refine halts, the runtime replays the journal directly:
//!     writes flush to storage, preimages land in the preimage map,
//!     transfers join `pending_transfers` for the next tick. There is no
//!     second PVM invocation — the native drain is an *optimization of*
//!     the byte-defined apply semantic in `crate::refine_payload`, which
//!     a guest APPLY on a JAM host executes identically.
//!
//! This keeps refine bounded and deterministic while still honoring the
//! JAM invariant that all state mutation is structurally one commit.
//! When on-chain bridging lands, journaled cross-service transfers will
//! be routed to a pallet submission instead of `pending_transfers`.
//!
//! Version negotiation: the host dispatches on the payload's leading
//! version byte. `0x02` blobs (already installed) get legacy handling —
//! the decoder synthesizes their state field into a final
//! `Write{STATE_KEY}` and anchor checks are skipped. `0x03` is what the
//! framework emits. Unknown versions and malformed payloads fail loud
//! (treated like a trapped dispatch), never silently as defaults.
//!
//! Self-directed transfers (a service sending to itself) become
//! **intra-round re-entries**: the runtime re-invokes the same service
//! at PC=0 with the self-messages as fresh FETCH items, capped by
//! [`MAX_REFINE_ITERATIONS`] per tick to guard against guest loops.
//!
//! Nested `INVOKE` children also run at PC=0 under the same refine
//! policy; their effects merge into the parent's journal.
//!
//! ## Continuations (host-side warm restart)
//!
//! When a service's refine sets `continue_next = true` (a `yield_now` /
//! `sleep` handler), the runtime:
//!
//!   * already holds the actor's serialized state — the guest emits a
//!     `Write{STATE_KEY}` effect on every state-changing dispatch, not
//!     just on yield — so a cold restart at PC=0 rehydrates it via
//!     `READ`; and
//!   * captures `flat_mem` into the [`DataLayer`] with a
//!     [`ContinuationHeader`](crate::pvm_image::ContinuationHeader) so
//!     the next tick restores the kernel via `InvocationKernel::new_warm`
//!     — the guest's `ACTOR_HOLDER` static is already populated and it
//!     skips the `READ` + deserialize.
//!
//! Continuation header saves/clears are VOS host bookkeeping: written
//! directly to [`ServiceStorage`], never through the journal, never
//! targeting `STATE_KEY` — they are not part of any work-result and must
//! not shadow one. The warm-restart overlay is a top-level-service
//! optimization only (invoke children always cold-start via
//! `new_cached`); its absence never changes semantics. There is no
//! automatic wake-up: a service that yielded with nothing left to do
//! under its own steam is resumed by the next external message
//! (typically a parent agent's INVOKE).
//!
//! ## Memory model
//!
//! VOS guests pass flat virtual addresses in φ[7..=11] (RISC-V ABI
//! `a0..=a4`). The runtime reads/writes those buffers via the kernel's
//! address-based window helpers — [`InvocationKernel::read_data_cap_window`]
//! and [`InvocationKernel::write_data_cap_window`] — which resolve the
//! covering DATA cap internally. The declared object cap in φ[12]
//! (grey-transpiler emits the stack cap, slot 65, by default) is
//! therefore ceremonial for VOS: cap dispatch is done by the kernel
//! over the flat window, not the φ[12] value.

use crate::abi::error;
use crate::abi::hostcall;
use crate::abi::service::ServiceId;
use javm::kernel::{InvocationKernel, KernelResult};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use tracing::error;

use crate::data_layer::{DataLayer, MemoryDataLayer};
use crate::refine_payload::{Effect, RefinePayload};

type Gas = u64;

const DEFAULT_GAS: Gas = 100_000_000;
const MAX_INVOKE_DEPTH: usize = 8;
/// Hard cap on how many refine re-entries a single service may accrue
/// inside one `tick()` via self-directed transfers. Protects the
/// runtime from a misbuilt guest that self-schedules forever.
const MAX_REFINE_ITERATIONS: usize = 64;

/// Gas budget for one service tick.
#[derive(Debug, Clone, Copy)]
pub struct GasConfig {
    /// Maximum gas a single refine invocation may burn.
    pub refine_gas: Gas,
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            refine_gas: DEFAULT_GAS,
        }
    }
}

// --- Kernel memory helpers (flat-address window) ---

fn kread(k: &InvocationKernel, addr: u32, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    k.read_data_cap_window(addr, len as u32).unwrap_or_default()
}

fn kread_hash(k: &InvocationKernel, addr: u32) -> [u8; 32] {
    let v = k.read_data_cap_window(addr, 32).unwrap_or_default();
    let mut h = [0u8; 32];
    let n = v.len().min(32);
    h[..n].copy_from_slice(&v[..n]);
    h
}

// --- BOOT_CONTEXT host provider ---
//
// Host-local, non-replicated source for the BOOT_CONTEXT hostcall. The
// deterministic PVM has no OS entropy, so the host mints a fresh per-boot
// `boot_token` (real OS entropy) on every refine (re)entry — cold AND warm
// restart — plus a host-local `device_id` and a monotonic per-service
// `boot_epoch`. A `Local`-consistency actor's forward-ratcheting CSPRNG
// (`HostRand`) re-boots from `(seed, token, device_id, epoch, persisted_ctr)`
// each entry, so a warm restart / snapshot fork cannot re-emit used MLS
// randomness (the Ristenpart–Yilek reuse catastrophe).
//
// This state is deliberately process-global, NOT per-`VosRuntime`: `device_id`
// is a property of the physical host, and `boot_epoch` must be host-local and
// outlive any single runtime instance. The token is intentionally
// non-deterministic — BOOT_CONTEXT is sound ONLY for non-replicated actors, and
// its output must never feed a replicated state transition.
//
// **Seam limits (follow-ons):** `boot_epoch`
// lives in memory, so it is monotonic only within a process — durable
// cross-process persistence (the live-RAM-snapshot defense) and a real
// per-device `device_id` (e.g. derived from the node's libp2p identity) are
// wired when the messenger runs as a PVM actor. The fresh OS-entropy
// token already defends cold clone + warm restart today.
struct BootContextHost {
    device_id: [u8; 32],
    boot_epochs: HashMap<u32, u64>,
}

impl BootContextHost {
    fn new() -> Self {
        let mut device_id = [0u8; 32];
        getrandom::getrandom(&mut device_id)
            .expect("OS entropy for the BOOT_CONTEXT device_id");
        Self {
            device_id,
            boot_epochs: HashMap::new(),
        }
    }

    /// Mint a fresh boot context for `svc_id`: fresh OS-entropy `boot_token`,
    /// the stable host `device_id`, and the next monotonic `boot_epoch`.
    fn mint(&mut self, svc_id: u32) -> ([u8; 32], [u8; 32], u64) {
        let mut token = [0u8; 32];
        getrandom::getrandom(&mut token).expect("OS entropy for the BOOT_CONTEXT token");
        let slot = self.boot_epochs.entry(svc_id).or_insert(0);
        let epoch = *slot;
        *slot += 1;
        (token, self.device_id, epoch)
    }
}

static BOOT_CONTEXT_HOST: std::sync::LazyLock<std::sync::Mutex<BootContextHost>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(BootContextHost::new()));

/// Wire layout of one BOOT_CONTEXT reply: `boot_token(32) ‖ device_id(32) ‖
/// boot_epoch(u64 LE)`.
const BOOT_CONTEXT_LEN: usize = 32 + 32 + 8;

/// Serialize a freshly-minted boot context for `svc_id` into the wire layout.
fn mint_boot_context(svc_id: u32) -> [u8; BOOT_CONTEXT_LEN] {
    let (token, device_id, epoch) = BOOT_CONTEXT_HOST
        .lock()
        .expect("BOOT_CONTEXT host mutex poisoned")
        .mint(svc_id);
    let mut out = [0u8; BOOT_CONTEXT_LEN];
    out[..32].copy_from_slice(&token);
    out[32..64].copy_from_slice(&device_id);
    out[64..72].copy_from_slice(&epoch.to_le_bytes());
    out
}

/// Install the VOS-specific zkpvm-precompile slots as Protocol caps in
/// the active VM's cap table. javm auto-installs slots 1..=28 (the
/// spec-canonical protocol range) but leaves higher slots empty, so
/// each precompile slot has to be slotted in here before the actor's
/// first `ecalli` against it. Without this, `ecalli imm=N` falls into
/// `handle_call(N)` which finds no cap and returns RESULT_WHAT — the
/// actor's inline asm doesn't check the return value, so the
/// precompile silently no-ops and the actor gets garbage output.
///
/// Slot layout (`zkpvm/src/core/ecall.rs` is the source of truth):
///
///   100 = blake2b_compress
///   110 = ristretto_scalar_mult
///   111 = ristretto_point_add
///   112 = scalar_from_bytes_mod_order_wide
///   113 = scalar_mul_mod_l
///   114 = scalar_add_mod_l
///
/// All fit in javm's `imm ≤ 127` budget. Call this once per kernel
/// construction, before the first `run()`, for every refine entry
/// path (`new_cached`, `new_warm`, and child `handle_invoke`). The
/// slots collide with javm's program-cap range (29..=63 via CREATE,
/// 64..=127 via MOVE); until javm grows native zkpvm-precompile
/// support, we squat.
fn install_vos_precompile_caps(kernel: &mut InvocationKernel) {
    use javm::cap::{Cap, ProtocolCap};
    // Source-of-truth IDs live in `zkpvm::core::ecall`, mirrored on
    // the guest side in `zkpvm::precompiles::ecalls`. We import
    // blake2b from `vos::crypto` (it's the only one with a host-side
    // handler today); ristretto IDs are hardcoded here until vos
    // grows its own handler — the install is a no-op for slots
    // whose ECALL never fires.
    let slots: [u8; 8] = [
        crate::crypto::ECALL_BLAKE2B_COMPRESS as u8, // 100
        110,                                         // ristretto_scalar_mult
        111,                                         // ristretto_point_add
        112,                                         // scalar_from_bytes_mod_order_wide
        113,                                         // scalar_mul_mod_l
        114,                                         // scalar_add_mod_l
        hostcall::BOOT_CONTEXT as u8,                // 120 (boot-context seam)
        hostcall::NOW_MS as u8,                      // 121 (host wall-clock seam)
    ];
    let vm = kernel.vm_arena.vm_mut(kernel.active_vm);
    for &slot in &slots {
        vm.cap_table
            .set(slot, Cap::Protocol(ProtocolCap { id: slot }));
    }
}

fn kwrite(k: &mut InvocationKernel, addr: u32, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    k.write_data_cap_window(addr, data);
}

// --- Per-service refine journal ---
//
// One journal spans a top-level service's tick. It accumulates effects
// from the service itself **and** from any children it INVOKEs — JAM
// semantics make every effect produced under one refine a structural
// part of that refine's commit. The journal still tracks *which*
// service each entry belongs to so they land on the right storage row
// at commit time and `journaled_read` can serve read-your-own-writes
// without a parent's writes shadowing a child's lookup.

#[derive(Default)]
struct RefineJournal {
    /// Pending row mutations, scoped per service: `(svc_id, key, value)`
    /// where `None` is a delete tombstone. One ordered list — not
    /// separate write/delete lists — because last-wins per key depends
    /// on the interleaving.
    writes: Vec<(u32, Vec<u8>, Option<Vec<u8>>)>,
    transfers: Vec<(ServiceId, Vec<u8>)>,
    preimages: Vec<([u8; 32], Vec<u8>)>,
    self_messages: Vec<Vec<u8>>,
    /// Service creation requests: (code_hash, assigned_service_id).
    /// Committed after refine by registering the blob+service.
    new_services: Vec<([u8; 32], u32)>,
}

impl RefineJournal {
    /// Read-your-own-writes for `svc_id`: latest journaled entry for
    /// `key` written by *this* service, if any. Outer `None` = no
    /// journal entry (fall back to committed storage); inner `None` =
    /// delete tombstone (the key is definitively absent). Other
    /// services' writes to the same key are intentionally ignored —
    /// STATE_KEY collides across services and would otherwise let a
    /// parent's encoded state shadow a child's STORAGE_R during a
    /// nested INVOKE.
    fn journaled_read(&self, svc_id: u32, key: &[u8]) -> Option<Option<&[u8]>> {
        self.writes
            .iter()
            .rev()
            .find(|(s, k, _)| *s == svc_id && k.as_slice() == key)
            .map(|(_, _, v)| v.as_deref())
    }

    /// The effective value of `key` for `svc_id`: the journal overlay
    /// (tombstones read as absent) falling back to committed storage.
    /// The one read semantic STORAGE_R, the anchor check, and the
    /// child-invoke prior-state capture all share.
    fn effective_read<'a>(
        &'a self,
        storage: &'a ServiceStorage,
        svc_id: u32,
        key: &[u8],
    ) -> Option<&'a [u8]> {
        match self.journaled_read(svc_id, key) {
            Some(entry) => entry,
            None => storage.read(ServiceId(svc_id), key),
        }
    }

    fn absorb_effects(&mut self, effects: Vec<Effect>, self_id: u32) {
        for eff in effects {
            match eff {
                Effect::Write { key, value } => {
                    self.writes.push((self_id, key, Some(value)));
                }
                Effect::Delete { key } => {
                    self.writes.push((self_id, key, None));
                }
                Effect::Transfer { target, memo } => {
                    if target == self_id {
                        self.self_messages.push(memo);
                    } else {
                        self.transfers.push((ServiceId(target), memo));
                    }
                }
                Effect::Provide { hash, data } => {
                    self.preimages.push((hash, data));
                }
                Effect::New { code_hash } => {
                    self.new_services.push((code_hash, 0));
                }
            }
        }
    }

    /// Snapshot the journal's current lengths so one dispatch's appended
    /// effects can be delimited and, on a trap, discarded without
    /// disturbing effects committed by earlier dispatches in the tick.
    fn mark(&self) -> JournalMark {
        JournalMark {
            writes: self.writes.len(),
            transfers: self.transfers.len(),
            preimages: self.preimages.len(),
            self_messages: self.self_messages.len(),
            new_services: self.new_services.len(),
        }
    }

    /// Discard every effect appended since `mark` — the writes,
    /// transfers, preimages, self-messages and service creations a
    /// panicked dispatch journaled, including child-INVOKE effects that
    /// were absorbed into this journal during it.
    fn rollback_to(&mut self, mark: JournalMark) {
        self.writes.truncate(mark.writes);
        self.transfers.truncate(mark.transfers);
        self.preimages.truncate(mark.preimages);
        self.self_messages.truncate(mark.self_messages);
        self.new_services.truncate(mark.new_services);
    }
}

/// Length snapshot of a [`RefineJournal`] delimiting one dispatch's
/// appended effects, for discard-on-trap.
#[derive(Clone, Copy)]
struct JournalMark {
    writes: usize,
    transfers: usize,
    preimages: usize,
    self_messages: usize,
    new_services: usize,
}

// --- Work-result apply (the contract's normative semantics) ---

/// Why an emitted work-result was rejected instead of applied. Either
/// way, nothing from the work-result applies and its reply is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkResultError {
    /// The halt output claimed a known RefinePayload version but did not
    /// decode (v3: strict canonical rules). Fail-loud, like a trap.
    Malformed,
    /// The v3 anchor did not commit to the effective state the
    /// work-result would apply against — a stale work-result (or a
    /// divergent replica / buggy guest on the serialized path).
    AnchorMismatch,
}

/// Dispatch-relevant summary of one applied work-result.
#[derive(Debug)]
struct AbsorbedWorkResult {
    continue_next: bool,
    forbidden: bool,
    reply: Vec<u8>,
    /// v3 payload carried at least one effect. Input to the durable-node
    /// rule: an effect-bearing dispatch must produce a durable log node
    /// even when the state blob is unchanged. Always `false` for v2
    /// (those guests emit their full state unconditionally, so the rule
    /// is evaluated by value comparison at the commit strategy instead).
    effect_bearing: bool,
    /// The `(kind, anchor)` the work-result declared and the host
    /// verified. `None` for v2 payloads (no anchor on that wire).
    anchor: Option<(u8, [u8; 32])>,
}

/// Verify and absorb one decoded work-result into the journal — the
/// single applier the native drain, the intra-tick anchor chain, and the
/// v2/v3 parity tests all go through.
///
/// The anchor is checked against the **effective** state: the last
/// `Write{STATE_KEY}` absorbed from previously accepted work-results in
/// the same apply scope ([`RefineJournal::journaled_read`]), falling back
/// to committed storage. Checking against raw storage instead would
/// reject every multi-iteration tick — see the module docs.
fn absorb_work_result(
    journal: &mut RefineJournal,
    storage: &ServiceStorage,
    svc_id: u32,
    payload: RefinePayload,
) -> Result<AbsorbedWorkResult, WorkResultError> {
    let anchor = if payload.version == crate::refine_payload::REFINE_PAYLOAD_VERSION {
        let expected = expected_anchor(journal, storage, svc_id);
        if (payload.anchor_kind, payload.anchor) != expected {
            return Err(WorkResultError::AnchorMismatch);
        }
        Some((payload.anchor_kind, payload.anchor))
    } else {
        None
    };
    let effect_bearing = anchor.is_some() && !payload.effects.is_empty();
    journal.absorb_effects(payload.effects, svc_id);
    Ok(AbsorbedWorkResult {
        continue_next: payload.continue_next,
        forbidden: payload.forbidden,
        reply: payload.reply,
        effect_bearing,
        anchor,
    })
}

/// The `(anchor_kind, anchor)` a v3 work-result must carry for this
/// service's *effective* prior state. Committed-storage actors write
/// their composite root as an ordinary framework row
/// ([`COMMITTED_ROOT_KEY`](crate::lifecycle::COMMITTED_ROOT_KEY)), so
/// once a first dispatch has stored one, the expectation is
/// `(ANCHOR_SMT_ROOT, that row)` — read through the same journal
/// overlay as the state blob, which is what advances the expectation
/// across a tick's chained iterations. Before the row exists (fresh
/// actor, or a plain 0x01 actor forever) the expectation falls back to
/// [`anchor_for`](crate::refine_payload::anchor_for) over the state
/// blob, so genesis and blob-hash anchors are untouched.
fn expected_anchor(
    journal: &RefineJournal,
    storage: &ServiceStorage,
    svc_id: u32,
) -> (u8, [u8; 32]) {
    if let Some(root) = journal.effective_read(storage, svc_id, crate::lifecycle::COMMITTED_ROOT_KEY)
        && root.len() == 32
    {
        let mut anchor = [0u8; 32];
        anchor.copy_from_slice(root);
        return (crate::refine_payload::ANCHOR_SMT_ROOT, anchor);
    }
    let effective = journal.effective_read(storage, svc_id, crate::lifecycle::STATE_KEY_BYTES);
    crate::refine_payload::anchor_for(effective)
}

/// Whether halt-output bytes claim to be a RefinePayload wire version
/// the host knows. Used to distinguish "malformed payload — fail loud"
/// from "old-style `[status][state_len][state][reply]` envelope" when
/// [`RefinePayload::decode`] returns `None`. Old-style envelopes lead
/// with a status byte, and no reachable status collides: traps never
/// halt, so `STATUS_PANICKED` (0x02) is never emitted as an envelope
/// head, and 0x03+ statuses only appear in sub-5-byte error envelopes
/// the invoke path packs host-side.
fn claims_refine_payload(bytes: &[u8]) -> bool {
    matches!(
        bytes.first(),
        Some(&crate::refine_payload::REFINE_PAYLOAD_V2)
            | Some(&crate::refine_payload::REFINE_PAYLOAD_VERSION)
    )
}

// --- Per-service storage ---

/// Each service's keyspace is an ordered map so key-adjacent rows can
/// be range-scanned (storage-type prefetch, row-streamed snapshots);
/// reads borrow the key directly instead of allocating a lookup pair.
#[derive(Default)]
pub struct ServiceStorage {
    data: HashMap<u32, BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl ServiceStorage {
    fn new() -> Self {
        Self::default()
    }

    pub fn read(&self, service: ServiceId, key: &[u8]) -> Option<&[u8]> {
        self.data
            .get(&service.0)?
            .get(key)
            .map(|v| v.as_slice())
    }

    pub fn write(&mut self, service: ServiceId, key: &[u8], value: &[u8]) {
        self.data
            .entry(service.0)
            .or_default()
            .insert(key.to_vec(), value.to_vec());
    }

    pub fn delete(&mut self, service: ServiceId, key: &[u8]) {
        if let Some(rows) = self.data.get_mut(&service.0) {
            rows.remove(key);
        }
    }

    /// Drop every row for one service — its whole derived keyspace.
    /// Used before a soft-restart DAG replay so rebuilt collections
    /// start from the same empty slate a cold-boot replay sees. The
    /// storage-type meta/index and `StorageVec` length rows are
    /// accumulators seeded from the current stored bytes, so replaying
    /// onto surviving rows rebuilds a divergent physical layout (and,
    /// for `StorageVec`, a divergent length); wiping first makes the
    /// rebuild deterministic and cross-replica byte-identical.
    pub fn clear_service(&mut self, service: ServiceId) {
        self.data.remove(&service.0);
    }

    /// Ordered iteration over one service's rows whose keys start with
    /// `prefix`, in key order.
    pub fn scan_prefix<'a>(
        &'a self,
        service: ServiceId,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = (&'a [u8], &'a [u8])> + 'a {
        self.data
            .get(&service.0)
            .into_iter()
            .flat_map(move |rows| {
                rows.range(prefix.to_vec()..)
                    .take_while(move |(k, _)| k.starts_with(prefix))
                    .map(|(k, v)| (k.as_slice(), v.as_slice()))
            })
    }
}

// --- Service registry ---

struct ServiceInfo {
    blob_idx: usize,
    alive: bool,
}

/// Reply from an external invoke handler.
///
/// `Done` covers the common case (workers, completed agent dispatches):
/// just reply bytes. `Yielded` carries the post-dispatch state + reply
/// so the calling actor's `lifecycle::invoke_raw` decodes it as
/// `InvokeResult::Yielded { state, reply }` and can keep driving the
/// yielded child on subsequent ticks. The runtime packs whichever
/// variant the handler returns into the same wire envelope a
/// same-runtime INVOKE would produce.
#[derive(Debug, Clone)]
pub enum ExternalInvokeReply {
    Done(Vec<u8>),
    Yielded { state: Vec<u8>, reply: Vec<u8> },
}

impl ExternalInvokeReply {
    /// Common case: a non-yielding reply. Equivalent to
    /// `ExternalInvokeReply::Done(reply)`.
    pub fn done(reply: Vec<u8>) -> Self {
        ExternalInvokeReply::Done(reply)
    }
}

/// Callback for handling INVOKE hostcalls to services not in this runtime.
///
/// Receives `(target_service_id, message_bytes)`. Returns
/// `Some(ExternalInvokeReply)` when the external target serviced the
/// request, or `None` to fall through to `STATUS_NOT_FOUND`. Workers
/// and one-shot handlers return `Done(reply)`; agents that propagate
/// yields across thread boundaries return `Yielded { state, reply }`.
pub type ExternalInvokeFn = Box<dyn Fn(ServiceId, &[u8]) -> Option<ExternalInvokeReply> + Send>;

pub struct VosRuntime<D: DataLayer = MemoryDataLayer> {
    blobs: Vec<Vec<u8>>,
    blob_by_hash: HashMap<[u8; 32], usize>,
    /// Witness-buffer address per **Task** blob (code hash →
    /// `__VOS_WITNESS` flat-memory offset). Registration here is what
    /// makes a full-hash INVOKE run in Task mode: `(state, msg)`
    /// patched into the initial image, tracer-parity hostcalls, no
    /// child rows, effects folded into the parent's keyspace.
    task_witness: HashMap<[u8; 32], (u32, u32)>,
    services: HashMap<u32, ServiceInfo>,
    next_id: u32,
    pub storage: ServiceStorage,
    preimages: HashMap<[u8; 32], Vec<u8>>,
    pending_transfers: Vec<(ServiceId, Vec<u8>)>,
    /// Count of services that panicked in refine this runtime's lifetime.
    /// Exposed so tests can detect silent guest crashes.
    pub panics: u32,
    /// Count of work-results rejected (anchor mismatch or malformed
    /// payload) this runtime's lifetime. On the serialized agent thread a
    /// non-zero value means a bug or a divergent replica; exposed so
    /// tests can assert the parity property (a healthy run never rejects).
    pub work_result_rejects: u32,
    gas: GasConfig,
    /// Pluggable data layer for continuation blob storage.
    pub data: D,
    /// JIT compile cache — avoids re-compiling the same PVM blob on
    /// every child invocation.
    code_cache: javm::CodeCache,
    /// Optional handler for INVOKE targets not in this runtime.
    external_invoke: Option<ExternalInvokeFn>,
    /// Side-channel mode for the current dispatch.
    ///
    /// - `Inactive` — regular execution; no recording or replay.
    /// - `Recording` — every top-level INVOKE output is captured
    ///   into the session's log for attachment to the commit.
    /// - `Replaying` — every top-level INVOKE short-circuits and
    ///   returns the next logged output instead of running the
    ///   child.
    effect_mode: crate::effect_log::EffectMode,
    /// Per-service reply bytes captured from the most recent
    /// dispatch's [`RefinePayload::reply`] field. The host pulls
    /// these out via [`take_last_reply`] to satisfy synchronous
    /// invoke requests from peer agents.
    ///
    /// [`take_last_reply`]: VosRuntime::take_last_reply
    last_reply: HashMap<u32, Vec<u8>>,
    /// Per-service exit status byte from the most recent
    /// dispatch's invoke envelope. Today only `STATUS_FORBIDDEN`
    /// (from the M6 macro-emitted role check) flows through here
    /// — `STATUS_DONE` / `STATUS_YIELDED` are still inferred by
    /// the host from `is_suspended`. Cleared by
    /// [`take_last_status`](VosRuntime::take_last_status).
    last_status: HashMap<u32, u8>,
    /// `(kind, anchor)` of the FIRST work-result applied per service
    /// since the last [`take_dispatch_anchor`] — i.e. the anchor of the
    /// state the dispatch ran against, before any same-tick chain
    /// advanced it. The host stamps it into the dispatch's EffectLog
    /// node; replay divergence detection compares against that record.
    ///
    /// [`take_dispatch_anchor`]: VosRuntime::take_dispatch_anchor
    dispatch_anchor: HashMap<u32, (u8, [u8; 32])>,
    /// Ordered storage mutations applied to each top-level service's
    /// own rows since the last [`take_dispatch_delta`] — the
    /// whole-agent delta the host commits durably
    /// ([`crate::commit::AgentDelta`]); `None` values are delete
    /// tombstones. Child-row writes are excluded (children with rows
    /// are a legacy shape the Tasks model retires); continuation
    /// headers never ride the journal, so host bookkeeping never
    /// appears here.
    ///
    /// [`take_dispatch_delta`]: VosRuntime::take_dispatch_delta
    dispatch_writes: HashMap<u32, Vec<(Vec<u8>, Option<Vec<u8>>)>>,
    /// Per-service marker: some applied v3 work-result carried effects
    /// since the last [`take_dispatch_delta`]. Input to the
    /// durable-node rule.
    ///
    /// [`take_dispatch_delta`]: VosRuntime::take_dispatch_delta
    dispatch_effect_bearing: HashMap<u32, bool>,
}

impl VosRuntime<MemoryDataLayer> {
    pub fn new() -> Self {
        Self::with_gas_config(GasConfig::default())
    }

    pub fn with_gas_config(gas: GasConfig) -> Self {
        Self::with_data_layer_and_gas(MemoryDataLayer::new(), gas)
    }
}

impl<D: DataLayer> VosRuntime<D> {
    pub fn with_data_layer(data: D) -> Self {
        Self::with_data_layer_and_gas(data, GasConfig::default())
    }

    pub fn with_data_layer_and_gas(data: D, gas: GasConfig) -> Self {
        Self {
            blobs: Vec::new(),
            blob_by_hash: HashMap::new(),
            task_witness: HashMap::new(),
            services: HashMap::new(),
            next_id: 1,
            storage: ServiceStorage::new(),
            preimages: HashMap::new(),
            pending_transfers: Vec::new(),
            panics: 0,
            work_result_rejects: 0,
            gas,
            data,
            code_cache: javm::CodeCache::new(),
            external_invoke: None,
            effect_mode: crate::effect_log::EffectMode::Inactive,
            last_reply: HashMap::new(),
            last_status: HashMap::new(),
            dispatch_anchor: HashMap::new(),
            dispatch_writes: HashMap::new(),
            dispatch_effect_bearing: HashMap::new(),
        }
    }

    /// Take the `(kind, anchor)` of the first work-result applied for
    /// `svc_id` since the previous take — the anchor of the state the
    /// dispatch ran against. `None` when no anchored work-result was
    /// applied (v2 blobs, old-style actors, pure-trap dispatches). The
    /// host stamps this into the dispatch's EffectLog before commit and
    /// compares it during replay.
    pub fn take_dispatch_anchor(&mut self, svc_id: ServiceId) -> Option<(u8, [u8; 32])> {
        self.dispatch_anchor.remove(&svc_id.0)
    }

    /// Take the dispatch's whole-agent storage delta for `svc_id` since
    /// the previous take: the ordered mutations that landed on the
    /// service's own rows (`STATE_KEY` included; `None` = delete) and
    /// whether any applied v3 work-result carried effects. The host
    /// commits these as one [`crate::commit::AgentDelta`].
    pub fn take_dispatch_delta(
        &mut self,
        svc_id: ServiceId,
    ) -> (Vec<(Vec<u8>, Option<Vec<u8>>)>, bool) {
        (
            self.dispatch_writes.remove(&svc_id.0).unwrap_or_default(),
            self.dispatch_effect_bearing
                .remove(&svc_id.0)
                .unwrap_or(false),
        )
    }

    /// Take and return the most recent dispatch's reply bytes for
    /// `svc_id`, if any. Used by the host (`agent_thread`) to
    /// answer synchronous invoke requests routed to this agent.
    pub fn take_last_reply(&mut self, svc_id: ServiceId) -> Option<Vec<u8>> {
        self.last_reply.remove(&svc_id.0)
    }

    /// Take and return the most recent dispatch's exit status
    /// byte for `svc_id`, if any. Today only `STATUS_FORBIDDEN`
    /// shows up here (from the M6 role check); other statuses
    /// stay implicit. Used by the host (`handle_invoke_request`)
    /// to override the default `STATUS_DONE` when the actor
    /// refused the call at the dispatch boundary.
    pub fn take_last_status(&mut self, svc_id: ServiceId) -> Option<u8> {
        self.last_status.remove(&svc_id.0)
    }

    pub fn gas_config(&self) -> &GasConfig {
        &self.gas
    }

    /// Set a callback for INVOKE targets not in this runtime.
    /// Used by VosNode to route invocations to workers.
    pub fn set_external_invoke(&mut self, handler: ExternalInvokeFn) {
        self.external_invoke = Some(handler);
    }

    /// Begin recording the observed reply bytes of every top-level
    /// INVOKE made during the next dispatch. The log is keyed by
    /// `msg` — typically the incoming dispatch bytes — and will be
    /// returned by [`finish_recording`](Self::finish_recording)
    /// after the dispatch completes.
    pub fn begin_recording(&mut self, msg: Vec<u8>) {
        self.effect_mode =
            crate::effect_log::EffectMode::Recording(crate::effect_log::EffectSession::new(msg));
    }

    /// Begin recording with a custom per-reply size cap (overrides
    /// [`crate::effect_log::DEFAULT_REPLY_CAP`]).
    pub fn begin_recording_with_cap(&mut self, msg: Vec<u8>, cap: usize) {
        self.effect_mode = crate::effect_log::EffectMode::Recording(
            crate::effect_log::EffectSession::new(msg).with_cap(cap),
        );
    }

    /// Take the recorded [`EffectLog`](crate::effect_log::EffectLog)
    /// and return to the inactive mode.
    ///
    /// Returns `None` if no recording was in progress (the mode was
    /// `Inactive` or `Replaying`).
    pub fn finish_recording(&mut self) -> Option<crate::effect_log::EffectLog> {
        match std::mem::take(&mut self.effect_mode) {
            crate::effect_log::EffectMode::Recording(s) => Some(s.into_log()),
            other => {
                self.effect_mode = other;
                None
            }
        }
    }

    /// Begin replay: every top-level INVOKE during the next
    /// dispatch will return the corresponding logged bytes instead
    /// of running the child. Use this when restoring a CRDT actor
    /// from its DAG.
    pub fn begin_replay(&mut self, log: crate::effect_log::EffectLog) {
        self.effect_mode =
            crate::effect_log::EffectMode::Replaying(crate::effect_log::EffectReplay::new(log));
    }

    /// Take the replay state and return to the inactive mode. The
    /// returned [`EffectReplay`](crate::effect_log::EffectReplay)
    /// can be inspected for completion (`is_complete`) or
    /// exhaustion (`was_exhausted`) to detect non-deterministic
    /// handlers during rebuild.
    ///
    /// Returns `None` if no replay was in progress.
    pub fn finish_replay(&mut self) -> Option<crate::effect_log::EffectReplay> {
        match std::mem::take(&mut self.effect_mode) {
            crate::effect_log::EffectMode::Replaying(r) => Some(r),
            other => {
                self.effect_mode = other;
                None
            }
        }
    }

    /// Whether a recording session is active. Mainly for tests and
    /// host-side diagnostics.
    #[doc(hidden)]
    pub fn is_recording(&self) -> bool {
        self.effect_mode.is_recording()
    }

    /// Whether replay is active. Mainly for tests and host-side
    /// diagnostics.
    #[doc(hidden)]
    pub fn is_replaying(&self) -> bool {
        self.effect_mode.is_replaying()
    }

    pub fn register_blob(&mut self, blob: Vec<u8>) -> usize {
        let idx = self.blobs.len();
        self.blob_by_hash.insert(blob_hash(&blob), idx);
        self.blobs.push(blob);
        idx
    }

    pub fn register_service_blob(&mut self, blob: Vec<u8>) -> usize {
        self.register_blob(blob)
    }

    /// Register a **Task** blob: an anonymous, code-hash-identified pure
    /// child (`vos::agent::Tasks`, `Child::Task`). `witness_addr` is the
    /// blob's `__VOS_WITNESS` flat-memory offset (from the ELF symbol,
    /// [`crate::zk::witness_addr`] — the transpiled blob preserves the
    /// layout). Returns the content hash parents invoke by. Tasks get no
    /// ServiceId and no storage row; a full-hash INVOKE of this hash
    /// runs witness-delivered.
    pub fn register_task_blob(
        &mut self,
        blob: Vec<u8>,
        witness_addr: u32,
        witness_cap: u32,
    ) -> [u8; 32] {
        let hash = blob_hash(&blob);
        self.register_blob(blob);
        self.task_witness.insert(hash, (witness_addr, witness_cap));
        hash
    }

    /// The initial memory image a Task invocation of `code_hash` with
    /// `(state, msg)` executes from — built through the same kernel +
    /// patch path the live INVOKE uses. This is the live half of the
    /// live≡traced equality gate: a prover patching the same input at
    /// the same witness address into the unmodified blob must arrive at
    /// this exact image.
    pub fn task_initial_image(
        &mut self,
        code_hash: &[u8; 32],
        state: &[u8],
        msg: &[u8],
        rows: &[(Vec<u8>, Option<Vec<u8>>)],
    ) -> Option<Vec<u8>> {
        let &(witness_addr, witness_cap) = self.task_witness.get(code_hash)?;
        let &blob_idx = self.blob_by_hash.get(code_hash)?;
        let blob = self.blobs.get(blob_idx)?;
        let input = crate::task_abi::encode_task_input_with_rows(state, msg, rows);
        if input.len() > witness_cap as usize {
            return None;
        }
        let kernel = build_task_kernel(
            blob,
            witness_addr,
            &input,
            DEFAULT_GAS,
            &mut self.code_cache,
        )?;
        Some(kernel.extract_flat_mem().0)
    }

    pub fn register_service(&mut self, blob_idx: usize) -> ServiceId {
        let id = self.next_id;
        self.next_id += 1;
        self.services.insert(
            id,
            ServiceInfo {
                blob_idx,
                alive: true,
            },
        );
        ServiceId(id)
    }

    /// Register a service with a specific externally-assigned ID.
    /// Used by [`crate::node::VosNode`] to assign node-global IDs.
    pub fn register_service_with_id(&mut self, blob_idx: usize, id: ServiceId) -> ServiceId {
        self.services.insert(
            id.0,
            ServiceInfo {
                blob_idx,
                alive: true,
            },
        );
        // Keep next_id above any externally assigned ID to avoid collisions
        if id.0 >= self.next_id {
            self.next_id = id.0 + 1;
        }
        id
    }

    pub fn send_to(&mut self, target: ServiceId, data: Vec<u8>) {
        self.pending_transfers.push((target, data));
    }

    pub fn has_work(&self) -> bool {
        !self.pending_transfers.is_empty()
    }

    /// Drain transfers destined for services not registered in this
    /// runtime. Used by [`crate::node::VosNode`] to route cross-agent
    /// messages through the node's mailbox.
    pub fn drain_external_transfers(&mut self, _self_id: ServiceId) -> Vec<(ServiceId, Vec<u8>)> {
        let mut external = Vec::new();
        self.pending_transfers.retain(|(target, data)| {
            if self.services.contains_key(&target.0) {
                true // keep — local service
            } else {
                external.push((*target, data.clone()));
                false // remove — route externally
            }
        });
        external
    }

    /// Check whether a service has a live continuation in the data layer.
    pub fn is_suspended(&self, id: ServiceId) -> bool {
        let Some(header_bytes) = self
            .storage
            .read(id, crate::lifecycle::CONTINUATION_HEADER_KEY)
        else {
            return false;
        };
        if header_bytes.is_empty() {
            return false;
        }
        let Some(header) = crate::pvm_image::ContinuationHeader::decode(header_bytes) else {
            return false;
        };
        self.data.contains(&header.commitment)
    }

    /// Run one round: for each service with pending input, run refine
    /// (re-entering on self-messages up to [`MAX_REFINE_ITERATIONS`]),
    /// then commit the journal directly.
    pub async fn tick(&mut self) -> bool {
        if self.pending_transfers.is_empty() {
            return false;
        }

        let mut by_service: HashMap<u32, Vec<Vec<u8>>> = HashMap::new();
        for (to, data) in self.pending_transfers.drain(..) {
            by_service.entry(to.0).or_default().push(data);
        }

        let mut new_transfers = Vec::new();
        let mut new_services_to_register: Vec<([u8; 32], u32)> = Vec::new();
        let mut did_work = false;

        let blobs = &self.blobs;
        let blob_by_hash = &self.blob_by_hash;
        let task_witness = &self.task_witness;
        let services = &self.services;
        let storage = &mut self.storage;
        let refine_gas = self.gas.refine_gas;
        let panics = &mut self.panics;
        let next_id = &mut self.next_id;

        for (svc_id, mut items) in by_service {
            // Drop any reply captured by a previous dispatch — only
            // the most recent dispatch's reply is meaningful, and
            // if this one produces no reply we don't want
            // take_last_reply to surface stale bytes.
            self.last_reply.remove(&svc_id);

            let info = match services.get(&svc_id) {
                Some(i) if i.alive => i,
                _ => continue,
            };
            let blob = match blobs.get(info.blob_idx) {
                Some(b) => b,
                None => continue,
            };

            did_work = true;
            let mut journal = RefineJournal::default();

            // Load any existing continuation for the first iteration.
            // Subsequent iterations use the previous iteration's captured
            // flat_mem so `ACTOR_HOLDER` and heap state survive across
            // self-message re-entries within the same tick.
            let mut warm_mem: Option<(Vec<u8>, u32, u32)> =
                load_continuation(storage, &self.data, svc_id);

            for iteration in 0..MAX_REFINE_ITERATIONS {
                let mut kernel = if let Some((ref flat_mem, heap_base, heap_top)) = warm_mem {
                    match InvocationKernel::new_warm(
                        blob,
                        &[],
                        refine_gas,
                        flat_mem,
                        heap_base,
                        heap_top,
                        Some(&mut self.code_cache),
                    ) {
                        Ok(k) => k,
                        Err(e) => {
                            error!(svc_id, error = %e, "service: warm kernel init failed");
                            break;
                        }
                    }
                } else {
                    match InvocationKernel::new_cached(blob, &[], refine_gas, &mut self.code_cache)
                    {
                        Ok(k) => k,
                        Err(e) => {
                            error!(svc_id, error = %e, "service: kernel init failed");
                            break;
                        }
                    }
                };
                install_vos_precompile_caps(&mut kernel);
                // Zero the entry register (a0 / φ[7]). The guest runs the
                // single refine entry at PC=0 and reads no phase selector.
                kernel.set_active_reg(7, 0);
                // Transition VM 0 from Ready → Running so kernel.run() executes.
                let _ = kernel
                    .vm_arena
                    .vm_mut(0)
                    .transition(javm::vm_pool::VmState::Running);

                // Stage FETCH items (raw transfers become one item each).
                // Filter out empty wake-up transfers (used to re-tick
                // suspended services with continuations).
                let mut round_items = std::mem::take(&mut items);
                round_items.retain(|item| !item.is_empty());

                // Delimit this dispatch's journal contributions so a trap
                // can drop them whole (A2 discard-on-panic).
                let dispatch_mark = journal.mark();

                let halted = run_refine_kernel(
                    &mut kernel,
                    svc_id,
                    &mut round_items,
                    &mut journal,
                    storage,
                    &self.preimages,
                    blobs,
                    blob_by_hash,
                    task_witness,
                    services,
                    &mut self.effect_mode,
                    &mut self.code_cache,
                    next_id,
                    &self.external_invoke,
                );

                // Verify + absorb the guest's work-result (if any) into
                // the journal. This covers the actor framework's
                // effect-buffering path where `set_refine_mode(true)`
                // packs writes/transfers — and the post-dispatch state,
                // as a final Write{STATE_KEY} effect — into the refine
                // output. There is no host state special-case.
                if let Some(payload_bytes) = halted {
                    // Two output formats: RefinePayload (service actors) or
                    // old-style [status:u8][state_len:u32][state...][reply...]
                    // (invoked actors). Both can signal yield/continue.
                    let applied = match RefinePayload::decode(&payload_bytes) {
                        Some(payload) => {
                            absorb_work_result(&mut journal, storage, svc_id, payload).map(Some)
                        }
                        None if claims_refine_payload(&payload_bytes) => {
                            Err(WorkResultError::Malformed)
                        }
                        None => Ok(None),
                    };
                    let continue_next = match applied {
                        Ok(Some(absorbed)) => {
                            // First applied work-result of this dispatch:
                            // its anchor is the state the dispatch ran
                            // against (later chain iterations anchor
                            // interior states).
                            if let Some(anchor) = absorbed.anchor {
                                self.dispatch_anchor.entry(svc_id).or_insert(anchor);
                            }
                            if absorbed.effect_bearing {
                                self.dispatch_effect_bearing.insert(svc_id, true);
                            }
                            // Capture the reply bytes for the host's
                            // synchronous-invoke path. Always insert,
                            // even for empty replies (Unit-returning
                            // handlers): callers distinguish "handler
                            // returned ()" from "handler panicked" by
                            // looking at whether `take_last_reply`
                            // returns `Some(_)` or `None`. A `None`
                            // here would conflate the two and let
                            // panics surface to the host as silent
                            // success.
                            self.last_reply.insert(svc_id, absorbed.reply);
                            // M6 — propagate the forbidden flag from
                            // the work-result so the host can
                            // surface the actor-emitted refusal as a
                            // STATUS_FORBIDDEN envelope. Other
                            // statuses stay implicit (DONE / YIELDED
                            // are inferred from is_suspended).
                            if absorbed.forbidden {
                                self.last_status
                                    .insert(svc_id, crate::actors::run::STATUS_FORBIDDEN);
                            }
                            absorbed.continue_next
                        }
                        // Old-style format: status byte 0x01 = yielded.
                        Ok(None) => {
                            !payload_bytes.is_empty()
                                && payload_bytes[0] == crate::actors::run::STATUS_YIELDED
                        }
                        Err(err) => {
                            // Reject the work-result whole: nothing it
                            // carries applies, its reply is dropped (the
                            // caller sees a failure and retries), and the
                            // guest is cold-restarted so its next dispatch
                            // re-reads durable state. Mid-chain,
                            // iterations before this one stand — the
                            // continuation is cleared directly (host
                            // bookkeeping), not via the discarded journal
                            // suffix.
                            error!(svc_id, ?err, "service: work-result rejected");
                            journal.rollback_to(dispatch_mark);
                            self.last_reply.remove(&svc_id);
                            self.last_status.remove(&svc_id);
                            clear_continuation(storage, &mut self.data, svc_id);
                            self.work_result_rejects += 1;
                            break;
                        }
                    };

                    if continue_next {
                        let (flat_mem, heap_base, heap_top) = kernel.extract_flat_mem();
                        save_continuation(
                            svc_id,
                            flat_mem,
                            heap_base,
                            heap_top,
                            &mut self.data,
                            storage,
                        );
                        // Re-queue mail the guest had not FETCHed before it
                        // yielded, then any self-directed transfers. A
                        // handler that yields mid-batch leaves the rest of
                        // this round's items unconsumed; dropping them would
                        // silently lose messages. Both redeliver next tick —
                        // un-fetched mail first — and the saved continuation
                        // warm-restarts the guest to process them. On a JAM
                        // host, accumulate would replay the self-transfers
                        // via hostcalls; VOS must match.
                        for msg in round_items.drain(..) {
                            new_transfers.push((ServiceId(svc_id), msg));
                        }
                        for msg in journal.self_messages.drain(..) {
                            new_transfers.push((ServiceId(svc_id), msg));
                        }
                        // Nothing left to redeliver means no wake-up: the
                        // service stays suspended until a future external
                        // message (typically a parent agent's INVOKE, which
                        // owns the dispatch loop) resumes the continuation.
                        // The host injects no synthetic self-transfer.
                        break;
                    }

                    if journal.self_messages.is_empty() {
                        // Guest signalled it's done; clear any prior
                        // continuation and exit the refine loop.
                        clear_continuation(storage, &mut self.data, svc_id);
                        break;
                    }
                } else {
                    // Guest trapped (panic / OOG / page fault) before
                    // halting: discard everything this dispatch journaled —
                    // including child-INVOKE effects absorbed into the
                    // parent's journal — so a panicked handler commits
                    // nothing from its own tick.
                    //
                    // Atomicity contract, explicit: the commit unit is one
                    // ITERATION (one work-result), not the whole
                    // self-message chain. Effects applied by earlier
                    // iterations in this tick stand — same rule as a
                    // mid-chain anchor rejection. What must NOT stand is
                    // the reply: an earlier iteration's reply is an
                    // intermediate of an unfinished chain, and leaving it
                    // in last_reply would surface the panic to the caller
                    // as STATUS_DONE with stale bytes. Drop it so
                    // take_last_reply returns None and the caller sees
                    // Panicked.
                    journal.rollback_to(dispatch_mark);
                    self.last_reply.remove(&svc_id);
                    self.last_status.remove(&svc_id);
                    *panics += 1;
                    break;
                }

                // Re-enter on self-messages, else stop.
                if journal.self_messages.is_empty() {
                    break;
                }
                // Capture flat_mem for the next iteration's warm restart
                // so ACTOR_HOLDER and heap state survive across self-message
                // re-entries within the same tick.
                let captured = kernel.extract_flat_mem();
                items = std::mem::take(&mut journal.self_messages);
                if iteration + 1 == MAX_REFINE_ITERATIONS {
                    // Spill remaining self-messages as pending transfers
                    // for the next tick. Capture a continuation so the
                    // service warm-restarts with its current heap/actor.
                    let (flat_mem, heap_base, heap_top) = captured;
                    save_continuation(
                        svc_id,
                        flat_mem,
                        heap_base,
                        heap_top,
                        &mut self.data,
                        storage,
                    );
                    // Re-queue leftover self-messages for next tick.
                    for msg in items.drain(..) {
                        new_transfers.push((ServiceId(svc_id), msg));
                    }
                    break;
                }
                warm_mem = Some(captured);
            }

            // Commit the journal (accumulate as a direct replay).
            // Each entry carries its origin service_id — children
            // INVOKEd inside this refine produced their own writes,
            // and they need to land on the child's storage row, not
            // the dispatching service's. The ticked service's own
            // writes are additionally captured as its dispatch delta
            // for the durable commit.
            for (write_svc_id, key, value) in journal.writes.drain(..) {
                match &value {
                    Some(v) => storage.write(ServiceId(write_svc_id), &key, v),
                    None => storage.delete(ServiceId(write_svc_id), &key),
                }
                if write_svc_id == svc_id {
                    self.dispatch_writes
                        .entry(svc_id)
                        .or_default()
                        .push((key, value));
                }
            }
            for (hash, data) in journal.preimages.drain(..) {
                self.preimages.insert(hash, data);
            }
            new_transfers.append(&mut journal.transfers);
            new_services_to_register.append(&mut journal.new_services);
        }

        // Register services created via NEW during this tick.
        // The code blob is looked up from preimages (populated by PROVIDE).
        for (code_hash, assigned_id) in new_services_to_register {
            if let Some(blob) = self.preimages.get(&code_hash).cloned() {
                let blob_idx = self.register_blob(blob);
                self.services.insert(
                    assigned_id,
                    ServiceInfo {
                        blob_idx,
                        alive: true,
                    },
                );
            }
        }

        self.pending_transfers.extend(new_transfers);
        did_work
    }

    pub async fn run(&mut self) {
        while self.has_work() {
            self.tick().await;
        }
    }

    pub fn run_blocking(&mut self) {
        pollster::block_on(self.run());
    }

    pub fn tick_blocking(&mut self) -> bool {
        pollster::block_on(self.tick())
    }
}

impl Default for VosRuntime<MemoryDataLayer> {
    fn default() -> Self {
        Self::new()
    }
}

/// Drive a refine-phase kernel to halt. Returns the guest's halt
/// output bytes (read from φ[7]/φ[8] as ptr/len) on success, `None` on
/// panic / OOG / page fault.
#[allow(clippy::too_many_arguments)]
fn run_refine_kernel(
    kernel: &mut InvocationKernel,
    svc_id: u32,
    items: &mut Vec<Vec<u8>>,
    journal: &mut RefineJournal,
    storage: &mut ServiceStorage,
    preimages: &HashMap<[u8; 32], Vec<u8>>,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    task_witness: &HashMap<[u8; 32], (u32, u32)>,
    services: &HashMap<u32, ServiceInfo>,
    mode: &mut crate::effect_log::EffectMode,
    code_cache: &mut javm::CodeCache,
    next_id: &mut u32,
    external_invoke: &Option<ExternalInvokeFn>,
) -> Option<Vec<u8>> {
    loop {
        match kernel.run() {
            KernelResult::Halt => {
                let ptr = kernel.active_reg(7) as u32;
                let len = (kernel.active_reg(8) as usize).min(1 << 20);
                return Some(kread(kernel, ptr, len));
            }
            KernelResult::Panic => {
                let pc = kernel.vm_arena.vm(kernel.active_vm).pc;
                error!(svc_id, pc, "service: panicked in refine");
                return None;
            }
            KernelResult::OutOfGas => {
                error!(svc_id, "service: out of gas in refine");
                return None;
            }
            KernelResult::PageFault(addr) => {
                error!(
                    svc_id,
                    addr = format!("{addr:#x}"),
                    "service: page fault in refine"
                );
                return None;
            }
            KernelResult::ProtocolCall { slot } => {
                handle_refine_hostcall(
                    kernel,
                    slot as u32,
                    items,
                    svc_id,
                    journal,
                    storage,
                    preimages,
                    blobs,
                    blob_by_hash,
                    task_witness,
                    services,
                    code_cache,
                    0,
                    next_id,
                    external_invoke,
                    mode,
                );
            }
        }
    }
}

/// Refine-phase protocol-cap dispatch. Mutating calls (WRITE, TRANSFER,
/// PREIMAGE_PROVIDE) are journaled, not applied. Always calls
/// `kernel.resume_protocol_call` before returning.
#[allow(clippy::too_many_arguments)]
fn handle_refine_hostcall(
    kernel: &mut InvocationKernel,
    call_id: u32,
    items: &mut Vec<Vec<u8>>,
    svc_id: u32,
    journal: &mut RefineJournal,
    storage: &mut ServiceStorage,
    preimages: &HashMap<[u8; 32], Vec<u8>>,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    task_witness: &HashMap<[u8; 32], (u32, u32)>,
    services: &HashMap<u32, ServiceInfo>,
    code_cache: &mut javm::CodeCache,
    depth: usize,
    next_id: &mut u32,
    external_invoke: &Option<ExternalInvokeFn>,
    mode: &mut crate::effect_log::EffectMode,
) {
    let a0 = kernel.active_reg(7);
    let a1 = kernel.active_reg(8);
    let a2 = kernel.active_reg(9);
    let a3 = kernel.active_reg(10);
    let a4 = kernel.active_reg(11);

    let (r7, r8): (u64, u64) = match call_id {
        hostcall::GAS => (kernel.active_gas(), 0),
        hostcall::GROW_HEAP => (error::HOST_OK, 0),
        hostcall::DEBUG_WRITE => {
            let buf = kread(kernel, a0 as u32, a1 as usize);
            let _ = std::io::stderr().write_all(&buf);
            let _ = std::io::stderr().flush();
            (buf.len() as u64, 0)
        }
        hostcall::FETCH => {
            let buf_ptr = a0 as u32;
            let buf_len = a1 as usize;
            if let Some(item) = items.first().cloned() {
                let copy_len = item.len().min(buf_len);
                kwrite(kernel, buf_ptr, &item[..copy_len]);
                items.remove(0);
                // Return the full item length, not copy_len. The guest
                // pairs this with `n <= buf_len` to detect truncation:
                // n > buf_len means the value didn't fit. Returning
                // copy_len here would conflate "fit exactly" with "was
                // truncated", silently dropping items of size buf_len.
                (item.len() as u64, 0)
            } else {
                (0, 0)
            }
        }
        hostcall::INFO => (svc_id as u64, 0),
        hostcall::STORAGE_R => {
            let key = kread(kernel, a0 as u32, a1 as usize);
            let value = journal
                .effective_read(storage, svc_id, &key)
                .map(|v| v.to_vec());
            match value {
                Some(v) => {
                    let copy_len = v.len().min(a3 as usize);
                    kwrite(kernel, a2 as u32, &v[..copy_len]);
                    // Return the full value length so the guest can
                    // detect truncation (n > buf_len). See FETCH for
                    // the rationale.
                    (v.len() as u64, 0)
                }
                None => (error::HOST_NONE, 0),
            }
        }
        hostcall::STORAGE_W => {
            let key = kread(kernel, a0 as u32, a1 as usize);
            let value = kread(kernel, a2 as u32, a3 as usize);
            journal.writes.push((svc_id, key, Some(value)));
            (error::HOST_OK, 0)
        }
        hostcall::TRANSFER => {
            let target = ServiceId(a0 as u32);
            let memo = kread(kernel, a3 as u32, a4 as usize);
            if target.0 == svc_id {
                journal.self_messages.push(memo);
            } else {
                journal.transfers.push((target, memo));
            }
            (error::HOST_OK, 0)
        }
        hostcall::PREIMAGE_LOOKUP => {
            // Lookup preimage by hash: check journal first, then global.
            let hash = kread_hash(kernel, a0 as u32);
            let buf_ptr = a1 as u32;
            let buf_len = a2 as usize;
            let data = journal
                .preimages
                .iter()
                .find(|(h, _)| *h == hash)
                .map(|(_, d)| d.as_slice())
                .or_else(|| preimages.get(&hash).map(|d| d.as_slice()));
            match data {
                Some(d) => {
                    let copy_len = d.len().min(buf_len);
                    kwrite(kernel, buf_ptr, &d[..copy_len]);
                    // Return the full preimage length (mirrors STORAGE_R
                    // / FETCH) so guests can detect truncation. No
                    // current caller in vos but the contract should be
                    // consistent across the read-into-buffer hostcalls.
                    (d.len() as u64, 0)
                }
                None => (error::HOST_NONE, 0),
            }
        }
        hostcall::PREIMAGE_PROVIDE => {
            let hash = kread_hash(kernel, a0 as u32);
            let data = kread(kernel, a1 as u32, a2 as usize);
            journal.preimages.push((hash, data));
            (error::HOST_OK, 0)
        }
        hostcall::SERVICE_NEW => {
            // JAM NEW: guest provides code_hash in a0 (ptr to 32 bytes).
            // Look up the code blob from journaled preimages, assign a
            // new service ID, and record it for commit.
            let code_hash = kread_hash(kernel, a0 as u32);
            // Look up in journal preimages first (PROVIDE'd this refine)
            let blob = journal
                .preimages
                .iter()
                .find(|(h, _)| *h == code_hash)
                .map(|(_, d)| d.clone());
            if let Some(_blob) = blob {
                let new_svc_id = *next_id;
                *next_id += 1;
                journal.new_services.push((code_hash, new_svc_id));
                (new_svc_id as u64, 0)
            } else {
                (error::HOST_NONE, 0)
            }
        }
        hostcall::OUTPUT | hostcall::CHECKPOINT => (error::HOST_OK, 0),
        hostcall::BOOT_CONTEXT => {
            // Boot-context seam: mint a FRESH boot context for this (re)entry —
            // a0 = guest out-buffer ptr, a1 = its length. Writes
            // `boot_token(32) ‖ device_id(32) ‖ boot_epoch(u64 LE)` and
            // returns the full length (so the guest can detect truncation,
            // like STORAGE_R / FETCH). A fresh OS-entropy token + advanced
            // epoch every call is what keeps a warm restart from re-emitting
            // used MLS randomness.
            let buf_ptr = a0 as u32;
            let buf_len = a1 as usize;
            let ctx = mint_boot_context(svc_id);
            let n = ctx.len().min(buf_len);
            kwrite(kernel, buf_ptr, &ctx[..n]);
            (ctx.len() as u64, 0)
        }
        hostcall::NOW_MS => {
            // Host wall-clock in Unix-epoch milliseconds. No args; the value is
            // returned directly. Intentionally non-deterministic — sound only
            // for non-replicated (`Local`) actors (the messenger reads it for
            // MLS Lifetime validity); replicated state takes time from chronos.
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            (now, 0)
        }
        crate::crypto::ECALL_BLAKE2B_COMPRESS => {
            // Wire ABI matches `zkpvm-precompiles`: a0=h_ptr (64B
            // in/out), a1=m_ptr (128B in), a2=t_low (counter low
            // 64 bits), a3=f flag. The compress primitive itself
            // lives inside vos::crypto as `host_compress_block`
            // — `blake2b_simd` doesn't expose a public single-
            // block API, so this glue stays in-tree.
            let h_ptr = a0 as u32;
            let m_ptr = a1 as u32;
            let t_low = a2;
            let f_flag = a3 != 0;
            let h_bytes = kread(kernel, h_ptr, 64);
            let m_bytes = kread(kernel, m_ptr, 128);
            if h_bytes.len() != 64 || m_bytes.len() != 128 {
                (error::HOST_WHAT, 0)
            } else {
                let mut h: [u8; 64] = h_bytes.try_into().unwrap();
                let m: [u8; 128] = m_bytes.try_into().unwrap();
                crate::crypto::blake2b::host_compress_block(&mut h, &m, t_low as u128, f_flag);
                kwrite(kernel, h_ptr, &h);
                (error::HOST_OK, 0)
            }
        }
        hostcall::INVOKE => {
            let result = handle_invoke(
                kernel,
                svc_id,
                blobs,
                blob_by_hash,
                task_witness,
                services,
                storage,
                preimages,
                code_cache,
                journal,
                depth + 1,
                next_id,
                external_invoke,
                mode,
            );
            (result, 0)
        }
        _ => (error::HOST_WHAT, 0),
    };

    kernel
        .resume_protocol_call(r7, r8)
        .expect("refine hostcall must resume its pending protocol boundary");
}

/// Write an invoke output into the caller's buffer, and — when a
/// recording session is active at depth 1 — append the same bytes
/// to the session log so replay can reproduce the caller's
/// observation byte-for-byte without re-running the child.
///
/// Nested invokes (depth >= 2) belong to a child's refine and
/// are irrelevant to the caller's session.
///
/// **Buffer cap enforcement.** When the caller's `output` register
/// carries a non-zero length in its high 32 bits (`output_buf_len`),
/// the runtime refuses to write more than that into the caller's
/// PVM memory. An over-cap reply is replaced with a one-byte
/// `STATUS_TOO_BIG` envelope at the caller's `output_ptr`, so the
/// guest sees `InvokeError::TooBig` — distinct from a crash — rather
/// than having its buffer silently overrun. A length of 0 means a
/// legacy guest predating the ABI extension — fall through to the
/// unbounded write.
///
/// **Recording cap enforcement.** When recording, the session
/// carries a per-reply byte cap (16 KiB by default). Outputs larger
/// than that cap are replaced — both in the log and in the caller's
/// buffer — with a single STATUS_PANICKED byte. This is a distinct
/// consensus-safety truncation (SOUND-1) from the buffer cap above:
/// it keeps DAG nodes bounded so a runaway worker can't poison
/// consensus replicas with multi-MB payloads, and it stays PANICKED
/// so the recorded observation is unchanged.
fn record_and_write_invoke(
    caller: &mut InvocationKernel,
    output_ptr: u32,
    output_buf_len: usize,
    output: &[u8],
    depth: usize,
    mode: &mut crate::effect_log::EffectMode,
) -> u64 {
    use crate::actors::run::{STATUS_PANICKED, STATUS_TOO_BIG};

    // Buffer cap fires first — if the reply doesn't fit in the caller's
    // PVM buffer, kwrite would overrun. Surface a distinct STATUS_TOO_BIG
    // (not STATUS_PANICKED) so the guest can tell an oversize reply from a
    // real crash. Feed the recording log the same marker so replay sees
    // the same observation.
    if output_buf_len > 0 && output.len() > output_buf_len {
        let truncated = alloc::vec![STATUS_TOO_BIG];
        if depth == 1
            && let crate::effect_log::EffectMode::Recording(s) = mode
        {
            s.record(truncated.clone());
        }
        kwrite(caller, output_ptr, &truncated);
        return truncated.len() as u64;
    }

    if depth == 1
        && let crate::effect_log::EffectMode::Recording(s) = mode
    {
        // Consensus-safety cap (SOUND-1): stays STATUS_PANICKED so the
        // recorded/replayed observation is unchanged.
        if output.len() > s.cap() {
            let truncated = alloc::vec![STATUS_PANICKED];
            s.record(truncated.clone());
            kwrite(caller, output_ptr, &truncated);
            return truncated.len() as u64;
        }
        s.record(output.to_vec());
    }
    kwrite(caller, output_ptr, output);
    output.len() as u64
}

/// Split an invoke input into `(state, witnessed-row keys, msg)`.
/// The base layout is `[state_len: u32 LE][state][msg]`; the extended
/// layout (flag bit in the length word — see
/// `lifecycle::invoke_hash_with_rows`) carries the row keys the caller
/// named between the state and the message. Inputs shorter than the
/// length prefix are all message (legacy raw invokes). A malformed
/// keys section degrades to "no keys, rest is message": the child then
/// panics on its first unproven read instead of the host guessing.
fn split_invoke_input(input: &[u8]) -> (&[u8], alloc::vec::Vec<&[u8]>, &[u8]) {
    if input.len() < 4 {
        return (&[], alloc::vec::Vec::new(), input);
    }
    let len_word = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let state_len = (len_word & !crate::lifecycle::INVOKE_INPUT_HAS_ROWS) as usize;
    let state_end = (4 + state_len).min(input.len());
    let state = &input[4..state_end];
    let mut rest = &input[state_end..];
    let mut row_keys = alloc::vec::Vec::new();
    if len_word & crate::lifecycle::INVOKE_INPUT_HAS_ROWS != 0 && rest.len() >= 4 {
        let n = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        let mut at = 4;
        let mut keys = alloc::vec::Vec::with_capacity(n);
        let mut ok = true;
        for _ in 0..n {
            if at + 2 > rest.len() {
                ok = false;
                break;
            }
            let klen = u16::from_le_bytes([rest[at], rest[at + 1]]) as usize;
            at += 2;
            if at + klen > rest.len() {
                ok = false;
                break;
            }
            keys.push(&rest[at..at + klen]);
            at += klen;
        }
        if ok {
            row_keys = keys;
            rest = &rest[at..];
        }
    }
    (state, row_keys, rest)
}

/// Build a Task child's kernel: fresh instance from the blob, VOS
/// precompile caps installed, `(state, msg)` input patched into the
/// initial image at the blob's witness address — the exact image a
/// prover's `trace_blob_with_patches` reconstructs from the unmodified
/// blob plus the same patch.
fn build_task_kernel(
    blob: &[u8],
    witness_addr: u32,
    input: &[u8],
    gas: Gas,
    code_cache: &mut javm::CodeCache,
) -> Option<InvocationKernel> {
    let mut child = InvocationKernel::new_cached(blob, &[], gas, code_cache).ok()?;
    install_vos_precompile_caps(&mut child);
    child.set_active_reg(7, 0);
    let _ = child
        .vm_arena
        .vm_mut(0)
        .transition(javm::vm_pool::VmState::Running);
    kwrite(&mut child, witness_addr, input);
    Some(child)
}

/// Serve one hostcall of a Task child with EXACTLY the observable
/// semantics `zkpvm`'s `TracingPvm::run_with_vos_stubs` gives the
/// traced re-execution — this table is the live half of live≡proved:
///
/// - the blake2b precompile executes natively (the tracer runs it too,
///   constrained in-circuit by Blake2bChip) with registers echoed back
///   untouched, exactly as the tracer leaves them;
/// - `GAS`/`FETCH`/`STORAGE_R`/`STORAGE_W`/`INFO`/`DEBUG_WRITE`/`OUTPUT`
///   echo the registers untouched — the tracer's "lucky stub" set. A
///   Task built on `run_task_service` never issues the input ones
///   (witness-delivered, READ/FETCH-free by construction); a handler
///   that does gets the same garbage the trace would. `DEBUG_WRITE`
///   additionally mirrors to stderr — a host-side effect the guest
///   cannot observe;
/// - everything else (INVOKE, TRANSFER, NOW_MS, the ristretto
///   precompiles — no vos host handler yet, though the tracer has one)
///   returns `false`: fail loud, exactly where the tracer would end the
///   trace un-halted and the proof could not complete.
fn handle_task_hostcall(kernel: &mut InvocationKernel, call_id: u32) -> bool {
    let echo7 = kernel.active_reg(7);
    let echo8 = kernel.active_reg(8);
    match call_id {
        crate::crypto::ECALL_BLAKE2B_COMPRESS => {
            let h_ptr = kernel.active_reg(7) as u32;
            let m_ptr = kernel.active_reg(8) as u32;
            let t_low = kernel.active_reg(9);
            let f_flag = kernel.active_reg(10) != 0;
            let h_bytes = kread(kernel, h_ptr, 64);
            let m_bytes = kread(kernel, m_ptr, 128);
            if h_bytes.len() != 64 || m_bytes.len() != 128 {
                return false;
            }
            let mut h: [u8; 64] = h_bytes.try_into().unwrap();
            let m: [u8; 128] = m_bytes.try_into().unwrap();
            crate::crypto::blake2b::host_compress_block(&mut h, &m, t_low as u128, f_flag);
            kwrite(kernel, h_ptr, &h);
        }
        hostcall::GAS
        | hostcall::FETCH
        | hostcall::STORAGE_R
        | hostcall::STORAGE_W
        | hostcall::INFO
        | hostcall::OUTPUT => {}
        hostcall::DEBUG_WRITE => {
            let buf = kread(kernel, echo7 as u32, echo8 as usize);
            let _ = std::io::stderr().write_all(&buf);
            let _ = std::io::stderr().flush();
        }
        other => {
            error!(call_id = other, "task child: hostcall outside the refine-pure set");
            return false;
        }
    }
    kernel
        .resume_protocol_call(echo7, echo8)
        .expect("task hostcall must resume its pending protocol boundary");
    true
}

/// Run a witness-delivered Task invocation (the A9 invoke mode): patch
/// `(state, msg)` into the child's initial image, run it under the
/// tracer-parity hostcall table, verify + convert its v3 work-result.
/// No child ServiceId, no child storage row — the extracted state goes
/// to the parent's envelope and the remaining effects fold into the
/// PARENT's keyspace.
#[allow(clippy::too_many_arguments)]
fn run_task_invoke(
    caller: &mut InvocationKernel,
    blob: &[u8],
    witness_addr: u32,
    witness_cap: u32,
    parent_svc_id: u32,
    state: &[u8],
    msg: &[u8],
    rows: &[(Vec<u8>, Option<Vec<u8>>)],
    gas: Gas,
    journal: &mut RefineJournal,
    code_cache: &mut javm::CodeCache,
    output_ptr: u32,
    output_buf_len: usize,
    depth: usize,
    mode: &mut crate::effect_log::EffectMode,
) -> u64 {
    use crate::actors::run::{
        STATUS_DONE, STATUS_OOG, STATUS_PANICKED, STATUS_TOO_BIG, STATUS_YIELDED,
    };

    let input = crate::task_abi::encode_task_input_with_rows(state, msg, rows);
    // The witness buffer is a fixed static in the child's image — an
    // over-capacity input would silently overwrite adjacent .bss.
    // Refuse host-side with the status the guest already understands.
    if input.len() > witness_cap as usize {
        return record_and_write_invoke(
            caller,
            output_ptr,
            output_buf_len,
            &[STATUS_TOO_BIG],
            depth,
            mode,
        );
    }
    let Some(mut child) = build_task_kernel(blob, witness_addr, &input, gas, code_cache) else {
        return record_and_write_invoke(
            caller,
            output_ptr,
            output_buf_len,
            &[STATUS_PANICKED],
            depth,
            mode,
        );
    };

    let invoke_mark = journal.mark();
    loop {
        match child.run() {
            KernelResult::Halt => break,
            KernelResult::Panic | KernelResult::PageFault(_) => {
                journal.rollback_to(invoke_mark);
                return record_and_write_invoke(
                    caller,
                    output_ptr,
                    output_buf_len,
                    &[STATUS_PANICKED],
                    depth,
                    mode,
                );
            }
            KernelResult::OutOfGas => {
                journal.rollback_to(invoke_mark);
                return record_and_write_invoke(
                    caller,
                    output_ptr,
                    output_buf_len,
                    &[STATUS_OOG],
                    depth,
                    mode,
                );
            }
            KernelResult::ProtocolCall { slot } => {
                if !handle_task_hostcall(&mut child, slot as u32) {
                    journal.rollback_to(invoke_mark);
                    return record_and_write_invoke(
                        caller,
                        output_ptr,
                        output_buf_len,
                        &[STATUS_PANICKED],
                        depth,
                        mode,
                    );
                }
            }
        }
    }

    let out_ptr = child.active_reg(7) as u32;
    let out_len = (child.active_reg(8) as usize).min(1 << 20);
    let raw_output = kread(&child, out_ptr, out_len);

    // Tasks are v3-native — run_task_service is the only entry that can
    // produce this halt shape; anything else is a mis-built blob.
    let payload = match RefinePayload::decode(&raw_output) {
        Some(p) if p.version == crate::refine_payload::REFINE_PAYLOAD_VERSION => p,
        _ => {
            error!(parent_svc_id, "task child: halt output is not a v3 work-result");
            journal.rollback_to(invoke_mark);
            return record_and_write_invoke(
                caller,
                output_ptr,
                output_buf_len,
                &[STATUS_PANICKED],
                depth,
                mode,
            );
        }
    };
    let mut payload = payload;

    // Parity: the child's anchor must commit to exactly the state the
    // parent delivered (genesis when it delivered none). Tasks stay on
    // blob-hash anchors: a witness-delivered committed root belongs to
    // the witnessed-read backend, which supplies the leaves it proves.
    let expected = crate::refine_payload::anchor_for(Some(state));
    if (payload.anchor_kind, payload.anchor) != expected {
        error!(parent_svc_id, "task child: work-result anchor mismatch");
        journal.rollback_to(invoke_mark);
        return record_and_write_invoke(
            caller,
            output_ptr,
            output_buf_len,
            &[STATUS_PANICKED],
            depth,
            mode,
        );
    }

    // Child state to the parent envelope (echo the input when
    // unchanged); every remaining effect folds into the PARENT's
    // keyspace — a Task has no rows of its own. Under a recording
    // session, log the effects alongside the invoke output: replay
    // short-circuits the child, so re-absorbing the recorded effects
    // is the only way a rebuilt replica gets them.
    let child_state = payload.take_state_write().unwrap_or_else(|| state.to_vec());
    if !payload.effects.is_empty()
        && let crate::effect_log::EffectMode::Recording(s) = &mut *mode
    {
        s.record_invoke_effects(
            parent_svc_id,
            crate::refine_payload::encode_effects(&payload.effects),
        );
    }
    journal.absorb_effects(core::mem::take(&mut payload.effects), parent_svc_id);

    let status = if payload.continue_next {
        STATUS_YIELDED
    } else {
        STATUS_DONE
    };
    let mut out = Vec::with_capacity(1 + 4 + child_state.len() + payload.reply.len());
    out.push(status);
    out.extend_from_slice(&(child_state.len() as u32).to_le_bytes());
    out.extend_from_slice(&child_state);
    out.extend_from_slice(&payload.reply);
    record_and_write_invoke(caller, output_ptr, output_buf_len, &out, depth, mode)
}

/// Handle INVOKE: run a child PVM at PC=0 (refine). The child reads
/// storage via the parent's snapshot and writes effects into the
/// parent's journal, so nested invokes share the parent's commit.
#[allow(clippy::too_many_arguments)]
fn handle_invoke(
    caller: &mut InvocationKernel,
    parent_svc_id: u32,
    blobs: &[Vec<u8>],
    blob_by_hash: &HashMap<[u8; 32], usize>,
    task_witness: &HashMap<[u8; 32], (u32, u32)>,
    services: &HashMap<u32, ServiceInfo>,
    storage: &mut ServiceStorage,
    preimages: &HashMap<[u8; 32], Vec<u8>>,
    code_cache: &mut javm::CodeCache,
    journal: &mut RefineJournal,
    depth: usize,
    next_id: &mut u32,
    external_invoke: &Option<ExternalInvokeFn>,
    mode: &mut crate::effect_log::EffectMode,
) -> u64 {
    use crate::actors::run::{STATUS_NOT_FOUND, STATUS_OOG, STATUS_PANICKED};

    let hash_ptr = caller.active_reg(7) as u32;
    let input_ptr = caller.active_reg(8) as u32;
    let input_len = caller.active_reg(9) as usize;
    let gas_limit = caller.active_reg(10);
    // Output register is packed: low 32 bits are the PVM address,
    // high 32 bits are the buffer length. Legacy guests that
    // predate this packing pass 0 in the high bits, in which case
    // `record_and_write_invoke` skips the buffer cap and writes
    // unbounded (preserving prior behaviour).
    let output_packed = caller.active_reg(11);
    let output_ptr = output_packed as u32;
    let output_buf_len = (output_packed >> 32) as u32 as usize;

    // Replay fast path: at the top-level invoke under a replay
    // session, return the next recorded output instead of running
    // the child — and re-absorb the side effects the live child
    // folded into the journal (recorded alongside the output; the
    // short-circuit skips the child, but its effects are as much
    // recorded history as the output bytes — without this, every
    // replica rebuild silently dropped the rows/transfers a Task
    // produced). If the log is exhausted, or an effects record is
    // corrupt, surface STATUS_PANICKED — the rebuild has diverged.
    if depth == 1
        && let crate::effect_log::EffectMode::Replaying(replay) = mode
    {
        let (out, absorbed): (alloc::vec::Vec<u8>, alloc::vec::Vec<(u32, Vec<Effect>)>) =
            match replay.next_reply() {
                Some(bytes) => {
                    let bytes = bytes.to_vec();
                    let idx = replay.position() - 1;
                    let mut absorbed = alloc::vec::Vec::new();
                    let mut corrupt = false;
                    for rec in replay.effects_for(idx) {
                        match crate::refine_payload::decode_effects(&rec.effects) {
                            Some(effects) => absorbed.push((rec.svc_id, effects)),
                            None => {
                                corrupt = true;
                                break;
                            }
                        }
                    }
                    if corrupt {
                        (alloc::vec![STATUS_PANICKED], alloc::vec::Vec::new())
                    } else {
                        (bytes, absorbed)
                    }
                }
                None => (alloc::vec![STATUS_PANICKED], alloc::vec::Vec::new()),
            };
        for (svc, effects) in absorbed {
            journal.absorb_effects(effects, svc);
        }
        kwrite(caller, output_ptr, &out);
        return out.len() as u64;
    }

    if depth >= MAX_INVOKE_DEPTH {
        return record_and_write_invoke(
            caller,
            output_ptr,
            output_buf_len,
            &[STATUS_OOG],
            depth,
            mode,
        );
    }

    let code_hash = kread_hash(caller, hash_ptr);

    // Task mode: a full-hash invoke of a registered Task blob runs
    // witness-delivered — `(state, msg)` patched into the initial
    // image, no ServiceId, no storage row, effects folded into the
    // invoking parent's keyspace.
    if let Some(&(witness_addr, witness_cap)) = task_witness.get(&code_hash)
        && let Some(&blob_idx) = blob_by_hash.get(&code_hash)
        && let Some(blob) = blobs.get(blob_idx)
    {
        let input = kread(caller, input_ptr, input_len);
        let (state, row_keys, msg) = split_invoke_input(&input);
        // Resolve the caller-named row keys against the invoking
        // parent's EFFECTIVE keyspace (the same overlay its own reads
        // see) — a Task reads the parent's rows and folds its effects
        // back into the parent, so the parent names what the child may
        // see. Named-but-absent keys stage as proven-absent (the
        // witnessed read returns absent); only a key the caller never
        // named panics as unproven.
        let rows: alloc::vec::Vec<(Vec<u8>, Option<Vec<u8>>)> = row_keys
            .iter()
            .map(|key| {
                let value = journal
                    .effective_read(storage, parent_svc_id, key)
                    .map(|value| value.to_vec());
                (key.to_vec(), value)
            })
            .collect();
        let gas = if gas_limit == 0 {
            DEFAULT_GAS
        } else {
            gas_limit.min(DEFAULT_GAS)
        };
        return run_task_invoke(
            caller,
            blob,
            witness_addr,
            witness_cap,
            parent_svc_id,
            state,
            msg,
            &rows,
            gas,
            journal,
            code_cache,
            output_ptr,
            output_buf_len,
            depth,
            mode,
        );
    }

    // The actor framework's `service_code_hash(svc_id)` packs the
    // target ServiceId into the first 4 bytes of `code_hash` and
    // leaves the remaining 28 bytes zero. A genuine content-addressed
    // invoke fills the whole 32 bytes from a real blake2b hash —
    // those land in `blob_by_hash` directly. Anything else with
    // non-zero tail bytes is a malformed hash that we drop as
    // NOT_FOUND.
    let is_service_invoke = code_hash[4..].iter().all(|&b| b == 0);
    let target_svc_id = if is_service_invoke {
        ServiceId(u32::from_le_bytes([
            code_hash[0],
            code_hash[1],
            code_hash[2],
            code_hash[3],
        ]))
    } else {
        ServiceId(0)
    };

    let blob_idx = if let Some(&idx) = blob_by_hash.get(&code_hash) {
        idx
    } else if is_service_invoke {
        // Explicit ServiceId invoke — look up in the services map.
        // ServiceId(0) (== `ServiceId::REGISTRY`) is a real,
        // resolvable target now that the registry actor lives there;
        // the previous `!= 0` guard predated the registry and would
        // have always rejected `ctx.resolve(...)` calls.
        match services.get(&target_svc_id.0) {
            Some(info) => info.blob_idx,
            None => {
                // Target not in this runtime — try external invoke
                // (worker on another thread, agent on another thread,
                // or peer over the network). The handler reports
                // whether the target yielded so the caller's PVM
                // sees the same status it would for a same-runtime
                // INVOKE; the runtime packs the wire envelope here.
                if let Some(handler) = external_invoke {
                    let input = kread(caller, input_ptr, input_len);
                    // Extract message from invoke input: [state_len:u32][state][msg]
                    let msg = if input.len() >= 4 {
                        let state_len = u32::from_le_bytes(input[..4].try_into().unwrap()) as usize;
                        let msg_start = (4 + state_len).min(input.len());
                        input[msg_start..].to_vec()
                    } else {
                        input
                    };
                    if let Some(reply) = handler(target_svc_id, &msg) {
                        let (status, state, reply_bytes) = match reply {
                            ExternalInvokeReply::Done(r) => {
                                (crate::actors::run::STATUS_DONE, Vec::new(), r)
                            }
                            ExternalInvokeReply::Yielded { state, reply } => {
                                (crate::actors::run::STATUS_YIELDED, state, reply)
                            }
                        };
                        let mut output = Vec::with_capacity(5 + state.len() + reply_bytes.len());
                        output.push(status);
                        output.extend_from_slice(&(state.len() as u32).to_le_bytes());
                        output.extend_from_slice(&state);
                        output.extend_from_slice(&reply_bytes);
                        return record_and_write_invoke(
                            caller,
                            output_ptr,
                            output_buf_len,
                            &output,
                            depth,
                            mode,
                        );
                    }
                }
                return record_and_write_invoke(
                    caller,
                    output_ptr,
                    output_buf_len,
                    &[STATUS_NOT_FOUND],
                    depth,
                    mode,
                );
            }
        }
    } else {
        return record_and_write_invoke(
            caller,
            output_ptr,
            output_buf_len,
            &[STATUS_NOT_FOUND],
            depth,
            mode,
        );
    };
    let blob = match blobs.get(blob_idx) {
        Some(b) => b,
        None => {
            return record_and_write_invoke(
                caller,
                output_ptr,
                output_buf_len,
                &[STATUS_NOT_FOUND],
                depth,
                mode,
            );
        }
    };

    let input = kread(caller, input_ptr, input_len);

    let gas = if gas_limit == 0 {
        DEFAULT_GAS
    } else {
        gas_limit.min(DEFAULT_GAS)
    };

    let mut child = match InvocationKernel::new_cached(blob, &[], gas, code_cache) {
        Ok(k) => k,
        Err(_) => {
            return record_and_write_invoke(
                caller,
                output_ptr,
                output_buf_len,
                &[STATUS_PANICKED],
                depth,
                mode,
            );
        }
    };
    install_vos_precompile_caps(&mut child);
    child.set_active_reg(7, 0); // refine
    let _ = child
        .vm_arena
        .vm_mut(0)
        .transition(javm::vm_pool::VmState::Running);

    // Delimit this child invoke's journal contributions — the state
    // delivery below, the child's own hostcall writes, and anything a
    // grandchild absorbed — so a trap or a rejected work-result inside
    // the nested run discards them whole. The top-level dispatch mark
    // only protects the PARENT's dispatch boundary; without this nested
    // mark, a caught child panic (surfaced as an error status the
    // parent handles) would leave the child's partial writes in the
    // journal and commit them with the parent's tick.
    let invoke_mark = journal.mark();

    // Unpack invoke input: [state_len:u32 LE][state][msg].
    // Journal the state onto the child's row under STATE_KEY so service
    // children (run_refine_service) can cold-start via READ — through
    // the journal, not a direct storage write, so a trapped dispatch
    // rolls it back with everything else. Only the message is delivered
    // as a FETCH item: a state item would be consumed by the service
    // child's message loop, where an empty one (fresh spawn) reads as
    // "no more mail" and stops the loop before the message arrives, and
    // a non-empty one mis-dispatches as a message. The FETCH-delivered
    // state channel (`run_refine` legacy children) is retired; READ is
    // the one state channel.
    let mut child_items = if input.len() >= 4 {
        let state_len = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
        let state_end = (4 + state_len).min(input.len());
        let state = &input[4..state_end];

        if !state.is_empty() {
            journal.writes.push((
                target_svc_id.0,
                crate::lifecycle::STATE_KEY_BYTES.to_vec(),
                Some(state.to_vec()),
            ));
        }

        if state_end < input.len() {
            vec![input[state_end..].to_vec()]
        } else {
            Vec::new()
        }
    } else {
        vec![input]
    };

    // The state the child will observe as its prior state — the journal
    // overlay (the delivery write above included) falling back to
    // committed storage. This is what the child's v3 anchor must commit
    // to, and what the envelope echoes when the child's state is
    // unchanged, so parents always see the authoritative full state.
    let child_prior_state: Vec<u8> = journal
        .effective_read(storage, target_svc_id.0, crate::lifecycle::STATE_KEY_BYTES)
        .map(|v| v.to_vec())
        .unwrap_or_default();

    loop {
        match child.run() {
            KernelResult::Halt => break,
            KernelResult::Panic => {
                let pc = child.vm_arena.vm(child.active_vm).pc;
                error!(pc, ?target_svc_id, "child invoke panicked");
                journal.rollback_to(invoke_mark);
                return record_and_write_invoke(
                    caller,
                    output_ptr,
                    output_buf_len,
                    &[STATUS_PANICKED],
                    depth,
                    mode,
                );
            }
            KernelResult::OutOfGas => {
                journal.rollback_to(invoke_mark);
                return record_and_write_invoke(
                    caller,
                    output_ptr,
                    output_buf_len,
                    &[STATUS_OOG],
                    depth,
                    mode,
                );
            }
            KernelResult::PageFault(_addr) => {
                journal.rollback_to(invoke_mark);
                return record_and_write_invoke(
                    caller,
                    output_ptr,
                    output_buf_len,
                    &[STATUS_PANICKED],
                    depth,
                    mode,
                );
            }
            KernelResult::ProtocolCall { slot } => {
                // Nested invokes by the child actor are not part
                // of the caller's recording/replay session. Feed
                // them an Inactive mode so they run normally.
                let mut child_mode = crate::effect_log::EffectMode::Inactive;
                handle_refine_hostcall(
                    &mut child,
                    slot as u32,
                    &mut child_items,
                    target_svc_id.0,
                    journal,
                    storage,
                    preimages,
                    blobs,
                    blob_by_hash,
                    task_witness,
                    services,
                    code_cache,
                    depth,
                    next_id,
                    external_invoke,
                    &mut child_mode,
                );
            }
        }
    }

    // Copy the child's halt output into the caller's output buffer.
    // If the child is a service (outputs RefinePayload), run the
    // child-invoke conversion — the fourth applier of the work-result
    // contract (§4b): the child's final Write{STATE_KEY} becomes the
    // envelope's state field and is STRIPPED before absorb, so child
    // state travels to the *parent*, never to a child storage row.
    let out_ptr = child.active_reg(7) as u32;
    let out_len = (child.active_reg(8) as usize).min(1 << 20);
    let raw_output = kread(&child, out_ptr, out_len);

    let output = if let Some(mut payload) = RefinePayload::decode(&raw_output) {
        // Parity check: a v3 child's anchor must commit to exactly the
        // state the host staged for it — or, for a committed-storage
        // child, the composite root its own keyspace recorded (read
        // through the same journal overlay; see `expected_anchor`).
        // A mismatch means a buggy guest or a doctored blob — apply
        // nothing, surface a crash.
        if payload.version == crate::refine_payload::REFINE_PAYLOAD_VERSION {
            let expected = if let Some(root) = journal.effective_read(
                storage,
                target_svc_id.0,
                crate::lifecycle::COMMITTED_ROOT_KEY,
            ) && root.len() == 32
            {
                let mut anchor = [0u8; 32];
                anchor.copy_from_slice(root);
                (crate::refine_payload::ANCHOR_SMT_ROOT, anchor)
            } else {
                crate::refine_payload::anchor_for(Some(&child_prior_state))
            };
            if (payload.anchor_kind, payload.anchor) != expected {
                error!(?target_svc_id, "child invoke: work-result anchor mismatch");
                journal.rollback_to(invoke_mark);
                return record_and_write_invoke(
                    caller,
                    output_ptr,
                    output_buf_len,
                    &[STATUS_PANICKED],
                    depth,
                    mode,
                );
            }
        }

        // When the child emitted no state write (state unchanged), echo
        // the state the host delivered so scheduler-style TaskRecords
        // are never silently emptied. Under a recording session, log
        // the child's effects alongside the invoke output — replay
        // short-circuits the child, so re-absorbing the record is the
        // only way a rebuilt replica's journal sees them.
        let child_state = payload
            .take_state_write()
            .unwrap_or_else(|| child_prior_state.clone());
        if !payload.effects.is_empty()
            && let crate::effect_log::EffectMode::Recording(s) = &mut *mode
        {
            s.record_invoke_effects(
                target_svc_id.0,
                crate::refine_payload::encode_effects(&payload.effects),
            );
        }
        journal.absorb_effects(core::mem::take(&mut payload.effects), target_svc_id.0);

        let status = if payload.continue_next {
            crate::actors::run::STATUS_YIELDED
        } else {
            crate::actors::run::STATUS_DONE
        };
        let sl = (child_state.len() as u32).to_le_bytes();
        let mut out = Vec::with_capacity(1 + 4 + child_state.len() + payload.reply.len());
        out.push(status);
        out.extend_from_slice(&sl);
        out.extend_from_slice(&child_state);
        out.extend_from_slice(&payload.reply);
        out
    } else if claims_refine_payload(&raw_output) {
        // Claims a payload version but doesn't decode — fail loud.
        error!(?target_svc_id, "child invoke: malformed work-result");
        journal.rollback_to(invoke_mark);
        alloc::vec![STATUS_PANICKED]
    } else {
        raw_output
    };

    record_and_write_invoke(caller, output_ptr, output_buf_len, &output, depth, mode)
}

/// Capture a continuation: hash flat_mem, store in the data layer, and
/// record the ContinuationHeader directly in storage. Host bookkeeping —
/// deliberately not journaled, so it is never part of a work-result's
/// apply scope and never shadows a payload's state write.
fn save_continuation<D: crate::data_layer::DataLayer>(
    svc_id: u32,
    flat_mem: Vec<u8>,
    heap_base: u32,
    heap_top: u32,
    data: &mut D,
    storage: &mut ServiceStorage,
) {
    let commitment = crate::pvm_image::commit(&flat_mem);
    let flat_mem_len = flat_mem.len() as u32;
    pollster::block_on(data.put(commitment, flat_mem));
    let header = crate::pvm_image::ContinuationHeader {
        pc: 0,
        heap_base,
        heap_top,
        need_gas_charge: false,
        iters: 0,
        flat_mem_len,
        commitment,
        registers: [0; 13],
    };
    storage.write(
        ServiceId(svc_id),
        crate::lifecycle::CONTINUATION_HEADER_KEY,
        &header.encode(),
    );
}

/// Load a continuation for a service: read header from storage (checking
/// journal first for read-your-own-writes), fetch the body from the data
/// layer, and return `Some((flat_mem, heap_base, heap_top))`.
fn load_continuation<D: crate::data_layer::DataLayer>(
    storage: &ServiceStorage,
    data: &D,
    svc_id: u32,
) -> Option<(Vec<u8>, u32, u32)> {
    let id = ServiceId(svc_id);
    let header_bytes = storage.read(id, crate::lifecycle::CONTINUATION_HEADER_KEY)?;
    if header_bytes.is_empty() {
        return None;
    }
    let header = crate::pvm_image::ContinuationHeader::decode(header_bytes)?;
    let body = pollster::block_on(data.get(&header.commitment))?;
    Some((body, header.heap_base, header.heap_top))
}

/// Clear any prior continuation for a service: remove the body from the
/// data layer and delete the header row directly. Host bookkeeping —
/// never journaled, and it must never touch `STATE_KEY` (an empty state
/// write here would clobber the payload's state under last-wins and
/// break the next dispatch's anchor). State teardown, if ever intended,
/// must be an explicit guest-emitted effect. No-op if the service has no
/// continuation.
fn clear_continuation<D: crate::data_layer::DataLayer>(
    storage: &mut ServiceStorage,
    data: &mut D,
    svc_id: u32,
) {
    let id = ServiceId(svc_id);
    let header_bytes = match storage.read(id, crate::lifecycle::CONTINUATION_HEADER_KEY) {
        Some(b) if !b.is_empty() => b,
        _ => return, // no prior continuation — nothing to clean up
    };
    if let Some(header) = crate::pvm_image::ContinuationHeader::decode(header_bytes) {
        pollster::block_on(data.remove(&header.commitment));
    }
    storage.delete(id, crate::lifecycle::CONTINUATION_HEADER_KEY);
}

/// blake2b-256 content hash keying `blob_by_hash`. Collision-resistant, so
/// a code-hash-identified INVOKE cannot be pointed at a forged blob — the
/// prior XOR fold was trivially collidable.
fn blob_hash(data: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b::blake2b_hash::<32>(b"vos/blob-addr/v1", &[data])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gas_config_default_refine_gas() {
        let g = GasConfig::default();
        assert_eq!(g.refine_gas, DEFAULT_GAS);
    }

    #[test]
    fn runtime_with_gas_config_uses_overrides() {
        let g = GasConfig { refine_gas: 12_345 };
        let rt = VosRuntime::with_gas_config(g);
        let cfg = rt.gas_config();
        assert_eq!(cfg.refine_gas, 12_345);
    }

    #[test]
    fn blob_hash_content_addresses_registered_blobs() {
        // blake2b keying is deterministic, distinguishes near-identical
        // blobs (the old XOR fold collided readily), and register_blob's
        // key resolves back to the blob index.
        let a = vec![1u8, 2, 3];
        let b = vec![1u8, 2, 4];
        assert_ne!(blob_hash(&a), blob_hash(&b));
        assert_eq!(blob_hash(&a), blob_hash(&a));

        let mut rt = VosRuntime::new();
        let idx = rt.register_blob(a.clone());
        assert_eq!(rt.blob_by_hash.get(&blob_hash(&a)), Some(&idx));
    }

    // ── Work-result apply parity (v2 vs v3) ─────────────────────────
    //
    // The one property the version negotiation must hold: a v2 payload
    // and the v3 payload describing the same logical transition absorb
    // into byte-identical journal contents. These drive the same
    // `absorb_work_result` the tick loop uses.

    fn state_key() -> Vec<u8> {
        crate::lifecycle::STATE_KEY_BYTES.to_vec()
    }

    fn drain_to_storage(journal: &mut RefineJournal, storage: &mut ServiceStorage) {
        for (svc, key, value) in journal.writes.drain(..) {
            match &value {
                Some(v) => storage.write(ServiceId(svc), &key, v),
                None => storage.delete(ServiceId(svc), &key),
            }
        }
    }

    #[test]
    fn v2_and_v3_absorb_identically() {
        use crate::refine_payload::{self, Effect, RefinePayload, anchor_for};

        let svc = 7u32;
        let prior_state = b"prior".to_vec();
        let new_state = b"new-state".to_vec();
        let effects = vec![
            Effect::Write {
                key: b"row".to_vec(),
                value: vec![1, 2],
            },
            Effect::Transfer {
                target: 9,
                memo: b"memo".to_vec(),
            },
        ];

        // v2: state as an explicit field on the wire.
        let v2_bytes =
            refine_payload::encode_v2(&new_state, b"reply", &effects, false, false);

        // v3: state as the final Write{STATE_KEY} + a verified anchor.
        let (anchor_kind, anchor) = anchor_for(Some(&prior_state));
        let mut v3_effects = effects.clone();
        v3_effects.push(Effect::Write {
            key: state_key(),
            value: new_state.clone(),
        });
        let v3_bytes = RefinePayload {
            anchor_kind,
            anchor,
            reply: b"reply".to_vec(),
            effects: v3_effects,
            ..RefinePayload::new()
        }
        .encode();

        let run = |bytes: &[u8]| {
            let mut storage = ServiceStorage::new();
            storage.write(ServiceId(svc), crate::lifecycle::STATE_KEY_BYTES, &prior_state);
            let mut journal = RefineJournal::default();
            let payload = RefinePayload::decode(bytes).expect("decodes");
            let absorbed =
                absorb_work_result(&mut journal, &storage, svc, payload).expect("applies");
            let writes = journal.writes.clone();
            let transfers = journal.transfers.clone();
            drain_to_storage(&mut journal, &mut storage);
            let end_state = storage
                .read(ServiceId(svc), crate::lifecycle::STATE_KEY_BYTES)
                .map(|v| v.to_vec());
            (writes, transfers, end_state, absorbed.reply)
        };

        let (w2, t2, s2, r2) = run(&v2_bytes);
        let (w3, t3, s3, r3) = run(&v3_bytes);
        assert_eq!(w2, w3, "journal writes must match across versions");
        assert_eq!(t2, t3, "journal transfers must match across versions");
        assert_eq!(s2, s3, "end-of-tick state must match across versions");
        assert_eq!(s2.as_deref(), Some(new_state.as_slice()));
        assert_eq!(r2, r3);
    }

    #[test]
    fn v3_anchor_checks_against_journal_overlay() {
        use crate::refine_payload::{Effect, RefinePayload, anchor_for};

        // Iteration N's anchor is the hash of iteration N−1's final
        // state, which lives only in the journal until end of tick —
        // the check must pass against the overlay, and a check against
        // committed storage alone would have rejected it.
        let svc = 3u32;
        let mut storage = ServiceStorage::new();
        storage.write(ServiceId(svc), crate::lifecycle::STATE_KEY_BYTES, b"s0");
        let mut journal = RefineJournal::default();

        let mk = |prior: &[u8], next: &[u8]| {
            let (anchor_kind, anchor) = anchor_for(Some(prior));
            RefinePayload {
                anchor_kind,
                anchor,
                effects: vec![Effect::Write {
                    key: state_key(),
                    value: next.to_vec(),
                }],
                ..RefinePayload::new()
            }
        };

        // Iteration 1: anchors committed storage (s0), writes s1.
        absorb_work_result(&mut journal, &storage, svc, mk(b"s0", b"s1"))
            .expect("iteration 1 applies");
        // Iteration 2: anchors the OVERLAY state (s1), not storage (s0).
        absorb_work_result(&mut journal, &storage, svc, mk(b"s1", b"s2"))
            .expect("iteration 2 must verify against the journal overlay");
        // A stale anchor (still s0) must reject.
        let err = absorb_work_result(&mut journal, &storage, svc, mk(b"s0", b"s3"))
            .expect_err("stale anchor must reject");
        assert_eq!(err, WorkResultError::AnchorMismatch);
        // Nothing from the rejected work-result applied.
        assert_eq!(
            journal.journaled_read(svc, crate::lifecycle::STATE_KEY_BYTES),
            Some(Some(&b"s2"[..])),
        );
    }

    #[test]
    fn v3_smt_anchor_follows_the_committed_root_row() {
        use crate::refine_payload::{ANCHOR_SMT_ROOT, Effect, RefinePayload, anchor_for};

        // A committed-storage actor's expected anchor is its recorded
        // composite-root row — read through the journal overlay, so a
        // work-result that rewrites the row advances the expectation
        // for the next chained iteration, exactly like the state blob.
        let svc = 4u32;
        let mut storage = ServiceStorage::new();
        storage.write(ServiceId(svc), crate::lifecycle::STATE_KEY_BYTES, b"s0");
        storage.write(
            ServiceId(svc),
            crate::lifecycle::COMMITTED_ROOT_KEY,
            &[0xc1; 32],
        );
        let mut journal = RefineJournal::default();

        // A blob-hash claim must reject once a composite row exists.
        let (k, a) = anchor_for(Some(b"s0"));
        let stale = RefinePayload {
            anchor_kind: k,
            anchor: a,
            ..RefinePayload::new()
        };
        assert_eq!(
            absorb_work_result(&mut journal, &storage, svc, stale).expect_err("0x01 vs 0x02"),
            WorkResultError::AnchorMismatch,
        );

        // The 0x02 claim matching the row applies — and its effects
        // (a new composite row) advance the expectation in-overlay.
        let ok = RefinePayload {
            anchor_kind: ANCHOR_SMT_ROOT,
            anchor: [0xc1; 32],
            effects: vec![Effect::Write {
                key: crate::lifecycle::COMMITTED_ROOT_KEY.to_vec(),
                value: alloc::vec![0xc2; 32],
            }],
            ..RefinePayload::new()
        };
        absorb_work_result(&mut journal, &storage, svc, ok).expect("0x02 matches the row");

        let stale2 = RefinePayload {
            anchor_kind: ANCHOR_SMT_ROOT,
            anchor: [0xc1; 32],
            ..RefinePayload::new()
        };
        assert_eq!(
            absorb_work_result(&mut journal, &storage, svc, stale2)
                .expect_err("stale composite must reject"),
            WorkResultError::AnchorMismatch,
        );
        let next = RefinePayload {
            anchor_kind: ANCHOR_SMT_ROOT,
            anchor: [0xc2; 32],
            ..RefinePayload::new()
        };
        absorb_work_result(&mut journal, &storage, svc, next)
            .expect("the overlay-advanced composite is the expectation");
    }

    #[test]
    fn scan_prefix_is_key_ordered_and_service_scoped() {
        let mut storage = ServiceStorage::new();
        let svc = ServiceId(1);
        storage.write(svc, b"s/acct/b", b"2");
        storage.write(svc, b"s/acct/a", b"1");
        storage.write(svc, b"s/acct/c", b"3");
        storage.write(svc, b"s/other/x", b"9");
        storage.write(ServiceId(2), b"s/acct/z", b"0");
        storage.delete(svc, b"s/acct/c");

        let rows: Vec<(&[u8], &[u8])> = storage.scan_prefix(svc, b"s/acct/").collect();
        assert_eq!(
            rows,
            vec![
                (&b"s/acct/a"[..], &b"1"[..]),
                (&b"s/acct/b"[..], &b"2"[..]),
            ],
            "prefix scan must be key-ordered, prefix-bounded, and blind \
             to other services' rows"
        );
    }

    #[test]
    fn clear_service_drops_only_that_services_rows() {
        let mut storage = ServiceStorage::new();
        let svc = ServiceId(1);
        // A mix of STATE, storage-type, and framework rows.
        storage.write(svc, crate::lifecycle::STATE_KEY_BYTES, b"state");
        storage.write(svc, b"s/log/l", &2u64.to_le_bytes());
        storage.write(svc, b"s/log/e\x00\x00\x00\x00\x00\x00\x00\x00", b"a");
        storage.write(svc, crate::lifecycle::INIT_KEY, b"init-args");
        storage.write(svc, crate::lifecycle::CONTINUATION_HEADER_KEY, b"cont");
        // A second service must be untouched.
        storage.write(ServiceId(2), b"s/log/l", &9u64.to_le_bytes());

        storage.clear_service(svc);

        assert_eq!(storage.read(svc, crate::lifecycle::STATE_KEY_BYTES), None);
        assert_eq!(storage.read(svc, b"s/log/l"), None);
        assert_eq!(storage.read(svc, crate::lifecycle::INIT_KEY), None);
        assert_eq!(
            storage.read(svc, crate::lifecycle::CONTINUATION_HEADER_KEY),
            None,
            "clearing a service drops its warm continuation, forcing a cold replay",
        );
        assert_eq!(
            storage.read(ServiceId(2), b"s/log/l"),
            Some(&9u64.to_le_bytes()[..]),
            "clear is service-scoped",
        );
    }

    #[test]
    fn delete_effect_tombstones_and_drains() {
        use crate::refine_payload::{Effect, RefinePayload};

        let svc = 5u32;
        let mut storage = ServiceStorage::new();
        storage.write(ServiceId(svc), b"committed", b"old");
        let mut journal = RefineJournal::default();

        let payload = RefinePayload {
            effects: vec![
                Effect::Write {
                    key: b"fresh".to_vec(),
                    value: vec![1],
                },
                Effect::Delete {
                    key: b"fresh".to_vec(),
                },
                Effect::Delete {
                    key: b"committed".to_vec(),
                },
                Effect::Delete {
                    key: b"reborn".to_vec(),
                },
                Effect::Write {
                    key: b"reborn".to_vec(),
                    value: vec![2],
                },
            ],
            ..RefinePayload::new()
        };
        absorb_work_result(&mut journal, &storage, svc, payload).expect("applies");

        // Last-wins per key through the overlay: a tombstone shadows
        // both the same-tick write and the committed row, and a write
        // after a tombstone resurrects the key.
        assert_eq!(journal.effective_read(&storage, svc, b"fresh"), None);
        assert_eq!(journal.effective_read(&storage, svc, b"committed"), None);
        assert_eq!(
            journal.effective_read(&storage, svc, b"reborn"),
            Some(&[2u8][..]),
        );
        // Raw storage still holds the committed row until drain.
        assert_eq!(
            storage.read(ServiceId(svc), b"committed"),
            Some(&b"old"[..]),
        );

        drain_to_storage(&mut journal, &mut storage);
        assert_eq!(storage.read(ServiceId(svc), b"fresh"), None);
        assert_eq!(storage.read(ServiceId(svc), b"committed"), None);
        assert_eq!(storage.read(ServiceId(svc), b"reborn"), Some(&[2u8][..]));
    }

    #[test]
    fn v3_genesis_anchor_requires_absent_or_empty_state() {
        use crate::refine_payload::RefinePayload;

        let svc = 4u32;
        let storage = ServiceStorage::new();
        let mut journal = RefineJournal::default();

        // Fresh service: genesis applies.
        absorb_work_result(&mut journal, &storage, svc, RefinePayload::new())
            .expect("genesis against absent state applies");

        // Existing state: genesis rejects.
        let mut seeded = ServiceStorage::new();
        seeded.write(ServiceId(svc), crate::lifecycle::STATE_KEY_BYTES, b"present");
        let err = absorb_work_result(&mut journal, &seeded, svc, RefinePayload::new())
            .expect_err("genesis against present state must reject");
        assert_eq!(err, WorkResultError::AnchorMismatch);

        // Empty-value STATE_KEY row counts as genesis (ServiceStorage
        // stores empty writes as present).
        let mut empty_row = ServiceStorage::new();
        empty_row.write(ServiceId(svc), crate::lifecycle::STATE_KEY_BYTES, b"");
        absorb_work_result(&mut journal, &empty_row, svc, RefinePayload::new())
            .expect("genesis against empty state applies");
    }

    #[test]
    fn v2_payloads_skip_anchor_checks() {
        use crate::refine_payload::{self, RefinePayload};

        // A v2 guest knows nothing about anchors; its payload applies
        // against any prior state.
        let svc = 5u32;
        let mut storage = ServiceStorage::new();
        storage.write(ServiceId(svc), crate::lifecycle::STATE_KEY_BYTES, b"whatever");
        let mut journal = RefineJournal::default();
        let bytes = refine_payload::encode_v2(b"next", b"", &[], false, false);
        let payload = RefinePayload::decode(&bytes).unwrap();
        let absorbed =
            absorb_work_result(&mut journal, &storage, svc, payload).expect("v2 applies");
        assert_eq!(absorbed.anchor, None);
        assert!(!absorbed.effect_bearing, "v2 never sets effect_bearing");
    }

    #[test]
    fn journal_absorb_new_service() {
        let mut journal = RefineJournal::default();
        let code_hash = [0x42u8; 32];
        journal.absorb_effects(
            vec![
                crate::refine_payload::Effect::Provide {
                    hash: code_hash,
                    data: vec![0xDE, 0xAD],
                },
                crate::refine_payload::Effect::New { code_hash },
            ],
            1, // self_id
        );
        assert_eq!(journal.preimages.len(), 1);
        assert_eq!(journal.preimages[0].0, code_hash);
        assert_eq!(journal.new_services.len(), 1);
        assert_eq!(journal.new_services[0].0, code_hash);
    }

    #[test]
    fn new_service_registered_after_tick() {
        // Verify that PROVIDE + NEW during refine results in the service
        // being registered after the tick commits.
        let mut rt = VosRuntime::new();
        let code_hash = blob_hash(&[0xAB; 16]);
        // Pre-populate preimages with a dummy "code blob"
        rt.preimages.insert(code_hash, vec![0xAB; 16]);

        // Simulate: journal records a NEW with this hash
        let assigned_id = rt.next_id;
        rt.next_id += 1;
        let blob = rt.preimages.get(&code_hash).cloned().unwrap();
        let blob_idx = rt.register_blob(blob);
        rt.services.insert(
            assigned_id,
            ServiceInfo {
                blob_idx,
                alive: true,
            },
        );

        assert!(rt.services.contains_key(&assigned_id));
        assert!(rt.services.get(&assigned_id).unwrap().alive);
    }
}
