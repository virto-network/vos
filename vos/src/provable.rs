//! Durable provable-transition records (`docs/plans/provable.md` W2).
//!
//! When a parent invokes a provable Task with a record tag (see
//! `lifecycle::INVOKE_INPUT_RECORD` / `agent::Tasks::spawn_provable`), the
//! host captures — into the invoking parent's own committed keyspace — what
//! a proof of that transition needs later, split by audience:
//!
//! - [`ProvableInput`] — the exact witness bytes (`encode_task_input_with_rows`
//!   output) plus the task hash. This is the complete SECRET: it re-traces
//!   the invocation bit-for-bit to the same io-hash, and never leaves the
//!   producing operator.
//! - [`ProvableRecord`] — the VERIFIER-facing summary: the framework anchor,
//!   transition digest, reply, and the bound io-hash (φ[9..12]). It carries
//!   no witnessed leaf values.
//!
//! Both are stored together as a [`ProofRecordEntry`] under the reserved
//! `__vos_proofrec/<tag>` row, so they ride the parent's ordinary commit —
//! surviving restart and CRDT/Raft replay (A10 short-circuits the child on
//! replay, so a record could not "regenerate"; it must be persisted state).
//! The app prunes a record once its proof is published (a
//! `Delete{__vos_proofrec/<tag>}` effect).
//!
//! `app_public` (the app-designated roots/bytes bound into the io-hash) and
//! the `catalog_name`/`catalog_version` a verifier checks against are added
//! in W3, where the verify surface consumes them — capturing them needs a
//! payload-surface change (the io-hash folds `app_public` and discards it
//! today) and a catalog lookup this layer doesn't yet perform.

use alloc::vec::Vec;

/// Reserved storage prefix for durable proof records. Under the `__vos_`
/// namespace, so no user storage prefix can collide.
pub const PROOFREC_PREFIX: &[u8] = b"__vos_proofrec/";

/// The row key a `(svc, tag)` record is stored under in the parent's
/// keyspace — `__vos_proofrec/` followed by the caller's 32-byte tag.
pub fn proofrec_key(tag: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(PROOFREC_PREFIX.len() + 32);
    key.extend_from_slice(PROOFREC_PREFIX);
    key.extend_from_slice(tag);
    key
}

/// Prover-only material: the complete secret that re-traces the proved
/// invocation. Never ships to a counterparty.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProvableInput {
    /// The invoked Task's content-address (the blob hash).
    pub task_hash: [u8; 32],
    /// The exact bytes patched into `__VOS_WITNESS` for this invocation
    /// (`task_abi::encode_task_input_with_rows` output — state, msg,
    /// witnessed rows). Re-tracing this against the cataloged blob
    /// reproduces the invocation, and its bound io-hash.
    pub witness_bytes: Vec<u8>,
}

/// Verifier-facing summary of a proved transition. Carries no witnessed
/// leaf values — safe to ship to a counterparty.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProvableRecord {
    /// The invoked Task's content-address (routing/CAS, not identity —
    /// identity is the commitment allowlist).
    pub task_hash: [u8; 32],
    /// Framework anchor over the Task's delivered state (`0x01`, or
    /// `0x00` genesis) — the entering state bound in `public'`.
    pub anchor_kind: u8,
    pub anchor: [u8; 32],
    /// Digest of the applied effects (`work-result-contract.md` §5).
    pub transition_digest: [u8; 32],
    /// The Task's reply bytes.
    pub reply: Vec<u8>,
    /// The bound io-hash read from φ[9..12] at halt — the value the
    /// proof carries as its `public_io_hash`.
    pub io_hash: [u8; 32],
}

/// The `(input, record)` pair stored under one `__vos_proofrec/<tag>` row.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ProofRecordEntry {
    pub input: ProvableInput,
    pub record: ProvableRecord,
}

impl ProofRecordEntry {
    /// Serialize to the bytes stored in the `__vos_proofrec/<tag>` row.
    pub fn encode(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .expect("ProofRecordEntry rkyv-encodes")
            .to_vec()
    }

    /// Decode a stored record row; `None` on a corrupt/foreign row.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes).ok()
    }
}
