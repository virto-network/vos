//! Durable provable-transition records (`docs/plans/provable.md` W2/W3).
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
//!   transition digest, reply, app-public bytes, and the bound io-hash
//!   (φ[9..12]). It carries no witnessed leaf values.
//!
//! Both are stored together as a [`ProofRecordEntry`] under the reserved
//! `__vos_proofrec/<tag>` row, so they ride the parent's ordinary commit —
//! surviving restart and CRDT/Raft replay (A10 short-circuits the child on
//! replay, so a record could not "regenerate"; it must be persisted state).
//! The app prunes a record once its proof is published (a
//! `Delete{__vos_proofrec/<tag>}` effect).
//!
//! ## The verify equation (W3)
//!
//! The record is UNTRUSTED courier material; every check re-derives from
//! the proof or the verifier's own knowledge. The io-hash the guest binds
//! at halt is
//!
//! ```text
//! io_hash = compute_io_hash(public', reply)
//! public' = anchor_kind ‖ anchor ‖ transition_digest ‖ app_public
//! ```
//!
//! so [`ProvableRecord::io_consistent`] (recompute `public'` from the
//! record's own fields and check the hash) plus a chain-verify that pins
//! the FINAL segment's `public_io_hash` to `compute_io_hash(public',
//! reply)` together force every record field to be exactly what the
//! proven execution bound — a tampered anchor, digest, reply, or
//! app-public shifts `public'` and fails one of the two.
//!
//! ## The `app_public` root convention
//!
//! `app_public` is app-designated (the guest's `vos::zk::bind_public`),
//! but a provable Task that attests state roots MUST lead it with
//! `root_before` (32 bytes) — typically followed by `root_after` — so a
//! third party can compare [`ProvableRecord::root_before`] against the
//! prior state it independently knows (`verify_record`'s
//! `expected_root_before`, the settlement check). Absent that check a
//! verifier learns "some transition between these roots was proven", not
//! "a transition over the state I know".
//!
//! ## Catalog identity
//!
//! `catalog_name`/`catalog_version` route a verifier to the allowlist
//! entry the chain must verify against (`docs/plans/provable.md` D5).
//! They are EMPTY at capture — the runtime holds no catalog — and are
//! resolved at prove time by matching the catalog pin whose `blob_hash`
//! equals the record's `task_hash` (unambiguous and stable across
//! re-pins, because the catalog is append-versioned and a record's
//! task_hash names the exact blob that ran). They are routing metadata,
//! not identity: identity is the commitment allowlist the chain verifies
//! against, and a lying name/version simply fails the chain check.

use alloc::string::String;
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

/// Content-address of a registered program blob — the hash parents
/// invoke Tasks by ([`crate::runtime`]'s blob registry) and the value a
/// catalog pin records as `blob_hash` so `prove_record` can resolve a
/// record's pin. ONE definition, shared by the runtime, `vosx zk pin`,
/// and the verify surface, so the join key cannot drift.
pub fn task_blob_hash(blob: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b::blake2b_hash::<32>(b"vos/blob-addr/v1", &[blob])
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
    /// App-designated public bytes the guest bound via
    /// `vos::zk::bind_public` — folded into `public'` at halt and
    /// surfaced by the v4 work-result. Leads with `root_before` (32
    /// bytes) for root-attesting Tasks (see the module docs).
    pub app_public: Vec<u8>,
    /// Catalog identity of the pin whose allowlist verifies this
    /// record's chain. Empty at capture; the PROVE FLOW's catalog
    /// holder (`vosx zk prove`, via `ProvableCatalog::find_blob` on
    /// `task_hash`) fills it into the shipped record — the prover
    /// extension itself is catalog-free and never touches these fields.
    pub catalog_name: String,
    /// The append-versioned catalog entry this record proves under
    /// (`0` = unresolved).
    pub catalog_version: u32,
}

impl ProvableRecord {
    /// Serialize to the bytes a producer ships to a verifier.
    pub fn encode(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .expect("ProvableRecord rkyv-encodes")
            .to_vec()
    }

    /// Decode a shipped record; `None` on malformed bytes.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        rkyv::from_bytes::<Self, rkyv::rancor::Error>(bytes).ok()
    }

    /// Reconstruct `public'` from this record's own fields — the exact
    /// bytes the guest folded at halt (`work-result-contract.md` §5).
    pub fn public_prime(&self) -> Vec<u8> {
        crate::refine_payload::folded_public(
            self.anchor_kind,
            &self.anchor,
            &self.transition_digest,
            &self.app_public,
        )
    }

    /// The record's internal binding equation:
    /// `compute_io_hash(public', reply) == io_hash`. Every verify path
    /// runs this first — a record that fails it cannot correspond to ANY
    /// execution, tampered or not.
    pub fn io_consistent(&self) -> bool {
        crate::zk::compute_io_hash(&self.public_prime(), &self.reply) == self.io_hash
    }

    /// The leading 32 bytes of `app_public` — `root_before` under the
    /// root convention (module docs). `None` when the Task bound fewer
    /// than 32 app-public bytes (it attests no prior root, so a caller
    /// with an `expected_root_before` must reject).
    pub fn root_before(&self) -> Option<[u8; 32]> {
        let head = self.app_public.get(..32)?;
        let mut root = [0u8; 32];
        root.copy_from_slice(head);
        Some(root)
    }
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

/// Guest-side (the record-owning parent agent): read a captured
/// `__vos_proofrec/<tag>` row back from THIS actor's own keyspace — the
/// raw [`ProofRecordEntry`] bytes, or `None` when no record exists under
/// the tag. The export half of the prove flow: a parent exposes a
/// handler over this so `vosx zk prove` can fetch the entry.
///
/// The entry contains [`ProvableInput`] — the complete proving SECRET —
/// so a production parent must gate any handler exposing it to its
/// operator (`#[msg(role)]`).
#[cfg(feature = "service")]
pub fn read_record_entry(tag: &[u8; 32]) -> Option<Vec<u8>> {
    crate::actors::storage::read_raw(&proofrec_key(tag))
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::vec;

    fn sample_record() -> ProvableRecord {
        let anchor_kind = crate::refine_payload::ANCHOR_STATE_HASH;
        let anchor = crate::refine_payload::state_anchor(b"prior");
        let transition_digest = [7u8; 32];
        let reply = vec![1, 2, 3];
        let mut app_public = vec![0u8; 64];
        app_public[..32].copy_from_slice(&[0xAA; 32]);
        app_public[32..].copy_from_slice(&[0xBB; 32]);
        let public_prime = crate::refine_payload::folded_public(
            anchor_kind,
            &anchor,
            &transition_digest,
            &app_public,
        );
        ProvableRecord {
            task_hash: [9u8; 32],
            anchor_kind,
            anchor,
            transition_digest,
            reply: reply.clone(),
            io_hash: crate::zk::compute_io_hash(&public_prime, &reply),
            app_public,
            catalog_name: String::new(),
            catalog_version: 0,
        }
    }

    #[test]
    fn record_round_trips_and_is_io_consistent() {
        let record = sample_record();
        assert!(record.io_consistent());
        let back = ProvableRecord::decode(&record.encode()).expect("record decodes");
        assert_eq!(back, record);
        assert_eq!(record.root_before(), Some([0xAA; 32]));
    }

    #[test]
    fn any_tampered_field_breaks_io_consistency() {
        // Every verifier-relevant field feeds public'/reply, so a flip
        // anywhere must break the record's internal binding equation.
        let base = sample_record();
        let mut r = base.clone();
        r.reply[0] ^= 1;
        assert!(!r.io_consistent(), "tampered reply must fail");
        let mut r = base.clone();
        r.transition_digest[0] ^= 1;
        assert!(!r.io_consistent(), "tampered digest must fail");
        let mut r = base.clone();
        r.anchor[0] ^= 1;
        assert!(!r.io_consistent(), "tampered anchor must fail");
        let mut r = base.clone();
        r.app_public[0] ^= 1;
        assert!(!r.io_consistent(), "tampered app_public must fail");
        let mut r = base.clone();
        r.io_hash[0] ^= 1;
        assert!(!r.io_consistent(), "tampered io_hash must fail");
        // Catalog identity is routing metadata, deliberately OUTSIDE the
        // binding — a lie there is caught by the chain-vs-allowlist check.
        let mut r = base.clone();
        r.catalog_name = String::from("impostor");
        r.catalog_version = 99;
        assert!(r.io_consistent());
    }

    #[test]
    fn short_app_public_has_no_root() {
        let mut record = sample_record();
        record.app_public = vec![1u8; 31];
        assert_eq!(record.root_before(), None);
    }

    #[test]
    fn blob_hash_matches_runtime_registry() {
        // The catalog join key and the runtime's invoke-by-hash registry
        // must be the same function (see task_blob_hash docs).
        let blob = b"example-blob-bytes";
        assert_eq!(
            task_blob_hash(blob),
            crate::crypto::blake2b::blake2b_hash::<32>(b"vos/blob-addr/v1", &[blob]),
        );
    }
}
