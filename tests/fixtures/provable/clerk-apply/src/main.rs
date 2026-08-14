//! clerk-apply — the flagship `#[provable]` Task (`docs/plans/provable.md`
//! W4): a PURE VERIFIER of a cipher-clerk batch transition.
//!
//! ## What it proves
//!
//! A clerk-ledger parent, in its live dispatch, gathers the leaves its
//! transfer will touch across the six committed sub-trees plus a
//! `vos::zk::state::BatchProof` over each (via
//! `CommittedMap::batch_proof`), packs a
//! `clerk_witness::ClerkTransitionWitness`, and invokes THIS Task with a
//! record tag. The Task:
//!
//! 1. reconstructs each sub-tree's `root_before` from its proven leaves
//!    (inclusion AND non-inclusion — a swapped value or lying-absent
//!    shifts the root and the check fails), and folds the composite
//!    `root_before`;
//! 2. re-executes the REAL cipher-clerk kernel over exactly those
//!    leaves — double-entry zero-sum, no-overdraft, signatures,
//!    idempotency, pending lifecycle, all enforced; an unwitnessed read
//!    panics (≡ "the proof won't verify");
//! 3. folds the composite `root_after` reusing the pinned frontiers;
//! 4. binds `app_public = root_before ‖ root_after ‖ batch_digest` via
//!    `vos::zk::bind_public_bytes`, LEADING with `root_before` — the W3
//!    leading-root convention a verifier's `expected_root_before`
//!    compares against.
//!
//! It writes no live committed storage: the parent applies the actual
//! mutation in its own dispatch, against the roots this Task attested.
//!
//! ## Task shape
//!
//! `#[actor(task, provable)]` — the framework delivers `(state, msg)`
//! through `__VOS_WITNESS`, composes the io-hash at halt over
//! `folded_public(anchor_kind, anchor, transition_digest, app_public)`,
//! and (when the invoker set a record tag) the host captures a durable
//! `ProvableRecord`. The Task's own state is empty; the batch witness
//! rides the message.

use clerk_witness::{ClerkTransitionWitness, apply_witnessed};
use vos::prelude::*;

/// A provable Task actor: no persistent state, one verifying handler.
#[actor(task, provable)]
struct ClerkApply;

#[messages]
impl ClerkApply {
    fn new() -> Self {
        ClerkApply
    }

    /// Verify one witnessed cipher-clerk batch transition and bind its
    /// app-named roots. `witness` is the rkyv-encoded
    /// [`ClerkTransitionWitness`] the parent extracted from its
    /// committed sub-trees. Any decode failure or kernel-rule violation
    /// panics → `Trap` → the proof won't verify.
    ///
    /// The reply repeats the exact 96 public bytes. The parent compares this
    /// synchronous result before committing its live writes, while a later
    /// verifier authenticates the same bytes through `app_public`.
    #[msg]
    async fn apply(&self, witness: Vec<u8>) -> Vec<u8> {
        let witness = ClerkTransitionWitness::decode(&witness)
            .expect("clerk-apply: witness is not a ClerkTransitionWitness");
        let applied = apply_witnessed(witness);

        // app_public = root_before(32) ‖ root_after(32) ‖ batch_digest(32).
        // The leading root is what a verifier's expected_root_before
        // compares against; the digest binds the exact batch (closing the
        // empty-batch root_before==root_after substitution).
        let public = applied.claim().encode();
        vos::zk::bind_public_bytes(&public);
        public.to_vec()
    }
}
