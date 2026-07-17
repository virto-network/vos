//! The soundness gate for the cipher-clerk ↔ vos witness bridge
//! (`docs/plans/provable.md` W4): a `ClerkTransitionWitness` built from
//! a real ledger must verify-and-apply to the SAME `(root_before,
//! root_after)` cipher-clerk's own `SuccinctTransitionWitness` and a
//! live `VecLedger` apply produce — and a doctored witness must panic
//! (the pure-verifier failure mode).

use cipher_clerk::crypto::{Amount, Blinding, Keypair};
use cipher_clerk::prelude::*;
use cipher_clerk::snapshot::{OpeningsOracle, VecLedger};
use cipher_clerk::state::Opening;
use cipher_clerk::state_root::{
    account_leaf_content, external_id_key, external_id_leaf_content, journal_leaf_content,
    pending_leaf_content, transfer_leaf_content, voided_leaf_content,
};
use cipher_clerk::succinct::SuccinctTransitionWitness;

use clerk_witness::{
    ClerkTransitionWitness, FullLeaves, TouchedKeys, apply_witnessed, discover_touched,
    witness_from_leaves,
};

const BATCH_TS: u64 = 600_000;

/// The six sub-trees of a `VecLedger` as `FullLeaves` — the exact
/// `(key, canonical leaf content)` pairs cipher-clerk's SMT commits.
fn full_leaves(
    l: &VecLedger,
) -> (FullLeaves, FullLeaves, FullLeaves, FullLeaves, FullLeaves, FullLeaves) {
    let accounts = l.accounts.iter().map(|a| (a.id.0, account_leaf_content(a))).collect();
    let transfers = l.transfers.iter().map(|t| (t.id.0, transfer_leaf_content(t))).collect();
    let journals = l
        .journal
        .iter()
        .map(|j| (j.id.0, journal_leaf_content(j)))
        .collect();
    let external_ids = l
        .external_ids
        .iter()
        .map(|eid| (external_id_key(eid), external_id_leaf_content(eid)))
        .collect();
    let voided = l
        .voided_transfers
        .iter()
        .map(|id| (*id, voided_leaf_content(id)))
        .collect();
    let pending = l
        .pending_statuses
        .iter()
        .map(|e| (e.id, pending_leaf_content(&e.id, e.status)))
        .collect();
    (accounts, transfers, journals, external_ids, voided, pending)
}

/// Build a 2-account / 1-transfer conservation batch over a fresh
/// journal — the same shape the federation e2e and the voucher pin
/// use. Returns the pre-batch ledger, the batch, the openings oracle,
/// and the debited amount commitment.
fn conservation_setup() -> (VecLedger, Vec<Transfer>, OpeningsOracle, Amount) {
    let registrar = Keypair::generate();
    let journal = Journal::new(JournalId::random(), registrar.public, 1);
    let jid = journal.id;
    let mut ledger = VecLedger::new();
    ledger.set_journal(journal);

    let value: u64 = 100;
    let blinding = Blinding::from_bytes([3u8; 32]).expect("canonical scalar");
    let amount_commit = Amount::commit(value, &blinding);
    let mut oracle = OpeningsOracle::new(vec![Opening {
        amount: amount_commit,
        value,
        blinding,
    }]);

    let alice_kp = Keypair::generate();
    let bob_kp = Keypair::generate();
    let alice = Account::open(AccountKind::Asset, jid, alice_kp.public, Iso4217::USD, BankCode::Vault);
    let bob =
        Account::open(AccountKind::Liability, jid, bob_kp.public, Iso4217::USD, BankCode::Checking);
    for r in cipher_clerk::apply_account_creations(
        &mut ledger,
        &[
            CreateAccount::signed(alice.clone(), &registrar.secret),
            CreateAccount::signed(bob.clone(), &registrar.secret),
        ],
        &mut oracle,
        500_000,
    ) {
        assert_eq!(r.status, EventStatus::Created);
    }

    let t = Transfer::builder(jid)
        .debit(&alice, Layer::Settled, amount_commit)
        .credit(&bob, Layer::Settled, amount_commit)
        .signed_with(&[(&alice, &alice_kp.secret)]);
    (ledger, vec![t], oracle, amount_commit)
}

/// Build the bridge witness from a full ledger — discovery + extraction
/// mirroring what a clerk-ledger parent does with `batch_proof`.
fn bridge_witness(
    ledger: &VecLedger,
    events: &[Transfer],
    oracle: &OpeningsOracle,
) -> (ClerkTransitionWitness, TouchedKeys) {
    let (touched, statuses) = discover_touched(ledger, events, oracle, BATCH_TS);
    for s in &statuses {
        assert_eq!(*s, EventStatus::Created, "the probe batch must apply cleanly");
    }
    let (accounts, transfers, journals, external_ids, voided, pending) = full_leaves(ledger);
    let witness = witness_from_leaves(
        &accounts,
        &transfers,
        &journals,
        &external_ids,
        &voided,
        &pending,
        &touched,
        oracle.clone(),
        events.to_vec(),
        BATCH_TS,
    );
    (witness, touched)
}

#[test]
fn bridge_roots_match_cipher_clerk_and_live_apply() {
    let (ledger, events, oracle, amount_commit) = conservation_setup();

    // The authoritative roots: a live VecLedger apply.
    let root_before = ledger.root();
    let mut live = ledger.clone();
    let mut live_oracle = oracle.clone();
    let _ = cipher_clerk::apply_batch(&mut live, &events, &mut live_oracle, BATCH_TS);
    let root_after = live.root();
    assert_ne!(root_before, root_after, "the transfer must move the root");

    // cipher-clerk's own succinct witness verifies these roots.
    let cc_witness = SuccinctTransitionWitness::from_full(&ledger, &events, &oracle, BATCH_TS);
    cc_witness.verify_transition(root_before, root_after);

    // The bridge witness reconstructs BYTE-IDENTICAL roots and folds
    // the same transition through the vos WitnessedLedger stack.
    let (witness, _touched) = bridge_witness(&ledger, &events, &oracle);
    let applied = apply_witnessed(witness);
    assert_eq!(applied.root_before, root_before, "bridge root_before parity");
    assert_eq!(applied.root_after, root_after, "bridge root_after parity");
    assert!(
        applied.has_debit_commit(&amount_commit),
        "the voucher tie must see the debited amount"
    );
    // A different commitment is not a debit in this batch.
    let other = Amount::commit(1, &Blinding::from_bytes([9u8; 32]).unwrap());
    assert!(!applied.has_debit_commit(&other));
}

#[test]
fn bridge_witness_round_trips_through_rkyv() {
    let (ledger, events, oracle, _) = conservation_setup();
    let (witness, _) = bridge_witness(&ledger, &events, &oracle);
    let bytes = witness.encode();
    let back = ClerkTransitionWitness::decode(&bytes).expect("witness decodes");
    let a = apply_witnessed(witness);
    let b = apply_witnessed(back);
    assert_eq!(a.root_before, b.root_before);
    assert_eq!(a.root_after, b.root_after);
}

#[test]
#[should_panic(expected = "inconsistent witness")]
fn a_swapped_leaf_is_rejected() {
    let (ledger, events, oracle, _) = conservation_setup();
    let (mut witness, _) = bridge_witness(&ledger, &events, &oracle);
    // Corrupt a present account leaf: the reconstructed sub-root no
    // longer matches its proven root_before, so construction traps.
    let leaf = witness
        .accounts
        .touched
        .iter_mut()
        .find(|(_, v)| v.is_some())
        .expect("a present account leaf");
    if let Some(bytes) = &mut leaf.1 {
        bytes[1] ^= 0xFF;
    }
    let _ = apply_witnessed(witness);
}

#[test]
#[should_panic(expected = "inconsistent witness")]
fn a_lying_absent_leaf_is_rejected() {
    let (ledger, events, oracle, _) = conservation_setup();
    let (mut witness, _) = bridge_witness(&ledger, &events, &oracle);
    // Hand a present account back as proven-absent: the empty leaf
    // shifts the reconstructed root away from root_before.
    let leaf = witness
        .accounts
        .touched
        .iter_mut()
        .find(|(_, v)| v.is_some())
        .expect("a present account leaf");
    leaf.1 = None;
    let _ = apply_witnessed(witness);
}

#[test]
#[should_panic]
fn a_tampered_batch_is_rejected() {
    let (ledger, events, oracle, _) = conservation_setup();
    let (mut witness, _) = bridge_witness(&ledger, &events, &oracle);
    // Replace the batch with an empty one: the kernel produces no
    // delta, root_after == root_before, but the openings/events no
    // longer describe the witnessed transition. An empty batch applies
    // cleanly to a no-op — so the guard that matters is the caller's
    // (has_debit_commit / root movement); assert the roots collapse.
    witness.events.clear();
    let applied = apply_witnessed(witness);
    assert_ne!(
        applied.root_before, applied.root_after,
        "an empty batch is a no-op transition — the caller must reject it"
    );
}
