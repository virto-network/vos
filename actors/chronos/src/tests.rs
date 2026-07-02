//! Unit tests for the clock, hash-chain, committee protocol, and the
//! rkyv round-trip invariants the raft soft-restart path depends on.

use super::*;
use vos::Message;
use vos::actors::context::ServiceId;

fn chronos() -> Chronos {
    Chronos::new()
}

/// Handler futures never await anything external, so a single poll with a
/// no-op waker resolves them (this crate is its own workspace, so the
/// std-gated `vos::block_on` isn't available).
fn run<F: core::future::Future>(fut: F) -> F::Output {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        fn noop(_: *const ()) {}
        RawWaker::new(
            core::ptr::null(),
            &RawWakerVTable::new(clone, noop, noop, noop),
        )
    }
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = core::pin::pin!(fut);
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(out) => out,
        Poll::Pending => panic!("actor handler future was not immediately ready"),
    }
}

fn dispatch<M>(c: &mut Chronos, msg: M) -> <Chronos as Message<M>>::Output
where
    Chronos: Message<M>,
{
    let mut ctx: vos::Context<Chronos> = vos::Context::new(ServiceId(0));
    run(<Chronos as Message<M>>::handle(c, msg, &mut ctx))
}

/// A valid VRF public key for a test seed, as wire bytes.
fn pk_bytes(seed: u8) -> [u8; 32] {
    let (_sk, pk) = vrf::keypair_from_seed(&[seed; 32]);
    pk.to_bytes()
}

const VOTER_A: &[u8] = b"peer-A-multihash";
const VOTER_B: &[u8] = b"peer-B-multihash";

const DOMAIN: &[u8] = b"space-42";

fn init(c: &mut Chronos) -> Status {
    dispatch(
        c,
        Init {
            domain: DOMAIN.to_vec(),
        },
    )
}

fn advance_to(c: &mut Chronos, slot: u64, entropy: [u8; 32]) -> AdvanceOutcome {
    dispatch(
        c,
        Advance {
            slot,
            entropy: entropy.to_vec(),
        },
    )
}

/// Fold epoch `n` by advancing to its first slot — a clean one-round-per-fold
/// helper for the chain tests (round `n` lands at slot `n * SLOTS_PER_EPOCH`).
fn fold(c: &mut Chronos, n: u64, entropy: [u8; 32]) -> AdvanceOutcome {
    advance_to(c, n * SLOTS_PER_EPOCH, entropy)
}

#[test]
fn genesis_is_a_verifiable_public_anchor() {
    let mut c = chronos();
    assert_eq!(init(&mut c), Status::Ok);
    let g = dispatch(&mut c, Current).expect("genesis round exists");
    assert_eq!(g.round, 0);
    assert_eq!(g.slot, 0);
    assert_eq!(g.prev, [0u8; 32]);
    assert_eq!(g.entropy, [0u8; 32]);
    assert!(verify_round(DOMAIN, &g), "genesis must verify");
    assert_eq!(dispatch(&mut c, Now), 0, "clock starts at the era anchor");
    // Recomputable by any holder of the domain alone.
    assert_eq!(g.beacon, derive_beacon(DOMAIN, &[0u8; 32], 0, 0, &[0u8; 32]));
}

#[test]
fn init_is_one_shot() {
    let mut c = chronos();
    assert_eq!(init(&mut c), Status::Ok);
    assert_eq!(init(&mut c), Status::AlreadyInitialized);
}

#[test]
fn advance_before_init_is_rejected() {
    let mut c = chronos();
    let out = advance_to(&mut c, 1, [1u8; 32]);
    assert_eq!(out.status, Status::NotInitialized);
}

#[test]
fn advance_rejects_wrong_length_entropy() {
    let mut c = chronos();
    init(&mut c);
    let out = dispatch(
        &mut c,
        Advance {
            slot: SLOTS_PER_EPOCH,
            entropy: vec![1u8; 16],
        },
    );
    assert_eq!(out.status, Status::InvalidInput);
    // Neither the clock nor the chain moved.
    assert_eq!(dispatch(&mut c, Now), 0);
    assert_eq!(dispatch(&mut c, Round), 0);
}

#[test]
fn now_advances_and_is_strictly_monotone() {
    let mut c = chronos();
    init(&mut c);
    let out = advance_to(&mut c, 1, [1u8; 32]);
    assert_eq!(out.status, Status::Ok);
    assert_eq!(dispatch(&mut c, Now), 1);

    // A backward or equal slot is rejected and changes nothing.
    assert_eq!(advance_to(&mut c, 1, [2u8; 32]).status, Status::StaleSlot);
    assert_eq!(advance_to(&mut c, 0, [2u8; 32]).status, Status::StaleSlot);
    assert_eq!(dispatch(&mut c, Now), 1);
}

#[test]
fn advance_within_an_epoch_stamps_the_clock_without_folding() {
    let mut c = chronos();
    init(&mut c);
    // The establishing advance into a fresh epoch folds round 1.
    let first = advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
    assert!(first.folded);
    assert_eq!(first.round, 1);

    // Subsequent slots within the same epoch only move the clock.
    let head_before = dispatch(&mut c, Current).unwrap();
    for s in 1..SLOTS_PER_EPOCH {
        let out = advance_to(&mut c, SLOTS_PER_EPOCH + s, [9u8; 32]);
        assert_eq!(out.status, Status::Ok);
        assert!(!out.folded, "within-epoch advance must not fold");
        assert_eq!(out.round, 1, "round unchanged within the epoch");
    }
    assert_eq!(dispatch(&mut c, Now), 2 * SLOTS_PER_EPOCH - 1);
    // The chain head is untouched by the within-epoch ticks.
    assert_eq!(dispatch(&mut c, Current).unwrap(), head_before);

    // Crossing into the next epoch folds round 2.
    let next = advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [2u8; 32]);
    assert!(next.folded);
    assert_eq!(next.round, 2);
}

#[test]
fn establishing_advance_may_leap_then_cap_applies() {
    let mut c = chronos();
    init(&mut c);
    // From the slot-0 era anchor, a single advance may jump arbitrarily far.
    let far = 10 * MAX_SLOT_JUMP;
    let out = advance_to(&mut c, far, [1u8; 32]);
    assert_eq!(out.status, Status::Ok);
    assert_eq!(dispatch(&mut c, Now), far);

    // Now the clock is established: a leap beyond the cap is rejected.
    let over = far + MAX_SLOT_JUMP + 1;
    assert_eq!(
        advance_to(&mut c, over, [2u8; 32]).status,
        Status::SlotJumpTooLarge
    );
    assert_eq!(dispatch(&mut c, Now), far, "a rejected leap changes nothing");

    // Exactly at the cap is accepted.
    let at_cap = far + MAX_SLOT_JUMP;
    assert_eq!(advance_to(&mut c, at_cap, [2u8; 32]).status, Status::Ok);
    assert_eq!(dispatch(&mut c, Now), at_cap);
}

#[test]
fn chain_advances_and_links_and_verifies() {
    let mut c = chronos();
    init(&mut c);
    let mut prev = dispatch(&mut c, Current).unwrap().beacon;
    for i in 1..=5u64 {
        let entropy = [i as u8; 32];
        let out = fold(&mut c, i, entropy);
        assert_eq!(out.status, Status::Ok);
        assert!(out.folded);
        assert_eq!(out.round, i);
        let row = dispatch(&mut c, RoundAt { round: i }).unwrap();
        assert_eq!(row.prev, prev, "each round must link to its predecessor");
        assert_eq!(row.slot, i * SLOTS_PER_EPOCH);
        assert!(verify_round(DOMAIN, &row), "round {i} must verify");
        assert_eq!(out.beacon, row.beacon);
        prev = row.beacon;
    }
    assert_eq!(dispatch(&mut c, Round), 5);
}

#[test]
fn same_domain_and_inputs_is_deterministic_distinct_domain_diverges() {
    let mut a = chronos();
    let mut b = chronos();
    init(&mut a);
    init(&mut b);
    let e = [7u8; 32];
    assert_eq!(fold(&mut a, 1, e).beacon, fold(&mut b, 1, e).beacon);

    // A different domain forks the whole chain from genesis.
    let mut d = chronos();
    dispatch(
        &mut d,
        Init {
            domain: b"other-space".to_vec(),
        },
    );
    assert_ne!(
        dispatch(&mut d, Current).unwrap().beacon,
        dispatch(&mut a, Current).unwrap().beacon,
    );
}

#[test]
fn tampering_with_a_stored_round_is_detectable() {
    let mut c = chronos();
    init(&mut c);
    fold(&mut c, 1, [3u8; 32]);
    let mut row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
    assert!(verify_round(DOMAIN, &row));
    // Flip the entropy: the stored beacon no longer matches its inputs.
    row.entropy[0] ^= 0xFF;
    assert!(
        !verify_round(DOMAIN, &row),
        "a tampered round must fail verification"
    );
    // Relabelling the slot is equally detectable (slot is bound into the hash).
    let mut row2 = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
    row2.slot ^= 0xFF;
    assert!(!verify_round(DOMAIN, &row2), "a relabelled slot must fail");
}

#[test]
fn latest_final_lags_the_live_head() {
    let mut c = chronos();
    init(&mut c);
    // Before enough rounds accumulate, there is no finalized value yet —
    // a consumer gets None (⇒ no hedge ⇒ no behavior change). latest_final
    // becomes Some only once history is deeper than FINALIZED_LAG, i.e.
    // after FINALIZED_LAG folds beyond genesis.
    assert!(dispatch(&mut c, LatestFinal).is_none());
    for k in 1..FINALIZED_LAG as u64 {
        fold(&mut c, k, [k as u8; 32]);
        assert!(
            dispatch(&mut c, LatestFinal).is_none(),
            "still within the lag window"
        );
    }
    // The FINALIZED_LAG-th fold makes genesis the finalized head.
    fold(&mut c, FINALIZED_LAG as u64, [42u8; 32]);
    assert_eq!(
        dispatch(&mut c, LatestFinal).unwrap().round,
        0,
        "the first finalized round is genesis"
    );

    // From here on latest_final trails the live head by exactly the lag.
    for i in (FINALIZED_LAG as u64 + 1)..=(FINALIZED_LAG as u64 + 3) {
        fold(&mut c, i, [i as u8; 32]);
        let f = dispatch(&mut c, LatestFinal).unwrap();
        let head = dispatch(&mut c, Current).unwrap();
        assert_eq!(
            f.round,
            head.round - FINALIZED_LAG as u64,
            "latest_final lags the head by exactly FINALIZED_LAG folds"
        );
    }
}

#[test]
fn randomness_at_returns_the_finalized_epoch_floor() {
    let mut c = chronos();
    init(&mut c);
    // Fold a contiguous run of epochs 1..=8 (round n at epoch n).
    for i in 1..=8u64 {
        fold(&mut c, i, [i as u8; 32]);
    }
    // A well-buried epoch returns its own round.
    let r = dispatch(&mut c, RandomnessAt { epoch: 3 }).unwrap();
    assert_eq!(r.round, 3);
    assert_eq!(r.slot / SLOTS_PER_EPOCH, 3);
    assert!(verify_round(DOMAIN, &r));

    // The freshest epochs (within the lag) are not yet final → None.
    let head_epoch = dispatch(&mut c, Epoch);
    assert!(
        dispatch(&mut c, RandomnessAt { epoch: head_epoch }).is_none(),
        "the live head epoch is not finalized"
    );

    // An epoch the clock skipped floors to the most recent earlier round.
    let mut d = chronos();
    init(&mut d);
    fold(&mut d, 1, [1u8; 32]); // epoch 1
    fold(&mut d, 5, [5u8; 32]); // epoch 5 (skipped 2,3,4)
    fold(&mut d, 6, [6u8; 32]);
    fold(&mut d, 7, [7u8; 32]); // pushes epoch 5 behind the lag
    let floored = dispatch(&mut d, RandomnessAt { epoch: 3 }).unwrap();
    assert_eq!(floored.slot / SLOTS_PER_EPOCH, 1, "epoch 3 floors to epoch 1");

    // Epoch 0 (genesis) is retained and finalized here.
    assert!(dispatch(&mut d, RandomnessAt { epoch: 0 }).is_some());
}

#[test]
fn history_is_bounded_and_keeps_the_head() {
    let mut c = chronos();
    init(&mut c);
    for i in 1..=(MAX_HISTORY as u64 + 50) {
        fold(&mut c, i, [(i % 251) as u8; 32]);
    }
    // The chain head is always available and correct.
    let head = dispatch(&mut c, Current).unwrap();
    assert_eq!(head.round, MAX_HISTORY as u64 + 50);
    assert!(verify_round(DOMAIN, &head));
    // The earliest rounds were pruned.
    assert!(
        dispatch(&mut c, RoundAt { round: 0 }).is_none(),
        "genesis should be pruned"
    );
    // A recent round is still retained and verifies.
    let recent = dispatch(
        &mut c,
        RoundAt {
            round: head.round - 1,
        },
    )
    .unwrap();
    assert!(verify_round(DOMAIN, &recent));
}

#[test]
fn at_returns_none_past_the_head() {
    let mut c = chronos();
    init(&mut c);
    fold(&mut c, 1, [1u8; 32]);
    assert!(dispatch(&mut c, RoundAt { round: 99 }).is_none());
}

#[test]
fn range_returns_an_ascending_verifiable_window() {
    let mut c = chronos();
    init(&mut c);
    for i in 1..=10u64 {
        fold(&mut c, i, [i as u8; 32]);
    }
    let window = dispatch(&mut c, Range { from: 3, limit: 4 });
    let rounds: Vec<u64> = window.iter().map(|r| r.round).collect();
    assert_eq!(rounds, alloc::vec![3, 4, 5, 6]);
    assert!(verify_chain(DOMAIN, &window), "a fetched window must verify");

    // From genesis through the head, clamped to MAX_RANGE.
    let all = dispatch(
        &mut c,
        Range {
            from: 0,
            limit: 1000,
        },
    );
    assert_eq!(all.first().unwrap().round, 0);
    assert_eq!(all.last().unwrap().round, 10);
    assert!(verify_chain(DOMAIN, &all));
}

#[test]
fn range_is_clamped_and_empty_past_the_head() {
    let mut c = chronos();
    init(&mut c);
    for i in 1..=5u64 {
        fold(&mut c, i, [i as u8; 32]);
    }
    assert_eq!(
        dispatch(
            &mut c,
            Range {
                from: 99,
                limit: 10
            }
        )
        .len(),
        0
    );
    assert_eq!(dispatch(&mut c, Range { from: 0, limit: 0 }).len(), 0);
    assert!(
        dispatch(
            &mut c,
            Range {
                from: 0,
                limit: u32::MAX
            }
        )
        .len()
            <= MAX_RANGE as usize
    );
}

#[test]
fn verify_chain_rejects_tamper_break_and_gaps() {
    let mut c = chronos();
    init(&mut c);
    for i in 1..=4u64 {
        fold(&mut c, i, [i as u8; 32]);
    }
    let good = dispatch(&mut c, Range { from: 1, limit: 4 });
    assert!(verify_chain(DOMAIN, &good));

    // Tampered beacon bytes in the middle.
    let mut tampered = good.clone();
    tampered[1].beacon[0] ^= 0xFF;
    assert!(!verify_chain(DOMAIN, &tampered), "tamper must fail");

    // Broken linkage: a valid-on-its-own round spliced out of sequence.
    let mut broken = good.clone();
    broken[2].prev[0] ^= 0xFF; // no longer points at rounds[1].beacon
    // recompute its own beacon so verify_round passes in isolation...
    broken[2].beacon = derive_beacon(
        DOMAIN,
        &broken[2].prev,
        broken[2].round,
        broken[2].slot,
        &broken[2].entropy,
    );
    assert!(
        verify_round(DOMAIN, &broken[2]),
        "the spliced round verifies alone"
    );
    assert!(
        !verify_chain(DOMAIN, &broken),
        "but the chain linkage must fail"
    );

    // Non-contiguous round numbers.
    let gapped = alloc::vec![good[0].clone(), good[2].clone()];
    assert!(
        !verify_chain(DOMAIN, &gapped),
        "a round-number gap must fail"
    );

    // Empty and singleton.
    assert!(verify_chain(DOMAIN, &[]));
    assert!(verify_chain(DOMAIN, &good[0..1]));
}

#[test]
fn verify_chain_anchors_round_zero_to_genesis() {
    // A fabricated round-0 row whose beacon correctly hashes its own
    // (non-zero) inputs passes verify_round in isolation, but must NOT pass
    // verify_chain: round 0 is only ever the canonical genesis. Without the
    // anchor an untrusted server could hand a consumer a whole chain hanging
    // off a forged origin.
    let forged_prev = [9u8; 32];
    let forged_entropy = [7u8; 32];
    let forged_slot = 99u64;
    let forged = BeaconRound {
        round: 0,
        slot: forged_slot,
        prev: forged_prev,
        entropy: forged_entropy,
        beacon: derive_beacon(DOMAIN, &forged_prev, 0, forged_slot, &forged_entropy),
    };
    assert!(
        verify_round(DOMAIN, &forged),
        "the forged origin verifies alone"
    );
    assert!(
        !verify_chain(DOMAIN, &[forged]),
        "but verify_chain must reject a non-genesis round 0",
    );

    // The real genesis still passes.
    let mut c = chronos();
    init(&mut c);
    let genesis = dispatch(&mut c, Current).unwrap();
    assert!(verify_chain(DOMAIN, &[genesis]));
}

// ── Committee enrolment ────────────────────────────────────────

fn set_committee(c: &mut Chronos, voters: &[&[u8]]) -> Status {
    let encoded = encode_committee(&voters.iter().map(|v| v.to_vec()).collect::<Vec<_>>());
    dispatch(c, SetCommittee { voters: encoded })
}

/// Enrol `voter`'s key derived from `seed`.
fn enrol(c: &mut Chronos, voter: &[u8], seed: u8) -> Status {
    dispatch(
        c,
        EnrolVoter {
            voter_id: voter.to_vec(),
            pubkey: pk_bytes(seed).to_vec(),
        },
    )
}

/// Compute and post `voter`'s reveal for `round` over `alpha`, using the key
/// derived from `seed`.
fn reveal_as(c: &mut Chronos, voter: &[u8], round: u64, seed: u8, alpha: [u8; 32]) -> Status {
    let (sk, pk) = vrf::keypair_from_seed(&[seed; 32]);
    let proof = vrf::prove(&sk, &pk, &alpha);
    dispatch(
        c,
        Reveal {
            voter_id: voter.to_vec(),
            round,
            proof: proof.to_bytes().to_vec(),
        },
    )
}

/// The `alpha` of the single currently-open round (panics if not exactly one).
fn open_alpha(c: &mut Chronos) -> [u8; 32] {
    let open = dispatch(c, OpenRounds);
    assert_eq!(open.len(), 1, "expected exactly one open round");
    open[0].alpha
}

/// An authorized voter enrols its key; the committee then exposes it.
#[test]
fn authorized_voter_enrols_and_appears_in_committee() {
    let mut c = chronos();
    init(&mut c);
    assert_eq!(set_committee(&mut c, &[VOTER_A]), Status::Ok);
    assert_eq!(enrol(&mut c, VOTER_A, 1), Status::Ok);
    let committee = dispatch(&mut c, Committee);
    assert_eq!(committee.len(), 1);
    assert_eq!(committee[0].voter, VOTER_A);
    assert_eq!(committee[0].pubkey, pk_bytes(1));
}

/// Enrolment is refused for a voter the leader has not authorized.
#[test]
fn enrol_rejects_unauthorized_voter() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    assert_eq!(enrol(&mut c, VOTER_B, 2), Status::NotAVoter);
    assert!(dispatch(&mut c, Committee).is_empty());
}

/// A non-canonical / wrong-length public key is rejected.
#[test]
fn enrol_rejects_invalid_pubkey() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    assert_eq!(
        dispatch(
            &mut c,
            EnrolVoter {
                voter_id: VOTER_A.to_vec(),
                pubkey: alloc::vec![0xFFu8; 32], // not a canonical Ristretto point
            },
        ),
        Status::InvalidInput
    );
    assert_eq!(
        dispatch(
            &mut c,
            EnrolVoter {
                voter_id: VOTER_A.to_vec(),
                pubkey: alloc::vec![1u8; 31], // wrong length
            },
        ),
        Status::InvalidInput
    );
}

/// First-wins binding: a same-key re-enrol is idempotent, but binding a
/// different key to an already-enrolled voter is refused (no silent override).
#[test]
fn enrol_is_first_wins() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    assert_eq!(enrol(&mut c, VOTER_A, 1), Status::Ok);
    // Re-enrol the SAME key — idempotent (the feeder re-fires this).
    assert_eq!(enrol(&mut c, VOTER_A, 1), Status::Ok);
    assert_eq!(dispatch(&mut c, Committee).len(), 1);
    // A DIFFERENT key is locked out.
    assert_eq!(enrol(&mut c, VOTER_A, 9), Status::KeyLocked);
    assert_eq!(
        dispatch(&mut c, Committee)[0].pubkey,
        pk_bytes(1),
        "the first key stands"
    );
}

/// Dropping a voter from the authorized set prunes its enrolled key.
#[test]
fn set_committee_prunes_dropped_voters() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A, VOTER_B]);
    enrol(&mut c, VOTER_A, 1);
    enrol(&mut c, VOTER_B, 2);
    assert_eq!(dispatch(&mut c, Committee).len(), 2);
    // Drop B: its key is pruned from the committee.
    set_committee(&mut c, &[VOTER_A]);
    let committee = dispatch(&mut c, Committee);
    assert_eq!(committee.len(), 1);
    assert_eq!(committee[0].voter, VOTER_A);
}

// ── Committee round protocol ───────────────────────────────────

/// With a committee configured, a round opens on the epoch boundary, stays
/// open across its reveal window collecting reveals, and folds the XOR-
/// combine of the revealed VRF outputs — no party chose the entropy.
#[test]
fn committee_round_collects_reveals_and_folds_the_combine() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A, VOTER_B]);
    enrol(&mut c, VOTER_A, 1);
    enrol(&mut c, VOTER_B, 2);

    // Crossing into epoch 1 opens round 1 — but a committee round does NOT
    // fold immediately; it waits the reveal window.
    advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
    let alpha = open_alpha(&mut c);
    assert_eq!(dispatch(&mut c, OpenRounds)[0].round, 1);
    assert_eq!(
        dispatch(&mut c, OpenRounds)[0].fold_epoch,
        1 + REVEAL_WINDOW_EPOCHS
    );
    assert_eq!(dispatch(&mut c, Round), 0, "round 1 has not folded yet");

    // Both voters reveal while the window is open.
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), Status::Ok);
    assert_eq!(reveal_as(&mut c, VOTER_B, 1, 2, alpha), Status::Ok);

    // Drive the clock to the fold epoch.
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [9u8; 32]);
    let out = advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [9u8; 32]);
    assert!(out.folded);
    assert_eq!(dispatch(&mut c, Round), 1);

    // The round entropy is exactly the committee combine of the two βs.
    let (ska, pka) = vrf::keypair_from_seed(&[1u8; 32]);
    let (skb, pkb) = vrf::keypair_from_seed(&[2u8; 32]);
    let ba = vrf::output(&vrf::prove(&ska, &pka, &alpha)).to_vec();
    let bb = vrf::output(&vrf::prove(&skb, &pkb, &alpha)).to_vec();
    let expected = combine_betas(DOMAIN, &[ba, bb]);
    let row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
    assert_eq!(row.entropy, expected, "round folds the committee XOR-combine");
    assert!(verify_round(DOMAIN, &row), "the folded round still verifies");

    // round_proofs carries both reveals for independent verification.
    let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
    assert_eq!(proofs.alpha, alpha);
    assert_eq!(proofs.reveals.len(), 2);
}

/// A single honest, unpredictable reveal already randomises the round — the
/// security floor of the committee combine. (The residual is the **1-bit
/// last-revealer**: the last voter to reveal sees the others and may withhold
/// its own fixed contribution, choosing between two outcomes — bounded, and
/// blunted by the lagged read. It cannot grind beyond that one bit because no
/// β can be *chosen*.)
#[test]
fn one_honest_reveal_randomises_the_round() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    enrol(&mut c, VOTER_A, 5);
    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
    let alpha = open_alpha(&mut c);
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 5, alpha), Status::Ok);
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]);
    let row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
    // The entropy is the VRF-derived combine, NOT the leader's zero input.
    assert_ne!(row.entropy, [0u8; 32]);
    let (sk, pk) = vrf::keypair_from_seed(&[5u8; 32]);
    let beta = vrf::output(&vrf::prove(&sk, &pk, &alpha)).to_vec();
    assert_eq!(row.entropy, combine_betas(DOMAIN, &[beta]));
}

/// The committee key is snapshotted when a round opens: re-enrolling a
/// different key afterward cannot change which key that round verifies
/// against (anti key-shopping — a voter cannot wait to see `α` then pick a
/// favourable key).
#[test]
fn open_round_snapshots_the_committee_key() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    enrol(&mut c, VOTER_A, 1); // K1
    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]); // opens round 1, snapshots K1
    let alpha = open_alpha(&mut c);

    // First-wins already refuses to rebind a different key K2...
    assert_eq!(enrol(&mut c, VOTER_A, 7), Status::KeyLocked);
    // ...and independently, the round is pinned to its OPEN-TIME snapshot key
    // K1: a reveal computed under K2 (seed 7) fails to verify, while a reveal
    // under the snapshot key K1 (seed 1) succeeds.
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 7, alpha), Status::BadProof);
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), Status::Ok);
}

/// A committee round that collects no reveals by its deadline folds the
/// leader's entropy — a degraded round (fairness-trusted), marked by an empty
/// `round_proofs` set and protected by the lagged read.
#[test]
fn committee_round_with_no_reveals_folds_the_fallback() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    enrol(&mut c, VOTER_A, 1);
    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]); // open r1 (waits)
    assert_eq!(dispatch(&mut c, Round), 0);
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
    let fallback = [0x42u8; 32];
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, fallback); // folds r1 with this entropy
    assert_eq!(dispatch(&mut c, Round), 1);
    let row = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
    assert_eq!(row.entropy, fallback, "zero-reveal round folds the leader entropy");
    let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
    assert!(proofs.reveals.is_empty(), "a degraded round carries no reveals");
}

/// Reveals are rejected for an unopened/folded round, for a non-committee
/// caller, and a bad proof; a duplicate reveal is an idempotent no-op.
#[test]
fn reveal_rejections_and_idempotence() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    enrol(&mut c, VOTER_A, 1);

    // No round open yet.
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, [0u8; 32]), Status::NoSuchRound);

    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
    let alpha = open_alpha(&mut c);

    // A voter not in the round's committee snapshot.
    assert_eq!(
        dispatch(
            &mut c,
            Reveal {
                voter_id: VOTER_B.to_vec(),
                round: 1,
                proof: alloc::vec![0u8; vrf::PROOF_LEN],
            },
        ),
        Status::NotAVoter
    );
    // A wrong-length / malformed proof from a real committee member.
    assert_eq!(
        dispatch(
            &mut c,
            Reveal {
                voter_id: VOTER_A.to_vec(),
                round: 1,
                proof: alloc::vec![0u8; 10],
            },
        ),
        Status::InvalidInput
    );

    // Valid reveal, then a duplicate (idempotent OK, no second β counted).
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), Status::Ok);
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), Status::Ok);

    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]); // folds r1
    let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
    assert_eq!(proofs.reveals.len(), 1, "a duplicate reveal is not double-counted");
    // After the fold the round is gone.
    assert_eq!(reveal_as(&mut c, VOTER_A, 1, 1, alpha), Status::NoSuchRound);
}

/// Removing a node from the committee (registry voter dropped) stops its
/// reveals from the next opened round, because the snapshot is taken fresh
/// each open.
#[test]
fn dropping_a_voter_excludes_it_from_future_rounds() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A, VOTER_B]);
    enrol(&mut c, VOTER_A, 1);
    enrol(&mut c, VOTER_B, 2);
    // Round 1 snapshots {A, B}.
    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
    // Drop B before round 2 opens.
    set_committee(&mut c, &[VOTER_A]);
    // Round 2 opens at epoch 2 snapshotting {A} only.
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
    let r2_alpha = dispatch(&mut c, OpenRounds)
        .iter()
        .find(|o| o.round == 2)
        .unwrap()
        .alpha;
    // B can no longer reveal for round 2.
    assert_eq!(reveal_as(&mut c, VOTER_B, 2, 2, r2_alpha), Status::NotAVoter);
    // A still can.
    assert_eq!(reveal_as(&mut c, VOTER_A, 2, 1, r2_alpha), Status::Ok);
}

// ── Independent combine verification ───────────────────────────

/// Build and fold committee round 1 with voters A (seed 1) and B (seed 2)
/// both revealing; return its `(BeaconRound, RoundProofSet)`.
fn folded_round_ab() -> (BeaconRound, RoundProofSet) {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A, VOTER_B]);
    enrol(&mut c, VOTER_A, 1);
    enrol(&mut c, VOTER_B, 2);
    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
    let alpha = open_alpha(&mut c);
    reveal_as(&mut c, VOTER_A, 1, 1, alpha);
    reveal_as(&mut c, VOTER_B, 1, 2, alpha);
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]);
    let round = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
    let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
    (round, proofs)
}

/// A genuine committee round verifies against its proof set.
#[test]
fn verify_combine_accepts_a_genuine_committee_round() {
    let (round, proofs) = folded_round_ab();
    assert_eq!(proofs.reveals.len(), 2);
    assert!(verify_combine(DOMAIN, &round, &proofs));
}

/// A forged proof byte breaks verification (the proof fails to verify, or its
/// β changes so the combine no longer matches).
#[test]
fn verify_combine_rejects_a_forged_proof() {
    let (round, mut proofs) = folded_round_ab();
    proofs.reveals[0].proof[0] ^= 0xFF;
    assert!(!verify_combine(DOMAIN, &round, &proofs));
}

/// Tampering the stored combine (round entropy) is detectable.
#[test]
fn verify_combine_rejects_a_tampered_combine() {
    let (mut round, proofs) = folded_round_ab();
    round.entropy[0] ^= 0xFF;
    assert!(!verify_combine(DOMAIN, &round, &proofs));
}

/// Relabelling the round's `α` invalidates every proof (they were made over
/// the real α), so the round no longer verifies.
#[test]
fn verify_combine_rejects_a_wrong_alpha() {
    let (round, mut proofs) = folded_round_ab();
    proofs.alpha[0] ^= 0xFF;
    assert!(!verify_combine(DOMAIN, &round, &proofs));
}

/// Swapping in a *different but individually valid* reveal (a real VRF proof
/// under another key over the same α) still fails: its β differs, so the
/// combine no longer equals the committed entropy. A self-consistent forgery
/// cannot reproduce the round's value.
#[test]
fn verify_combine_rejects_a_swapped_valid_reveal() {
    let (round, mut proofs) = folded_round_ab();
    let (sk_c, pk_c) = vrf::keypair_from_seed(&[99u8; 32]);
    let proof_c = vrf::prove(&sk_c, &pk_c, &proofs.alpha);
    assert!(
        vrf::verify(&pk_c, &proofs.alpha, &proof_c).is_some(),
        "the swapped-in proof is itself valid"
    );
    proofs.reveals[0].pubkey = pk_c.to_bytes();
    proofs.reveals[0].proof = proof_c.to_bytes().to_vec();
    assert!(
        !verify_combine(DOMAIN, &round, &proofs),
        "a valid-but-different reveal still breaks the committed combine"
    );
}

/// A degraded (zero-reveal) round has nothing committee-verifiable —
/// `verify_combine` returns false — but its hash linkage still holds.
#[test]
fn verify_combine_rejects_a_degraded_round_but_verify_round_holds() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A]);
    enrol(&mut c, VOTER_A, 1);
    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]); // open r1 (no reveals come)
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0x42u8; 32]); // fold degraded
    let round = dispatch(&mut c, RoundAt { round: 1 }).unwrap();
    let proofs = dispatch(&mut c, RoundProofs { round: 1 }).unwrap();
    assert!(proofs.reveals.is_empty());
    assert!(
        !verify_combine(DOMAIN, &round, &proofs),
        "no committee combine to verify for a degraded round"
    );
    assert!(
        verify_round(DOMAIN, &round),
        "but the round's hash linkage still holds (hash-chain tamper-evidence)"
    );
}

/// Fold round 1 (committee {A, B}) with exactly `revealers` revealing; return
/// the folded round entropy.
fn fold_with_revealers(revealers: &[(&[u8], u8)]) -> [u8; 32] {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A, VOTER_B]);
    enrol(&mut c, VOTER_A, 1);
    enrol(&mut c, VOTER_B, 2);
    advance_to(&mut c, SLOTS_PER_EPOCH, [0u8; 32]);
    let alpha = open_alpha(&mut c);
    for (v, seed) in revealers {
        reveal_as(&mut c, v, 1, *seed, alpha);
    }
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [0u8; 32]);
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [0u8; 32]);
    dispatch(&mut c, RoundAt { round: 1 }).unwrap().entropy
}

/// The raft soft-restart re-commits the rebuilt state and short-circuits
/// only when its bytes are UNCHANGED. So the state encoding must be
/// byte-deterministic for the same logical value — otherwise every commit
/// triggers a soft-restart that commits a "different" state, looping forever
/// (unzeroed rkyv padding between mixed-size fields is the classic cause).
#[test]
fn state_encoding_is_byte_deterministic() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A, VOTER_B]);
    enrol(&mut c, VOTER_A, 1);
    enrol(&mut c, VOTER_B, 2);
    advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
    let alpha = open_alpha(&mut c);
    reveal_as(&mut c, VOTER_A, 1, 1, alpha);
    reveal_as(&mut c, VOTER_B, 1, 2, alpha);
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [9u8; 32]);
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [9u8; 32]);

    let a = vos::Encode::encode(&c);
    let b = vos::Encode::encode(&c);
    assert_eq!(a, b, "same state must encode to identical bytes");
    // And a decode→re-encode must reproduce the exact bytes (the soft-restart
    // replay path: rebuild state, re-encode, compare).
    let back = <Chronos as vos::Decode>::try_decode(&a).expect("round-trips");
    assert_eq!(vos::Encode::encode(&back), a, "decode→encode must be stable");
}

/// The runtime persists actor state with `Encode::encode` and reloads it
/// through the **validating** `try_decode` (`lifecycle::load_or_create`); a
/// decode failure silently resets the actor to genesis — and the runtime
/// reloads on every committed raft index. So a fully-populated state
/// (committee, an open draft with reveals, and folded proofs) MUST round-trip
/// through that exact path, or the live actor wipes itself every commit.
#[test]
fn populated_state_round_trips_through_the_validating_codec() {
    let mut c = chronos();
    init(&mut c);
    set_committee(&mut c, &[VOTER_A, VOTER_B]);
    enrol(&mut c, VOTER_A, 1);
    enrol(&mut c, VOTER_B, 2);
    // Open round 1 (committee), collect reveals, then fold it so BOTH the
    // `pending` (still-open later rounds) and `proofs` (folded round 1) are
    // populated, plus `committee` + `history`.
    advance_to(&mut c, SLOTS_PER_EPOCH, [1u8; 32]);
    let alpha = open_alpha(&mut c);
    reveal_as(&mut c, VOTER_A, 1, 1, alpha);
    reveal_as(&mut c, VOTER_B, 1, 2, alpha);
    advance_to(&mut c, 2 * SLOTS_PER_EPOCH, [9u8; 32]);
    advance_to(&mut c, 3 * SLOTS_PER_EPOCH, [9u8; 32]); // folds round 1
    assert!(!dispatch(&mut c, OpenRounds).is_empty(), "expected open drafts");
    assert!(dispatch(&mut c, RoundProofs { round: 1 }).is_some(), "expected folded proofs");

    let bytes = vos::Encode::encode(&c);
    let mut back = <Chronos as vos::Decode>::try_decode(&bytes)
        .expect("populated state must survive the validating decode");

    assert_eq!(dispatch(&mut back, Now), dispatch(&mut c, Now));
    assert_eq!(dispatch(&mut back, Round), dispatch(&mut c, Round));
    assert_eq!(dispatch(&mut back, Committee).len(), 2);
    assert_eq!(
        dispatch(&mut back, RoundProofs { round: 1 }),
        dispatch(&mut c, RoundProofs { round: 1 }),
    );
    assert_eq!(
        dispatch(&mut back, OpenRounds),
        dispatch(&mut c, OpenRounds),
    );
}

/// The honest residual, made explicit. The combine of {A} differs from the
/// combine of {A, B}, so the **last revealer** B — who sees the others'
/// reveals and whose own β is fixed — can compute both outcomes and, by
/// choosing to reveal or withhold, select between exactly **two** values:
/// a one-bit last-revealer bias. It is *bounded*: B cannot reach any third
/// value, because no β can be chosen (each is a deterministic VRF output).
/// This residual is what the lagged finalized read (FINALIZED_LAG) blunts;
/// removing the bit entirely needs threshold crypto or a VDF.
#[test]
fn last_revealer_has_a_one_bit_choice() {
    let only_a = fold_with_revealers(&[(VOTER_A, 1)]);
    let a_and_b = fold_with_revealers(&[(VOTER_A, 1), (VOTER_B, 2)]);
    assert_ne!(
        only_a, a_and_b,
        "the last revealer selects between exactly two outcomes"
    );
    // Order-independence: {A,B} and {B,A} reach the SAME value, so the last
    // revealer's lever is purely the include/withhold bit, not ordering.
    let b_and_a = fold_with_revealers(&[(VOTER_B, 2), (VOTER_A, 1)]);
    assert_eq!(a_and_b, b_and_a, "the combine is order-independent");
}
