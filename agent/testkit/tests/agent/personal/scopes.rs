//! Sealed scopes: pushes deduplicated by id before the epoch check,
//! numbered per scope, read back by cursor; checkpoint acknowledgements;
//! the quotas, their exemptions and each device's share; and what a push
//! and a read cost.

use vos_wire::personal::{
    Acknowledged, Candidacy, Envelope, MAX_ENVELOPE, PersonalError, Policy, Pushed, RECOVERY,
    Recorded, envelope_id,
};
use vos_wire::result::Outcome;

use super::*;

/// A10: an envelope pushed again answers where it is stored, before its
/// epoch is checked, so a retry after a key change is no `StaleEpoch`; a
/// new envelope under an old epoch is; each scope numbers its envelopes
/// in the order taken.
#[test]
fn a_push_is_deduplicated_before_its_epoch_is_checked() {
    let mut home = Home::new();
    let first = envelope(scope(1), 0, 1, 300);
    let pushed = home.push(0, first.clone()).unwrap();
    assert_eq!((pushed.position, pushed.id), (1, envelope_id(&first)));
    let other = home.push(0, envelope(scope(2), 0, 2, 300)).unwrap();
    assert_eq!(other.position, 1, "a scope of its own");
    let candidacy: Candidacy = home.call(admin(0), "commit", update(1, 1)).unwrap();
    // Under a pending candidate the confirmed epoch is still 0.
    let second = home.push(0, envelope(scope(1), 0, 3, 300)).unwrap();
    assert_eq!(second.position, 2);
    home.confirm_all(1, &candidacy.set);
    let again = home.push(0, first.clone()).unwrap();
    assert_eq!((again.position, again.id), (1, pushed.id));
    assert_eq!(
        home.push(0, envelope(scope(1), 0, 4, 300)),
        Err(PersonalError::StaleEpoch { confirmed: 1 })
    );
    assert_eq!(
        home.push(0, envelope(scope(1), 2, 4, 300)),
        Err(PersonalError::StaleEpoch { confirmed: 1 })
    );
    let third = home.push(0, envelope(scope(1), 1, 4, 300)).unwrap();
    assert_eq!(third.position, 3);
    assert_eq!(
        home.push(0, vec![0; Header::BYTES - 1]),
        Err(PersonalError::Malformed)
    );
    assert_eq!(
        home.push(0, envelope(scope(1), 1, 5, MAX_ENVELOPE + 1)),
        Err(PersonalError::TooLarge)
    );
}

/// `since` answers a scope's envelopes after a position, in order, each
/// with its position, id and bytes, as many as one answer holds and at
/// least one; the kit reads the recovery scope and no other.
#[test]
fn since_answers_positions_ids_and_bytes_in_order() {
    let mut home = Home::new();
    home.pair(0, 1);
    let mut pushed = Vec::new();
    for (n, len) in [(1u8, 200), (2, 60 << 10), (3, 60 << 10), (4, 900), (5, 20)] {
        let bytes = envelope(scope(9), 1, n, len);
        home.push(n % 2, envelope(scope(8), 1, n, 100)).unwrap();
        let at = home.push(n % 2, bytes.clone()).unwrap();
        pushed.push(Envelope {
            position: at.position,
            id: at.id,
            bytes,
        });
    }
    let mut read = Vec::new();
    let mut cursor = 0;
    let mut answers = 0;
    loop {
        let answer: Vec<Envelope> = home.query(sync(1), "since", (scope(9), cursor)).unwrap();
        let Some(last) = answer.last() else { break };
        cursor = last.position;
        answers += 1;
        read.extend(answer);
    }
    assert_eq!(read, pushed);
    assert_eq!(answers, 4, "each 60 KiB envelope alone in its answer");
    let from: Vec<Envelope> = home.query(sync(0), "since", (scope(9), 3u64)).unwrap();
    assert_eq!(from, pushed[3..]);
    // The kit: the recovery scope only.
    let recovery = envelope(RECOVERY, 1, 0xaa, 400);
    home.push(0, recovery.clone()).unwrap();
    let kit_read: Vec<Envelope> = home.query(KIT, "since", (RECOVERY, 0u64)).unwrap();
    assert_eq!(kit_read[0].bytes, recovery);
    assert_eq!(
        home.query::<Vec<Envelope>>(KIT, "since", (scope(9), 0u64)),
        Err(PersonalError::NotAdmitted)
    );
    assert_eq!(
        home.call::<Pushed>(KIT, "push", envelope(RECOVERY, 1, 0xab, 400)),
        Err(PersonalError::NotAdmitted),
        "the kit pushes nothing"
    );
}

/// A device acknowledges a checkpoint at a stored position; the devices
/// and the kit read the acknowledgements, a restore's trust.
#[test]
fn checkpoint_acknowledgements_are_stored_and_read() {
    let mut home = Home::new();
    home.pair(0, 1);
    for n in 0..3 {
        home.push(0, envelope(scope(1), 1, n, 100)).unwrap();
    }
    assert_eq!(
        home.call::<u64>(sync(1), "acknowledge", (scope(1), 4u64, [1u8; 32])),
        Err(PersonalError::NoPosition)
    );
    assert_eq!(
        home.call::<u64>(sync(1), "acknowledge", (scope(1), 0u64, [1u8; 32])),
        Err(PersonalError::NoPosition)
    );
    home.call::<u64>(sync(1), "acknowledge", (scope(1), 3u64, [3u8; 32]))
        .unwrap();
    home.call::<u64>(sync(0), "acknowledge", (scope(1), 3u64, [3u8; 32]))
        .unwrap();
    home.call::<u64>(sync(1), "acknowledge", (scope(1), 2u64, [2u8; 32]))
        .unwrap();
    let acks: Vec<Acknowledged> = home
        .query(KIT, "acknowledgements", (scope(1), 0u64))
        .unwrap();
    let ack = |position, device, hash| Acknowledged {
        position,
        device,
        hash: [hash; 32],
    };
    assert_eq!(acks, vec![ack(2, 1, 2), ack(3, 0, 3), ack(3, 1, 3)]);
    let later: Vec<Acknowledged> = home
        .query(sync(0), "acknowledgements", (scope(1), 2u64))
        .unwrap();
    assert_eq!(later, acks[1..]);
}

/// C5: the agent's bytes, its envelopes a day and each device's share,
/// half the agent's while it has another device, bound pushes; a full
/// quota still takes a removal, the commit carrying it, the votes and
/// `alive`, so no device blocks its own removal by filling it; a re-proof
/// raises the bytes held.
#[test]
fn quotas_bound_pushes_and_exempt_what_removes_a_device() {
    let policy = Policy {
        bytes_new: 64 << 10,
        bytes_full: 128 << 10,
        envelopes_per_day: 12,
        commits_per_day: 3,
        probation_ms: HOUR_MS,
        removal_delay_ms: HOUR_MS,
        ..Policy::DEFAULT
    };
    let mut home = Home::with(policy);
    home.pair(0, 1);
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    // Device 1, a thief's: its share is half the agent's bytes.
    let eight = |n| envelope(scope(1), 1, n, 8 << 10);
    for n in 0..4 {
        home.push(1, eight(n)).unwrap();
    }
    assert_eq!(home.push(1, eight(4)), Err(PersonalError::Quota));
    for n in 10..14 {
        home.push(0, eight(n)).unwrap();
    }
    assert_eq!(
        home.push(0, envelope(scope(1), 1, 20, 100)),
        Err(PersonalError::Quota),
        "the agent's bytes"
    );
    // The commits a day: the pairing's and two updates spend them.
    for epoch in [2, 3] {
        let taken: Candidacy = home
            .call(admin(0), "commit", update(epoch, epoch as u8))
            .unwrap();
        home.confirm_all(epoch, &taken.set);
    }
    assert_eq!(
        home.call::<Candidacy>(admin(0), "commit", update(4, 4)),
        Err(PersonalError::Quota)
    );
    // The same day, what removes the thief's device is taken.
    home.call::<Recorded>(admin(0), "remove", 1u32).unwrap();
    home.call::<Recorded>(sync(1), "alive", ()).unwrap();
    home.call::<Recorded>(sync(0), "alive", ()).unwrap();
    home.pass(HOUR_MS);
    let removal = home.commit_removing(0, vec![1]);
    assert_eq!(removal.set, vec![0]);
    assert_eq!(
        home.push(0, envelope(scope(1), 4, 21, 100)),
        Err(PersonalError::Quota),
        "the bytes held still"
    );
    // A re-proof raises the bytes held; the envelopes a day still bound.
    home.call::<Recorded>(HOMES, "renew", ()).unwrap();
    for n in 30..34 {
        home.push(0, envelope(scope(1), 4, n, 100)).unwrap();
    }
    assert_eq!(
        home.push(0, envelope(scope(1), 4, 34, 100)),
        Err(PersonalError::Quota),
        "twelve envelopes a day"
    );
    home.pass(DAY);
    home.push(0, envelope(scope(1), 4, 35, 100)).unwrap();
}

/// What a push and a read cost on the agent: the gas a push of an
/// envelope runs and the bytes it writes, and the gas of `since` answering
/// it, for a small, a middling and a largest envelope.
#[test]
fn a_push_and_its_read_cost() {
    let mut home = Home::new();
    // A first push makes the scope's and the device's rows.
    home.push(0, envelope(scope(1), 0, 0, 100)).unwrap();
    for (n, len) in [(1u8, 1usize << 10), (2, 16 << 10), (3, MAX_ENVELOPE)] {
        let bytes = envelope(scope(1), 0, n, len);
        let run = home.run(sync(0), "push", bytes);
        let pushed: Pushed = match &run.outcome {
            Outcome::Done(reply) => Pushed::decode_exact(reply).unwrap(),
            other => panic!("{other:?}"),
        };
        let written: usize = run
            .writes
            .iter()
            .map(|write| write.key.len() + write.value.as_ref().map_or(0, Vec::len))
            .sum();
        let query = Work::Query(Query {
            time: home.now,
            seed: [0; 32],
            caller: sync(0),
            instance: PERSONAL,
            method: home.method("since"),
            arguments: (scope(1), pushed.position - 1).encode(),
        });
        let since = home.node.run_refine(&query, crate::common::OUTER_GAS);
        eprintln!(
            "an envelope of {len} B: push {} gas, {} rows, {written} B written \
             ({} B beyond the envelope); since {} gas",
            run.gas_used,
            run.writes.len(),
            written - len,
            since.gas_used,
        );
        assert!(written - len < 1024, "a push's rows beyond its bytes");
        // Within a handler's default gas, a read's and a push's alike.
        assert!(run.gas_used < vos_wire::defaults::HANDLER_GAS);
        assert!(since.gas_used < vos_wire::defaults::HANDLER_GAS);
    }
}

/// The share binds what a device adds once the agent has a second device:
/// a sole device holding more than half the bytes pushes again after it
/// pairs another, within its share from then.
#[test]
fn a_share_counts_from_the_second_device() {
    let policy = Policy {
        bytes_new: 64 << 10,
        ..Policy::DEFAULT
    };
    let mut home = Home::with(policy);
    for n in 0..5 {
        home.push(0, envelope(scope(1), 0, n, 8 << 10)).unwrap();
    }
    home.pair(0, 1);
    for n in 5..8 {
        home.push(0, envelope(scope(1), 1, n, 8 << 10)).unwrap();
    }
    assert_eq!(
        home.push(0, envelope(scope(1), 1, 8, 8 << 10)),
        Err(PersonalError::Quota),
        "the agent's bytes"
    );
}
