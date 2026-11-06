//! Evidence: each admin call's signed message and signature, posted by
//! the device that made it under its sync key, stored as data beside the
//! call, its arguments compared byte for byte with the call recorded, and
//! a commit's Welcome bound by its hash.

use vos_wire::ids::{MethodId, Session};
use vos_wire::ingress::call_message;
use vos_wire::personal::{Body, Candidacy, Effect, Entry, PersonalError, Recorded, welcome_hash};

use super::*;

/// The message `key` signs for `method` with `arguments`, as a client
/// signs a call.
fn message(key: [u8; 32], method: MethodId, arguments: &[u8]) -> Vec<u8> {
    let session = Session {
        key,
        name: [7; 16],
        t0: T0,
    };
    call_message(&IDENTITY, &session, 4, PERSONAL, method, arguments)
}

/// The evidence call's arguments.
fn evidence(index: u64, message: Vec<u8>, welcome: Option<Vec<u8>>) -> impl Encode {
    ((index, message), ([0x5a_u8; 64], welcome))
}

/// A commit's evidence and a removal's are stored beside them, each once
/// and only from the device that made the call; a message whose
/// arguments, method, key or instance is not the call recorded is
/// refused, as is a Welcome missing, unexpected or not the one named; an
/// entry that is no admin call takes none. The log holds the evidence as
/// posted, its chain over it.
#[test]
fn evidence_is_stored_beside_its_call_its_arguments_byte_for_byte() {
    let mut home = Home::new();
    home.pair(0, 1);
    home.pass(72 * HOUR_MS);
    let welcome = vec![0x77u8; 1400];
    let effect = Effect {
        add: Some(device(2)),
        remove: Vec::new(),
    };
    let arguments = (
        (2u64, effect),
        (vec![0x22u8; 800], Some(welcome_hash(&welcome))),
    );
    let candidacy: Candidacy = home.call(admin(0), "commit", arguments.clone()).unwrap();
    let signed = arguments.encode();
    let commit = home.method("commit");
    let good = message(device(0).admin, commit, &signed);

    let refusals = [
        (
            sync(1),
            good.clone(),
            Some(welcome.clone()),
            PersonalError::NotYours,
        ),
        (
            admin(0),
            good.clone(),
            Some(welcome.clone()),
            PersonalError::NotAdmitted,
        ),
        (sync(0), good.clone(), None, PersonalError::Welcome),
        (
            sync(0),
            good.clone(),
            Some(vec![0x78; 1400]),
            PersonalError::Welcome,
        ),
        (
            sync(0),
            good[..good.len() - 1].to_vec(),
            Some(welcome.clone()),
            PersonalError::Mismatch,
        ),
        (
            sync(0),
            message(device(1).admin, commit, &signed),
            Some(welcome.clone()),
            PersonalError::Mismatch,
        ),
        (
            sync(0),
            message(device(0).admin, home.method("remove"), &signed),
            Some(welcome.clone()),
            PersonalError::Mismatch,
        ),
        (
            sync(0),
            {
                let mut altered = signed.clone();
                *altered.last_mut().unwrap() ^= 1;
                message(device(0).admin, commit, &altered)
            },
            Some(welcome.clone()),
            PersonalError::Mismatch,
        ),
        (
            sync(0),
            {
                let session = Session {
                    key: device(0).admin,
                    name: [7; 16],
                    t0: T0,
                };
                call_message(&IDENTITY, &session, 4, InstanceId(6), commit, &signed)
            },
            Some(welcome.clone()),
            PersonalError::Mismatch,
        ),
    ];
    for (caller, message, welcome, refusal) in refusals {
        assert_eq!(
            home.call::<Recorded>(
                caller,
                "evidence",
                evidence(candidacy.index, message, welcome)
            ),
            Err(refusal)
        );
    }
    let stored: Recorded = home
        .call(
            sync(0),
            "evidence",
            evidence(candidacy.index, good.clone(), Some(welcome.clone())),
        )
        .unwrap();
    assert_eq!(
        home.call::<Recorded>(
            sync(0),
            "evidence",
            evidence(candidacy.index, good.clone(), Some(welcome.clone()))
        ),
        Err(PersonalError::Evidenced)
    );
    let entries: Vec<(u64, Entry)> = home.query(sync(1), "log", stored.index).unwrap();
    assert_eq!(
        entries[0].1.body,
        Body::Evidence {
            index: candidacy.index,
            message: good,
            signature: [0x5a; 64],
            welcome: Some(welcome),
        }
    );
    let before: Vec<(u64, Entry)> = home.query(sync(1), "log", stored.index - 1).unwrap();
    assert_eq!(
        entries[0].1.chain,
        vos_wire::personal::chain(
            &before[0].1.chain,
            stored.index,
            entries[0].1.at,
            &entries[0].1.body
        ),
        "the chain runs over the evidence as posted"
    );

    // A removal's evidence carries no Welcome.
    let removal: Recorded = home.call(admin(0), "remove", 1u32).unwrap();
    let signed = message(device(0).admin, home.method("remove"), &1u32.encode());
    assert_eq!(
        home.call::<Recorded>(
            sync(0),
            "evidence",
            evidence(removal.index, signed.clone(), Some(vec![1]))
        ),
        Err(PersonalError::Welcome)
    );
    home.call::<Recorded>(sync(0), "evidence", evidence(removal.index, signed, None))
        .unwrap();
    // Evidence is no admin call.
    assert_eq!(
        home.call::<Recorded>(
            sync(0),
            "evidence",
            evidence(stored.index, Vec::new(), None)
        ),
        Err(PersonalError::NotAdminCall)
    );
}
