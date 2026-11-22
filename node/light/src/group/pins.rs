//! The group's stored state and the pairing's handover pinned: an
//! every-field value of each encoded, so a change to either is a new
//! layout of the store (`crate::store::LAYOUT`) or a new pairing code
//! (`crate::pairing`), never a silent one.

use vos_abi::Encode;
use vos_abi::ids::InstanceId;
use vos_wire::personal::{
    AdminClass, Attestation, Effect, KitKind, NewDevice, NewKit, Op, Policy, Signer, Vote,
};

use super::archive::{Archive, Recovery};
use super::state::{
    Act, Call, Check, Claim, Course, Known, Made, Named, Own, Passing, Pending, Sent, Set, State,
    Support,
};
use super::{Agent, Pairing};
use crate::kit::KitKey;

fn device(fill: u8) -> NewDevice {
    NewDevice {
        sync: [fill; 32],
        admin: [fill + 1; 32],
        class: AdminClass::Strong,
        attestation: Attestation {
            hardware: true,
            verified_boot: false,
        },
        nullifier: [fill + 2; 32],
        label: vec![fill + 3; 2],
    }
}

fn effect() -> Effect {
    Effect {
        add: Some(device(40)),
        remove: vec![41],
        rekey: Some(NewKit {
            entries: Vec::new(),
            r2_hash: [42; 32],
            r_hash: [43; 32],
        }),
    }
}

fn known() -> Known {
    Known {
        keys: device(1),
        admin: [5; 32],
        leaf: [6; 32],
        strong: true,
        active_from: 7,
        frozen: Some(8),
        matured: Some(9),
        out: true,
        alive: 10,
    }
}

fn set() -> Set {
    Set {
        kit: vec![KitKey {
            kind: KitKind::Phrase,
            signing: [11; 32],
            sealing: [12; 32],
        }],
        operations: vec![Call {
            index: 13,
            at: 14,
            by: Signer::Device(15),
            origin: [16; 32],
            method: 17,
            arguments: vec![18],
            act: Act::Op {
                op: Op::Remove(19),
                matures: 20,
            },
            evidence: Check::Valid,
            rival: Some(21),
            awaits: Some(22),
        }],
        claims: vec![Claim {
            entry: 23,
            op: 24,
            rival: Some(25),
            at: 26,
            every: true,
            removes: vec![27],
            removed: vec![28],
            support: Support::Held,
        }],
        closed: vec![29],
        owed: vec![30],
        adds: vec![device(31)],
        fresh: Some(35),
    }
}

fn agent() -> Agent {
    Agent {
        identity: [36; 32],
        instance: InstanceId(37),
    }
}

fn named() -> Named {
    Named {
        since: 38,
        hash: [39; 32],
        by_kit: true,
    }
}

fn state() -> State {
    State {
        agent: agent(),
        me: device(50),
        id: Some(54),
        next: 55,
        chain: [56; 32],
        floor: 57,
        time: 58,
        calls: vec![59],
        confirmed: 60,
        offset: 61,
        policy: Policy::DEFAULT,
        devices: vec![(62, known())],
        set: set(),
        pending: Some(Pending {
            index: 63,
            at: 64,
            epoch: 65,
            by: 66,
            set: vec![67],
            chain: [68; 32],
            added: Some(69),
            effect: effect(),
            handshake: vec![70],
            welcome_hash: Some([71; 32]),
            origin: [72; 32],
            arguments: vec![73],
            evidence: Check::Missing,
            awaits: Some(74),
            welcome: Some(vec![75]),
            votes: vec![(76, Vote::Confirm([77; 32]))],
            mine: Some(Vote::Nack),
            logged: true,
        }),
        passing: Some(Passing {
            epoch: 78,
            at: 79,
            added: Some(80),
            effect: effect(),
        }),
        own: Some(Own {
            epoch: 81,
            welcome: Some(vec![82]),
            arguments: vec![83],
            signed: Some((vec![84], [85; 64])),
            r2: Some([86; 32]),
            index: Some(87),
            evidenced: true,
        }),
        decided: Some((88, true)),
        course: Course::Stuck {
            epoch: 89,
            committer: 90,
        },
        recovery: Some(named()),
        rekeyed: Some((91, [92; 32])),
        made: vec![Made {
            index: 93,
            origin: [94; 32],
            method: 95,
            arguments: vec![96],
            dropped: true,
        }],
        sent: vec![Sent {
            message: vec![97],
            signature: [98; 64],
            r2: Some([99; 32]),
            index: Some(100),
        }],
        reseal: true,
        views: vec![(101, [102; 32])],
        ahead: Some(103),
        assigned: Some(104),
        leaving: true,
    }
}

fn pairing() -> Pairing {
    Pairing {
        agent: agent(),
        next: 105,
        chain: [106; 32],
        floor: 107,
        time: 108,
        confirmed: 109,
        offset: 110,
        policy: Policy::DEFAULT,
        devices: vec![(111, known())],
        set: set(),
        recovery: Some(named()),
        assigned: Some(112),
        archive: Archive {
            naming: [113; 32],
            previous: vec![[114; 32]],
            scopes: vec![[115; 16]],
            keys: vec![((116, [117; 16]), vec![[118; 32]])],
            recovery: Some(Recovery {
                since: 119,
                r: [120; 32],
            }),
            drawn: vec![[121; 32]],
        },
    }
}

/// BLAKE2b-256 of `bytes`, in hex.
fn digest(bytes: &[u8]) -> String {
    use blake2::Digest as _;
    hex::encode(blake2::Blake2b::<blake2::digest::consts::U32>::digest(
        bytes,
    ))
}

#[test]
fn the_group_state_and_the_pairing_handover_are_pinned() {
    assert_eq!(digest(&state().encode()), STATE, "the group's state row");
    assert_eq!(
        digest(&pairing().encode()),
        PAIRING,
        "the pairing's handover"
    );
}

const STATE: &str = "f6f57dd723a2f7f6916c3ea24dea0265e0d849dd251a482949f3864567e73099";
const PAIRING: &str = "4a1b65ce6569747f2db1d319ca93bb70a438f1ef705fc2b09a771760544e40fb";
