//! A credentialed call's wire (`identity-and-authority.md` §5): the request,
//! its public digests and refusal codes, the input the log carries, the
//! origins, the binding digest and the scope, and the system rows apply
//! keeps.

use vos_wire::abi::Refusal;
use vos_wire::batch::{CredentialedInput, Input};
use vos_wire::credentials::{self, Bound, Tag};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{CredentialPublic, CredentialRefusal, Credentialed, Rejection};
use vos_wire::keys::{self, Due};
use vos_wire::result::InputRef;
use vos_wire::{Decode, Encode, SpaceId};

fn blake2b(bytes: &[u8]) -> [u8; 32] {
    vos_pvm::precompile::blake2b_256(bytes)
}

/// The origins' indexes: `Anonymous` 3 and `Owner` 4, each digest its 32
/// bytes.
#[test]
fn the_origins_are_indexes_three_and_four() {
    let anonymous = Principal::Anonymous {
        scope: [1; 32],
        nullifier: [2; 32],
    };
    assert_eq!(
        anonymous.encode(),
        [&[3u8][..], &[1; 32], &[2; 32]].concat()
    );
    assert_eq!(
        Principal::Owner([4; 32]).encode(),
        [&[4u8][..], &[4; 32]].concat()
    );
    assert_eq!(
        Principal::decode_exact(&anonymous.encode()),
        Some(anonymous)
    );
}

/// The request in SCALE, field by field, its public statement's index its
/// kind; the refusal codes in check order, under `Rejection`'s index 9.
#[test]
fn the_request_and_its_refusals_encode_as_pinned() {
    let call = Credentialed {
        instance: InstanceId(7),
        method: MethodId(0x0102_0304),
        arguments: vec![0xaa, 0xbb],
        nonce: [5; 16],
        expires_ms: 9,
        format: 42,
        public: CredentialPublic::Owner {
            owner: [6; 32],
            binding: [8; 32],
        },
        proof: vec![0xcc],
    };
    let expected = [
        &7u32.to_le_bytes()[..],
        &0x0102_0304u32.to_le_bytes(),
        &2u32.to_le_bytes(),
        &[0xaa, 0xbb],
        &[5; 16],
        &9u64.to_le_bytes(),
        &42u32.to_le_bytes(),
        &[1],
        &[6; 32],
        &[8; 32],
        &1u32.to_le_bytes(),
        &[0xcc],
    ]
    .concat();
    assert_eq!(call.encode(), expected);
    assert_eq!(Credentialed::decode_exact(&expected), Some(call));
    let auth = CredentialPublic::Auth {
        map_root: [1; 32],
        scope: [2; 32],
        nullifier: [3; 32],
        binding: [4; 32],
    };
    assert_eq!(auth.encode()[0], 0);
    assert_eq!(auth.kind(), 0);
    assert_eq!(auth.binding(), &[4; 32]);
    assert_eq!(
        auth.origin(),
        Principal::Anonymous {
            scope: [2; 32],
            nullifier: [3; 32]
        }
    );
    let words = auth.words().expect("words below p");
    assert_eq!(words.len(), 33);
    assert_eq!(words[0], 0);
    assert_eq!(words[1], u32::from_le_bytes([1; 4]));
    let wide = CredentialPublic::Owner {
        owner: [0xff; 32],
        binding: [0; 32],
    };
    assert_eq!(wide.words(), None, "a word at or above p");

    let codes = [
        CredentialRefusal::NoSpace,
        CredentialRefusal::Format,
        CredentialRefusal::Size,
        CredentialRefusal::Expiry { now: 3 },
        CredentialRefusal::Method,
        CredentialRefusal::Kind,
        CredentialRefusal::Scope,
        CredentialRefusal::Binding,
        CredentialRefusal::Replayed,
        CredentialRefusal::Once,
        CredentialRefusal::RootUnknown,
        CredentialRefusal::RootStale,
        CredentialRefusal::Proof,
    ];
    for (index, code) in codes.into_iter().enumerate() {
        let encoded = Rejection::Credential(code).encode();
        assert_eq!(encoded[..2], [9, index as u8], "{code:?}");
    }
    assert_eq!(
        CredentialRefusal::Expiry { now: 3 }.encode(),
        [&[3u8][..], &3u64.to_le_bytes()].concat()
    );
}

/// The log's input at `Input`'s index 10, without the proof, the nonce or
/// the format; its step's reference at `InputRef`'s index 9.
#[test]
fn the_logged_input_carries_the_origin_alone() {
    let input = CredentialedInput {
        origin: Principal::Owner([1; 32]),
        instance: InstanceId(2),
        method: MethodId(3),
        arguments: vec![4],
        binding: [5; 32],
        expires_ms: 6,
        root: None,
    };
    let fields = [
        &Principal::Owner([1; 32]).encode()[..],
        &2u32.to_le_bytes(),
        &3u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[4],
        &[5; 32],
        &6u64.to_le_bytes(),
        &[0],
    ]
    .concat();
    assert_eq!(
        Input::Credentialed(Box::new(input.clone())).encode(),
        [&[10u8][..], &fields].concat()
    );
    assert_eq!(
        InputRef::Credentialed { binding: [5; 32] }.encode(),
        [&[9u8][..], &[5; 32]].concat()
    );
    assert_eq!(Refusal::Replayed.code(), 8);
}

/// `b` is BLAKE2b-256 of its fields in order, each at its width, the
/// arguments with their `u32` length; any field changed changes it. The
/// proof's `binding` is `C(T(binding), W(b))`, and the scope
/// `C(T(scope), W(BLAKE2b-256(..)))` over the space, agent, instance and
/// name.
#[test]
fn the_binding_and_the_scope_are_their_fields_hashes() {
    let space = SpaceId([0x11; 32]);
    let program = [0x22; 32];
    let nonce = [0x33; 16];
    let bound = Bound {
        space: &space,
        agent: AgentId(0x0102_0304),
        instance: InstanceId(5),
        method: MethodId(6),
        program: &program,
        kind: 1,
        arguments: &[7, 8, 9],
        nonce: &nonce,
        expires_ms: 0x0a0b,
    };
    let expected = blake2b(
        &[
            &b"vos/cred/binding/v1"[..],
            &[0x11; 32],
            &0x0102_0304u32.to_le_bytes(),
            &5u32.to_le_bytes(),
            &6u32.to_le_bytes(),
            &[0x22; 32],
            &[1],
            &3u32.to_le_bytes(),
            &[7, 8, 9],
            &[0x33; 16],
            &0x0a0bu64.to_le_bytes(),
        ]
        .concat(),
    );
    assert_eq!(bound.digest(), expected);
    let changed = [
        Bound { kind: 0, ..bound },
        Bound {
            arguments: &[7, 8],
            ..bound
        },
        Bound {
            instance: InstanceId(4),
            ..bound
        },
        Bound {
            expires_ms: 0x0a0c,
            ..bound
        },
    ];
    for other in changed {
        assert_ne!(other.digest(), expected);
    }
    let binding = credentials::binding(&expected);
    let words = credentials::compress(&Tag::Binding.block(), &credentials::reduced(&expected));
    assert_eq!(binding, credentials::digest(&words));
    assert!(credentials::words(&binding).is_some());

    let scope = credentials::scope(&space, AgentId(1), InstanceId(2), b"vote");
    let hash = blake2b(
        &[
            &b"vos/cred/scope/v1"[..],
            &[0x11; 32],
            &1u32.to_le_bytes(),
            &2u32.to_le_bytes(),
            b"vote",
        ]
        .concat(),
    );
    let words = credentials::compress(&Tag::Scope.block(), &credentials::reduced(&hash));
    assert_eq!(scope, credentials::digest(&words));
    for other in [
        credentials::scope(&space, AgentId(9), InstanceId(2), b"vote"),
        credentials::scope(&SpaceId([0x12; 32]), AgentId(1), InstanceId(2), b"vote"),
        credentials::scope(&space, AgentId(1), InstanceId(2), b"vote/2"),
    ] {
        assert_ne!(other, scope);
    }
    // Two spaces sharing a handle: one secret, one guard's name, two
    // nullifiers.
    let secret = [1, 2, 3, 4, 5, 6, 7, 8];
    let nullifier = |scope: &credentials::Digest| {
        let key = credentials::compress(&Tag::Nf.block(), &secret);
        credentials::compress(&key, &credentials::words(scope).unwrap())
    };
    let elsewhere = credentials::scope(&SpaceId([0x12; 32]), AgentId(1), InstanceId(2), b"vote");
    assert_ne!(nullifier(&scope), nullifier(&elsewhere));
}

/// The rows apply keeps: the credential actor's instance, each binding
/// digest, each admitted nullifier by its scope; a binding's row of the
/// due index names its 32 bytes, and reads back.
#[test]
fn the_credential_rows_are_their_own_and_read_back() {
    assert_eq!(keys::credentials(), [0x00, 0x27]);
    assert_eq!(
        keys::binding(&[1; 32]),
        [&[0x00, 0x28][..], &[1; 32]].concat()
    );
    assert_eq!(
        keys::once(&[2; 32], &[3; 32]),
        [&[0x00, 0x29][..], &[2; 32], &[3; 32]].concat()
    );
    let row = keys::due(7, Due::Binding([9; 32]));
    assert_eq!(
        row,
        [&[0x00, 0x0f][..], &7u64.to_be_bytes(), &[2], &[9; 32]].concat()
    );
    assert_eq!(keys::due_entry(&row), Some((7, Due::Binding([9; 32]))));
    assert_eq!(keys::due_entry(&row[..row.len() - 1]), None);
    let session = keys::due(7, Due::Session(vos_wire::ids::SessionId(1)));
    assert_eq!(
        keys::due_entry(&[&session[..], &[0]].concat()),
        None,
        "a session's id is eight bytes"
    );
    let rows = [session.clone(), row.clone()];
    let listed = keys::due_rows(rows.iter().map(Ok::<_, ()>), 7, 8).unwrap();
    assert_eq!(listed.len(), 2);
}

/// The ring's row is the credential actor's hashed table `ring`'s one row,
/// under the key byte 0, at that actor's instance alone.
#[test]
fn the_rings_row_is_its_tables_one_row() {
    let rows = vos_wire::abi::Rows::Table {
        tag: vos_wire::ids::derive_id("vos/table/", credentials::tables::RING),
        transform: keys::Transform::Hashed,
    };
    let actor = InstanceId(9);
    assert_eq!(
        credentials::ring_key(actor),
        keys::row(actor, rows, &[credentials::tables::RING_KEY]).unwrap()
    );
    assert_ne!(
        credentials::ring_key(actor),
        credentials::ring_key(InstanceId(8))
    );
}
