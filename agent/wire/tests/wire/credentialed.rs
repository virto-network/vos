//! A proven call's wire (`identity-and-authority.md` §5): the request, its
//! claim and refusal codes, the stock claims, the input the log carries,
//! the origins, the binding digest and the scope, and the system rows
//! apply keeps.

use vos_abi::abi::Refusal;
use vos_abi::credentials::Tag;
use vos_abi::ids::{AgentId, InstanceId, MethodId, Principal, ProgramHash};
use vos_abi::keys::{self, Due};
use vos_abi::records::DeviceRelease;
use vos_abi::result::InputRef;
use vos_abi::{Decode, Encode, SpaceId, defaults};
use vos_wire::batch::{CredentialedInput, Input};
use vos_wire::credentials::{self, AuthClaim, Bound, OwnerClaim};
use vos_wire::ingress::{CredentialRefusal, Credentialed, Rejection};

fn blake2b(bytes: &[u8]) -> [u8; 32] {
    vos_pvm::precompile::blake2b_256(bytes)
}

/// The origins' indexes: `Anonymous` 3, `Owner` 4 and `Kernel` 7, each
/// digest its 32 bytes; 5 and 6 are reserved.
#[test]
fn the_origins_are_indexes_three_four_and_seven() {
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
    let kernel = Principal::Kernel { program: [5; 32] };
    assert_eq!(kernel.encode(), [&[7u8][..], &[5; 32]].concat());
    assert_eq!(Principal::decode_exact(&kernel.encode()), Some(kernel));
    for reserved in [5u8, 6] {
        assert_eq!(
            Principal::decode_exact(&[&[reserved][..], &[0; 32]].concat()),
            None
        );
    }
}

/// The request in SCALE, field by field, its claim bytes; the stock claims
/// their digests alone, a claim's binding its last 32 bytes; the refusal
/// codes in check order, under `Rejection`'s index 9.
#[test]
fn the_request_and_its_refusals_encode_as_pinned() {
    let call = Credentialed {
        instance: InstanceId(7),
        method: MethodId(0x0102_0304),
        arguments: vec![0xaa, 0xbb],
        nonce: [5; 16],
        expires_ms: 9,
        format: 47,
        claim: vec![6; 40],
        proof: vec![0xcc],
    };
    let expected = [
        &7u32.to_le_bytes()[..],
        &0x0102_0304u32.to_le_bytes(),
        &2u32.to_le_bytes(),
        &[0xaa, 0xbb],
        &[5; 16],
        &9u64.to_le_bytes(),
        &47u32.to_le_bytes(),
        &40u32.to_le_bytes(),
        &[6; 40],
        &1u32.to_le_bytes(),
        &[0xcc],
    ]
    .concat();
    assert_eq!(call.encode(), expected);
    assert_eq!(Credentialed::decode_exact(&expected), Some(call));
    let auth = AuthClaim {
        map_root: [1; 32],
        scope: [2; 32],
        nullifier: [3; 32],
        binding: [4; 32],
    };
    let bytes = auth.encode();
    assert_eq!(bytes, [[1; 32], [2; 32], [3; 32], [4; 32]].concat());
    assert_eq!(bytes.len(), AuthClaim::BYTES);
    assert_eq!(credentials::claim_binding(&bytes), Some(&[4; 32]));
    let owner = OwnerClaim {
        owner: [6; 32],
        binding: [8; 32],
    };
    assert_eq!(owner.encode(), [[6; 32], [8; 32]].concat());
    assert_eq!(owner.encode().len(), OwnerClaim::BYTES);
    assert_eq!(
        OwnerClaim::decode_exact(&bytes),
        None,
        "auth's is no owner's"
    );
    assert_eq!(credentials::claim_binding(&[1; 31]), None);
    assert_eq!(
        credentials::claim_binding(&[&[0u8; 8][..], &[9; 32]].concat()),
        Some(&[9; 32])
    );

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

/// The log's input at `Input`'s index 10, its claim, its kernel, its
/// device format and the kernel's release beside the origin, without the
/// proof or the nonce; its step's reference at `InputRef`'s index 9.
#[test]
fn the_logged_input_carries_the_origin_and_the_claim() {
    let input = CredentialedInput {
        origin: Principal::Owner([1; 32]),
        instance: InstanceId(2),
        method: MethodId(3),
        arguments: vec![4],
        binding: [5; 32],
        expires_ms: 6,
        claim: vec![7; 3],
        kernel: MethodId(8),
        format: 47,
        release: DeviceRelease {
            kernel: ProgramHash([9; 32]),
            reference: ProgramHash([10; 32]),
            headroom: 11,
        },
    };
    let fields = [
        &Principal::Owner([1; 32]).encode()[..],
        &2u32.to_le_bytes(),
        &3u32.to_le_bytes(),
        &1u32.to_le_bytes(),
        &[4],
        &[5; 32],
        &6u64.to_le_bytes(),
        &3u32.to_le_bytes(),
        &[7; 3],
        &8u32.to_le_bytes(),
        &47u32.to_le_bytes(),
        &[9; 32],
        &[10; 32],
        &[11],
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
            &3u32.to_le_bytes(),
            &[7, 8, 9],
            &[0x33; 16],
            &0x0a0bu64.to_le_bytes(),
        ]
        .concat(),
    );
    assert_eq!(bound.digest(), expected);
    let changed = [
        Bound {
            program: &[0x23; 32],
            ..bound
        },
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
    let words = vos_abi::credentials::compress(
        &Tag::Binding.block(),
        &vos_abi::credentials::reduced(&expected),
    );
    assert_eq!(binding, vos_abi::credentials::digest(&words));
    assert!(vos_abi::credentials::words(&binding).is_some());

    let scope = credentials::scope(&space, AgentId(1), InstanceId(2), b"vote");
    let hash = blake2b(
        &[
            &b"vos/cred/scope/v1"[..],
            &[0x11; 32],
            &1u32.to_le_bytes(),
            &2u32.to_le_bytes(),
            &4u32.to_le_bytes(),
            b"vote",
        ]
        .concat(),
    );
    let words =
        vos_abi::credentials::compress(&Tag::Scope.block(), &vos_abi::credentials::reduced(&hash));
    assert_eq!(scope, vos_abi::credentials::digest(&words));
    // The device library's vector (`vos-light`'s `SCOPE_VECTOR`): the
    // name in SCALE, as `proving.md` §8 pins it.
    assert_eq!(
        credentials::scope(&SpaceId([0x51; 32]), AgentId(4), InstanceId(2), b"login"),
        [
            176, 47, 24, 3, 211, 3, 208, 103, 92, 44, 198, 75, 144, 255, 58, 99, 210, 27, 59, 25,
            235, 172, 49, 126, 162, 142, 147, 35, 82, 189, 54, 43,
        ]
    );
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
    let nullifier = |scope: &vos_abi::credentials::Digest| {
        let key = vos_abi::credentials::compress(&Tag::Nf.block(), &secret);
        vos_abi::credentials::compress(&key, &vos_abi::credentials::words(scope).unwrap())
    };
    let elsewhere = credentials::scope(&SpaceId([0x12; 32]), AgentId(1), InstanceId(2), b"vote");
    assert_ne!(nullifier(&scope), nullifier(&elsewhere));
}

/// The rows apply keeps: the credential actor's instance, each binding
/// digest, each admitted nullifier by its scope; a binding's due row is
/// in its own index, its time then its 32 bytes, and reads back; each
/// index lists its own rows, so due bindings never hold a session's row
/// back.
#[test]
fn the_credential_rows_are_their_own_and_read_back() {
    assert_eq!(keys::credentials(), [0x00, 0x26]);
    assert_eq!(
        keys::binding(&[1; 32]),
        [&[0x00, 0x27][..], &[1; 32]].concat()
    );
    assert_eq!(
        keys::once(&[2; 32], &[3; 32]),
        [&[0x00, 0x28][..], &[2; 32], &[3; 32]].concat()
    );
    let row = keys::due(7, Due::Binding([9; 32]));
    assert_eq!(
        row,
        [&[0x00, 0x2d][..], &7u64.to_be_bytes(), &[9; 32]].concat()
    );
    assert_eq!(keys::DueIndex::Bindings.prefix(), [0x00, 0x2d]);
    assert_eq!(keys::due_entry(&row), Some((7, Due::Binding([9; 32]))));
    assert_eq!(keys::due_entry(&row[..row.len() - 1]), None);
    assert_eq!(keys::due_entry(&[&row[..], &[0]].concat()), None);
    let session = keys::due(7, Due::Session(vos_abi::ids::SessionId(1)));
    assert_eq!(
        keys::due_entry(&[&session[..], &[0]].concat()),
        None,
        "a session's id is eight bytes"
    );
    // More bindings due than a sweep forgets, all before the session's
    // row: the sweep lists its most of them, and the session's row too.
    let bindings: Vec<Vec<u8>> = (0..=defaults::SWEEP_BINDINGS as u8)
        .map(|byte| keys::due(1, Due::Binding([byte; 32])))
        .collect();
    let scan = |index: keys::DueIndex| match index {
        keys::DueIndex::Rows => vec![Ok::<_, ()>(session.clone())],
        keys::DueIndex::Bindings => bindings.iter().cloned().map(Ok).collect(),
    };
    let listed = keys::sweep_rows(scan, 7, 8).unwrap();
    assert_eq!(listed.len(), 1 + defaults::SWEEP_BINDINGS);
    assert_eq!(listed[0], (7, Due::Session(vos_abi::ids::SessionId(1))));
}

/// The ring's row is the credential actor's hashed table `ring`'s one row,
/// under the key byte 0, at that actor's instance alone.
#[test]
fn the_rings_row_is_its_tables_one_row() {
    let rows = vos_abi::abi::Rows::Table {
        tag: vos_abi::ids::derive_id("vos/table/", credentials::tables::RING),
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
