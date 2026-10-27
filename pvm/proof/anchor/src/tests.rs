use alloc::vec;
use alloc::vec::Vec;

use super::*;

#[cfg(feature = "vectors")]
fn hex(bytes: &[u8]) -> alloc::string::String {
    bytes
        .iter()
        .map(|byte| alloc::format!("{byte:02x}"))
        .collect()
}

fn genesis() -> SpaceGenesis {
    SpaceGenesis {
        nodes: vec![(1, [0x11; 32]), (2, [0x22; 32])],
        clock: WindowClock {
            origin_ms: 1_000_000,
            length_ms: 600_000,
        },
        time: 1_000_123,
        nonce: [0x0e; 16],
    }
}

/// The genesis's encoding, field by field; its decode; the id over it.
#[test]
fn a_genesis_encodes_field_by_field() {
    let genesis = genesis();
    let bytes = genesis.encode();
    let mut expected = vec![1, 2 << 2, 1];
    expected.extend_from_slice(&[0x11; 32]);
    expected.push(2);
    expected.extend_from_slice(&[0x22; 32]);
    expected.extend_from_slice(&1_000_000u64.to_le_bytes());
    expected.extend_from_slice(&600_000u64.to_le_bytes());
    expected.extend_from_slice(&1_000_123u64.to_le_bytes());
    expected.extend_from_slice(&[0x0e; 16]);
    assert_eq!(bytes, expected);
    assert_eq!(SpaceGenesis::decode(&bytes), Ok(genesis.clone()));
    assert_eq!(
        space_id(&genesis).0,
        blake2b_256(&[b"vos/space/id", &expected]),
        "the id hashes the bytes a venue is given"
    );
}

/// A genesis decode refuses what is not one canonical genesis of its
/// version: another version, a byte short, a byte more, the count in a
/// longer compact mode, a count past the input, no node, node numbers not
/// strictly ascending. Its encoding writes its one version.
#[test]
fn a_genesis_decode_is_canonical() {
    let bytes = genesis().encode();
    let refused = |bytes: &[u8]| SpaceGenesis::decode(bytes).unwrap_err();
    for version in [0, 2, 0xff] {
        let mut other = bytes.clone();
        other[0] = version;
        assert_eq!(refused(&other), DecodeError::Noncanonical, "{version}");
    }
    assert_eq!(refused(&bytes[..bytes.len() - 1]), DecodeError::Short);
    let mut more = bytes.clone();
    more.push(0);
    assert_eq!(refused(&more), DecodeError::Trailing);
    let long = [&bytes[..1], &[(2 << 2) | 1, 0], &bytes[2..]].concat();
    assert_eq!(refused(&long), DecodeError::Noncanonical);
    let past = [&bytes[..1], &[60 << 2], &bytes[2..]].concat();
    assert_eq!(refused(&past), DecodeError::Short);
    // The nodes: none; one number twice; two out of order.
    let mut none = genesis();
    none.nodes.clear();
    assert_eq!(refused(&none.encode()), DecodeError::Noncanonical);
    type Nodes = fn(&mut Vec<(NodeNumber, [u8; 32])>);
    let unordered: [Nodes; 2] = [|nodes| nodes[1].0 = 1, |nodes| nodes.swap(0, 1)];
    for change in unordered {
        let mut other = genesis();
        change(&mut other.nodes);
        assert_eq!(refused(&other.encode()), DecodeError::Noncanonical);
    }
    assert_eq!(bytes[0], GENESIS_VERSION);
}

/// Window w holds `[B_{w-1}, B_w)`: the origin opens window 0, a time
/// exactly at a boundary is the next window's, a time before the origin
/// has none, and a clock of no length numbers nothing.
#[test]
fn windows_at_their_edges() {
    let clock = genesis().clock;
    assert_eq!(clock.window(0), None);
    assert_eq!(
        clock.window(999_999),
        None,
        "a millisecond before the origin"
    );
    assert_eq!(clock.window(1_000_000), Some(0), "the origin");
    assert_eq!(clock.boundary(0), Some(1_600_000));
    assert_eq!(clock.window(1_599_999), Some(0), "a millisecond before B_0");
    assert_eq!(clock.window(1_600_000), Some(1), "exactly B_0");
    let mut start = clock.origin_ms;
    for w in 0..5 {
        let boundary = clock.boundary(w).unwrap();
        assert_eq!(boundary - start, 600_000, "{w}");
        assert_eq!(clock.window(start), Some(w), "{w}");
        assert_eq!(clock.window(boundary - 1), Some(w), "{w}");
        assert_eq!(clock.window(boundary), Some(w + 1), "{w}");
        start = boundary;
    }
    assert_eq!(
        clock.window(u64::MAX),
        Some((u64::MAX - 1_000_000) / 600_000)
    );
    assert_eq!(clock.boundary(u64::MAX), None, "past u64");
    assert_eq!(clock.boundary(u64::MAX / 600_000), None, "past u64");
    let none = WindowClock {
        origin_ms: 0,
        length_ms: 0,
    };
    assert_eq!(none.window(5), None);
    let at_top = WindowClock {
        origin_ms: u64::MAX,
        length_ms: 600_000,
    };
    assert_eq!(at_top.window(u64::MAX), Some(0));
    assert_eq!(at_top.boundary(0), None);
}

/// The lengths a venue registers, at their ends; the default among them.
#[test]
fn registrable_lengths() {
    let clock = |length_ms| WindowClock {
        origin_ms: 0,
        length_ms,
    };
    for (length, registrable) in [
        (0, false),
        (119_999, false),
        (120_000, true),
        (600_000, true),
        (3_600_000, true),
        (3_600_001, false),
    ] {
        assert_eq!(clock(length).registrable(), registrable, "{length}");
    }
    assert!(WindowClock::DEFAULT.registrable());
    assert_eq!(WindowClock::DEFAULT.length_ms, 600_000);
    assert_eq!(WindowClock::default(), WindowClock::DEFAULT);
}

/// The representative's clock lags by a fifth of a window, at most two
/// minutes: its cut of window w falls at `B_w + D`.
#[test]
fn the_representatives_clock() {
    for (length, delay) in [(120_000, 24_000), (600_000, 120_000), (3_600_000, 120_000)] {
        let clock = WindowClock {
            origin_ms: 5_000,
            length_ms: length,
        };
        let representative = clock.representative().unwrap();
        assert_eq!(representative.origin_ms, 5_000 + delay, "{length}");
        assert_eq!(representative.length_ms, length);
        assert_eq!(
            representative.boundary(7),
            Some(clock.boundary(7).unwrap() + delay)
        );
    }
    let at_top = WindowClock {
        origin_ms: u64::MAX,
        length_ms: 600_000,
    };
    assert_eq!(at_top.representative(), None);
}

/// One root kind is known; every other byte is refused at decode, in a
/// root read and in an anchor.
#[test]
fn an_unknown_root_kind_is_refused_at_decode() {
    let read = RootRead {
        kind: RootKind::Space,
        space: SpaceId([0xa1; 32]),
        window: 7,
        root: [0xb2; 32],
    };
    let mut bytes = Vec::new();
    read.encode_to(&mut bytes);
    assert_eq!(bytes.len(), RootRead::BYTES);
    assert_eq!(bytes[0], 0);
    assert_eq!(RootRead::decode_from(&mut Reader::new(&bytes)), Ok(read));
    let anchor = Anchor {
        space: read.space,
        window: 7,
        kind: RootKind::Space,
        root: read.root,
        signer: [0x5e; 32],
        signature: [0x51; 64],
    };
    let encoded = anchor.encode();
    assert_eq!(encoded.len(), Anchor::BYTES);
    assert_eq!(Anchor::decode(&encoded), Ok(anchor));
    for kind in 1..=u8::MAX {
        assert_eq!(RootKind::from_u8(kind), None);
        assert_eq!(RootKind::try_from(kind), Err(DecodeError::Noncanonical));
        let mut unknown = bytes.clone();
        unknown[0] = kind;
        assert_eq!(
            RootRead::decode_from(&mut Reader::new(&unknown)),
            Err(DecodeError::Noncanonical),
            "{kind}"
        );
        let mut unknown = encoded.clone();
        unknown[40] = kind;
        assert_eq!(Anchor::decode(&unknown), Err(DecodeError::Noncanonical));
    }
    assert_eq!(RootKind::try_from(0), Ok(RootKind::Space));
}

/// Each digest is BLAKE2b-256 over its domain and its fields, as
/// `spaces-pallet.md` §3 writes its preimage.
#[test]
fn every_digest_is_its_preimages() {
    let space = space_id(&genesis());
    let venue = VenueId([0x4b; 32]);
    let rep_root = [0x33; 32];
    let s_w = space_root(&space, 0x0102_0304_0506_0708, &rep_root);
    let w = [8, 7, 6, 5, 4, 3, 2, 1];
    assert_eq!(
        s_w,
        blake2b_256(&[&[b"vos/space/v1".as_slice(), &space.0, &w, &rep_root].concat()])
    );
    let anchor = Anchor {
        space,
        window: 0x0102_0304_0506_0708,
        kind: RootKind::Space,
        root: s_w,
        signer: [0; 32],
        signature: [0; 64],
    };
    assert_eq!(
        anchor.digest(&venue),
        blake2b_256(&[&[
            b"vos/anchor/v1".as_slice(),
            &venue.0,
            &space.0,
            &w,
            &[0],
            &s_w
        ]
        .concat()])
    );
    assert_eq!(
        register_digest(&venue, &space, &[0xc0; 32]),
        blake2b_256(&[&[
            b"vos/space/register".as_slice(),
            &venue.0,
            &space.0,
            &[0xc0; 32]
        ]
        .concat()])
    );
    assert_eq!(
        VenueId::jam(&[0x7a; 32], 0x0a0b_0c0d).0,
        blake2b_256(&[&[
            b"vos/venue/jam".as_slice(),
            &[0x7a; 32],
            &[0x0d, 0x0c, 0x0b, 0x0a]
        ]
        .concat()])
    );
}

/// Each input of a digest moves it.
#[test]
fn every_field_is_bound() {
    let base = genesis();
    type Change = fn(&mut SpaceGenesis);
    let changes: [(&str, Change); 7] = [
        ("a node's number", |g| g.nodes[1].0 = 3),
        ("a node's key", |g| g.nodes[0].1[31] ^= 1),
        ("the nodes' order", |g| g.nodes.swap(0, 1)),
        ("the origin", |g| g.clock.origin_ms += 1),
        ("the length", |g| g.clock.length_ms += 1),
        ("the time", |g| g.time += 1),
        ("the nonce", |g| g.nonce[15] ^= 1),
    ];
    for (name, change) in changes {
        let mut changed = base.clone();
        change(&mut changed);
        assert_ne!(space_id(&changed), space_id(&base), "{name}");
    }

    let space = space_id(&base);
    let (venue, other_venue) = (VenueId([1; 32]), VenueId([2; 32]));
    let other_space = SpaceId([3; 32]);
    let root = space_root(&space, 9, &[4; 32]);
    assert_ne!(root, space_root(&other_space, 9, &[4; 32]));
    assert_ne!(root, space_root(&space, 10, &[4; 32]));
    assert_ne!(root, space_root(&space, 9, &[5; 32]));
    let anchor = anchor_digest(&venue, &space, 9, RootKind::Space, &root);
    assert_ne!(
        anchor,
        anchor_digest(&other_venue, &space, 9, RootKind::Space, &root)
    );
    assert_ne!(
        anchor,
        anchor_digest(&venue, &other_space, 9, RootKind::Space, &root)
    );
    assert_ne!(
        anchor,
        anchor_digest(&venue, &space, 10, RootKind::Space, &root)
    );
    assert_ne!(
        anchor,
        anchor_digest(&venue, &space, 9, RootKind::Space, &[0; 32])
    );
    let register = register_digest(&venue, &space, &[6; 32]);
    assert_ne!(register, register_digest(&other_venue, &space, &[6; 32]));
    assert_ne!(register, register_digest(&venue, &other_space, &[6; 32]));
    assert_ne!(register, register_digest(&venue, &space, &[7; 32]));
    assert_ne!(VenueId::jam(&[1; 32], 1), VenueId::jam(&[1; 32], 2));
    assert_ne!(VenueId::jam(&[1; 32], 1), VenueId::jam(&[2; 32], 1));
}

/// No domain is a prefix of another, this crate's or a statement's, so no
/// digest's preimage is another's.
#[test]
fn no_domain_is_a_prefix_of_another() {
    let domains: [&[u8]; 7] = [
        SPACE_ID_DOMAIN,
        SPACE_ROOT_DOMAIN,
        ANCHOR_DOMAIN,
        REGISTER_DOMAIN,
        JAM_VENUE_DOMAIN,
        b"vos/io/v1",
        b"vos/statement/v1",
    ];
    for (i, a) in domains.iter().enumerate() {
        for (j, b) in domains.iter().enumerate() {
            assert!(i == j || !b.starts_with(a), "{i} {j}");
        }
    }
}

/// The golden vectors' digests, each its pinned bytes; each vector's
/// encoding round-trips.
#[cfg(feature = "vectors")]
#[test]
fn the_golden_vectors() {
    for golden in vectors::golden() {
        let bytes = golden.vector.encode();
        assert_eq!(vectors::Vector::decode(&bytes).as_ref(), Ok(&golden.vector));
        assert_eq!(
            vectors::Vector::decode(&bytes[..bytes.len() - 1]),
            Err(DecodeError::Short)
        );
        let digests = golden.vector.digests();
        assert_eq!(hex(&digests.to_bytes()), golden.digests, "{}", golden.name);
        assert!(golden.vector.genesis.clock.registrable(), "{}", golden.name);
    }
}

/// The small-order keys are the eight-torsion subgroup's points, every one
/// of them under either sign bit and the non-canonical encodings of 0 and
/// 1: each refused, as `verify_strict` refuses each key it decodes; and no
/// key of a signing key is.
#[test]
fn the_small_order_keys_are_the_torsion_points() {
    use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
    use curve25519_dalek::traits::Identity;

    let order_8 = CompressedEdwardsY(venue::SMALL_ORDER[2])
        .decompress()
        .expect("a point");
    let mut point = EdwardsPoint::identity();
    for _ in 0..8 {
        assert!(point.is_small_order());
        assert!(venue::small_order(&point.compress().to_bytes()));
        point += order_8;
    }
    assert_eq!(point, EdwardsPoint::identity(), "a point of order 8");
    for encoding in venue::SMALL_ORDER {
        for sign in [0, 0x80] {
            let mut key = encoding;
            key[31] |= sign;
            assert!(venue::small_order(&key));
            if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&key) {
                assert!(key.is_weak(), "{key:?}");
            }
        }
    }
    for seed in 0..=u8::MAX {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        assert!(!venue::small_order(key.as_bytes()), "{seed}");
    }
}

/// Freshness at its edges: a root fresh through `B_w + MaxRootAge`, aged a
/// millisecond after; a window whose expiry overflows neither; a `Seen`
/// entry's expiry its newest root's, never for none.
#[test]
fn freshness_at_its_edges() {
    let clock = genesis().clock;
    let last = clock.boundary(7).unwrap() + MAX_ROOT_AGE_MS;
    assert_eq!(venue::expiry(&clock, 7), Some(last));
    assert!(venue::fresh(&clock, 7, 0));
    assert!(venue::fresh(&clock, 7, last) && !venue::aged(&clock, 7, last));
    assert!(!venue::fresh(&clock, 7, last + 1) && venue::aged(&clock, 7, last + 1));
    assert!(!venue::fresh(&clock, u64::MAX, 0) && !venue::aged(&clock, u64::MAX, u64::MAX));
    assert_eq!(venue::seen_expiry(&clock, [7, 3]), last);
    assert_eq!(venue::seen_expiry(&clock, []), u64::MAX);
    assert_eq!(venue::seen_expiry(&clock, [u64::MAX]), u64::MAX);
}
