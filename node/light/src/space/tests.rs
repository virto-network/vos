//! What the state file keeps and how a local actor is installed.

use super::*;
use vos_wire::personal::{AdminClass, Attestation};

/// A state with each field set, its values fixed.
fn every_field() -> State {
    let home = Kept {
        home: Home {
            space: [1; 32],
            handle: [2; 32],
            agent: 3,
            identity: [4; 32],
            homes: InstanceId(5),
            credentials: InstanceId(6),
        },
        onions: vec![Onion {
            key: [7; 32],
            ssh_host_key: [8; 32],
        }],
    };
    let device = NewDevice {
        sync: [9; 32],
        admin: [10; 32],
        class: AdminClass::Strong,
        attestation: Attestation {
            hardware: true,
            verified_boot: false,
        },
        nullifier: [11; 32],
        label: b"phone".to_vec(),
    };
    let kit = NewKit {
        entries: vec![vos_wire::personal::KitEntry {
            kind: KitKind::SecurityKey,
            signing: [30; 32],
            sealing: [31; 32],
            sealed_r1: vec![32; 2],
        }],
        r2_hash: [12; 32],
        r_hash: [13; 32],
    };
    let next = KitKey {
        kind: KitKind::Phrase,
        signing: [14; 32],
        sealing: [15; 32],
    };
    let mut restoring = Restoring::new(&device, &kit, next, [16; 32]);
    restoring.signed = Some((vec![17; 3], [18; 64]));
    State {
        home: Some(home.clone()),
        agent: Some((19, [20; 32])),
        source: Some(b"\x01vos.device.1".to_vec()),
        admin: Some(([21; 32], true, true)),
        label: "phone".into(),
        bound: Some(Bound {
            home: home.clone(),
            agent: (22, [23; 32]),
        }),
        next_admin: vec![([24; 32], false, true)],
        restoring: Some(restoring),
        acked: Some(Acked {
            handle: [28; 32],
            onions: Vec::new(),
            agent: (33, [34; 32]),
            slot: [35; 32],
            expires: 36,
            ack: vec![29; 4],
        }),
        books: vec![(1, 2), (2, 3)],
        store: 4,
    }
}

/// The bytes of [`every_field`] in [`STATE_VERSION`]: a change to what
/// the file keeps, or to how a type it holds encodes, fails here, and
/// is a new version.
const PINNED: &str = concat!(
    "766f732f70737400030001010101010101010101010101010101010101010101010101010101010101010102",
    "0202020202020202020202020202020202020202020202020202020202020203000000040404040404040404",
    "0404040404040404040404040404040404040404040404050000000600000001000000070707070707070707",
    "0707070707070707070707070707070707070707070707080808080808080808080808080808080808080808",
    "0808080808080808080808011300000014141414141414141414141414141414141414141414141414141414",
    "14141414010d00000001766f732e6465766963652e3101151515151515151515151515151515151515151515",
    "151515151515151515151501010500000070686f6e6501010101010101010101010101010101010101010101",
    "0101010101010101010101020202020202020202020202020202020202020202020202020202020202020203",
    "0000000404040404040404040404040404040404040404040404040404040404040404050000000600000001",
    "0000000707070707070707070707070707070707070707070707070707070707070707080808080808080808",
    "0808080808080808080808080808080808080808080808160000001717171717171717171717171717171717",
    "1717171717171717171717171717170100000018181818181818181818181818181818181818181818181818",
    "18181818181818000101000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f",
    "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0d0d0d0d0d0d0d0d0d0d0d0d0d",
    "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0df7000000090909090909090909090909090909090909090909",
    "09090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a00",
    "01000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0500000070686f6e6501",
    "000000011e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1f1f1f1f1f1f1f1f",
    "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0200000020200c0c0c0c0c0c0c0c0c0c0c0c0c0c",
    "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
    "0d0d0d0d0d0d0110101010101010101010101010101010101010101010101010101010101010100103000000",
    "1111111212121212121212121212121212121212121212121212121212121212121212121212121212121212",
    "1212121212121212121212121212121212121212121212011c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c",
    "1c1c1c1c1c1c1c1c1c1c1c1c0000000021000000222222222222222222222222222222222222222222222222",
    "2222222222222222232323232323232323232323232323232323232323232323232323232323232324000000",
    "00000000040000001d1d1d1d020000000100000002000000020000000300000004000000",
);

#[test]
fn the_state_files_layout_is_pinned_to_its_version() {
    let bytes = state_bytes(&every_field());
    assert_eq!(hex::encode(&bytes), PINNED);
    let read = read_state(&bytes).unwrap();
    assert_eq!(state_bytes(&read), bytes);
}

#[test]
fn a_state_file_of_another_version_or_none_is_refused() {
    let bytes = state_bytes(&every_field());
    let mut later = bytes.clone();
    later[MAGIC.len()..MAGIC.len() + 2].copy_from_slice(&(STATE_VERSION + 1).to_le_bytes());
    assert!(read_state(&later).err().unwrap().contains("version 4"));
    let unversioned = every_field().encode();
    assert!(
        read_state(&unversioned)
            .err()
            .unwrap()
            .contains("no version")
    );
    assert!(read_state(&bytes[..bytes.len() - 1]).is_err());
    assert!(read_state(&bytes[..MAGIC.len() + 1]).is_err());
    assert!(read_state(&[bytes.as_slice(), &[0]].concat()).is_err());
}

/// A local actor upgraded in place to a later release the app carries,
/// never downgraded to an earlier one.
#[test]
fn a_local_actor_is_upgraded_in_place() {
    let directory = tempfile::tempdir().unwrap();
    let artifacts = artifacts();
    let light = Light::open(directory.path(), &artifacts.agent, Config::default()).unwrap();
    let mut kept = Vec::new();
    assert!(install(&light, &artifacts.books, &mut kept).unwrap());
    assert!(!install(&light, &artifacts.books, &mut kept).unwrap());
    let (instance, package) = &artifacts.books[0];
    let first = crate::release::Package::decode_exact(package).unwrap();
    let next = crate::release::Package {
        release: first.release + 1,
        ..first.clone()
    };
    let books = vec![(*instance, next.encode())];
    assert!(install(&light, &books, &mut kept).unwrap());
    assert!(kept.contains(&(instance.0, first.release + 1)));
    // The upgrade stands: the earlier release is refused under it.
    assert!(matches!(
        light.install(*instance, &first, Vec::new()),
        Err(crate::Error::Release { installed }) if installed == first.release + 1
    ));
    assert!(!install(&light, &artifacts.books, &mut kept).unwrap());
    // A record lost: the installed release is learnt from the refusal.
    let mut lost = Vec::new();
    assert!(install(&light, &artifacts.books, &mut lost).unwrap());
    assert!(lost.contains(&(instance.0, first.release + 1)));
}

/// The light node's artifacts from this tree's guests: the default agent
/// and the two books' packages.
fn artifacts() -> Artifacts {
    use vos_testkit::programs::program_elf;
    let read = |name| std::fs::read(program_elf(name)).unwrap();
    let package = |name| crate::release::package(&read(name), 1).unwrap().encode();
    Artifacts {
        agent: crate::release::agent(&read("vos-agent")).unwrap(),
        books: vec![
            (CREDENTIAL_BOOK, package("vos-credential-book")),
            (DEVICE_BOOK, package("vos-device-book")),
        ],
    }
}
