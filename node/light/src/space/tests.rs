//! What the personal space's rows keep and how a local actor is installed.

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
        home: Some(home),
        agent: Some((19, [20; 32])),
        source: Some(b"\x01vos.device.1".to_vec()),
        admin: Some(([21; 32], true, true)),
        label: "phone".into(),
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
        kit_calls: vec![KitCall {
            identity: [37; 32],
            message: vec![38; 3],
            signature: [39; 64],
        }],
        onions: Some(Refreshed {
            handle: [40; 32],
            at: 41,
            previous: vec![Onion {
                key: [42; 32],
                ssh_host_key: [43; 32],
            }],
            until: 44,
        }),
    }
}

/// The rows of [`every_field`], each key and its value in hex: a change to
/// what a row keeps, or to how a type it holds encodes, fails here, and is
/// a new layout (`crate::store::LAYOUT`).
const PINNED: &[(&str, &str)] = &[
    (
        "p/home",
        concat!(
            "01010101010101010101010101010101010101010101010101010101010101010102020202020202",
            "02020202020202020202020202020202020202020202020202030000000404040404040404040404",
            "04040404040404040404040404040404040404040405000000060000000100000007070707070707",
            "07070707070707070707070707070707070707070707070707080808080808080808080808080808",
            "08080808080808080808080808080808080113000000141414141414141414141414141414141414",
            "1414141414141414141414141414",
        ),
    ),
    ("p/source", "0d00000001766f732e6465766963652e31"),
    (
        "p/admin",
        "15151515151515151515151515151515151515151515151515151515151515150101",
    ),
    ("p/label", "0500000070686f6e65"),
    (
        "p/next-admin",
        "0100000018181818181818181818181818181818181818181818181818181818181818180001",
    ),
    (
        "p/restoring",
        concat!(
            "000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0f0f0f0f0f0f0f",
            "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
            "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0df700000009090909090909090909090909090909090909",
            "090909090909090909090909090a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a",
            "0a0a0a0a0a0001000b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "0500000070686f6e6501000000011e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e",
            "1e1e1e1e1e1e1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f0200",
            "000020200c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0d0d0d0d",
            "0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d011010101010101010101010",
            "10101010101010101010101010101010101010101001030000001111111212121212121212121212",
            "12121212121212121212121212121212121212121212121212121212121212121212121212121212",
            "12121212121212121212121212",
            "0000000000000000",
        ),
    ),
    (
        "p/acked",
        concat!(
            "1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c1c0000000021000000",
            "22222222222222222222222222222222222222222222222222222222222222222323232323232323",
            "2323232323232323232323232323232323232323232323232400000000000000040000001d1d1d1d",
        ),
    ),
    (
        "p/kit-calls",
        concat!(
            "01000000252525252525252525252525252525252525252525252525252525252525252503000000",
            "26262627272727272727272727272727272727272727272727272727272727272727272727272727",
            "272727272727272727272727272727272727272727272727272727",
        ),
    ),
    (
        "p/onions",
        concat!(
            "28282828282828282828282828282828282828282828282828282828282828282900000000000000",
            "010000002a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2b2b2b2b",
            "2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2c00000000000000",
        ),
    ),
];

fn hexed(rows: &[crate::store::Change]) -> Vec<(String, String)> {
    rows.iter()
        .map(|(key, value)| {
            (
                String::from_utf8_lossy(key).into_owned(),
                value.as_deref().map(hex::encode).unwrap_or_default(),
            )
        })
        .collect()
}

#[test]
fn the_personal_rows_are_pinned_to_the_layout() {
    let rows = hexed(&every_field().rows());
    let pinned: Vec<(String, String)> = PINNED
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    assert_eq!(rows, pinned, "{rows:#?}");
}

/// What the rows keep reads back as it was; a row that does not decode
/// names the personal space in need of repair; a store not made the
/// device's is not ready.
#[test]
fn the_personal_rows_read_back_and_a_bad_one_needs_repair() {
    let directory = tempfile::tempdir().unwrap();
    let store = &crate::Store::open(directory.path(), 1 << 20).unwrap();
    assert!(!rows::ready(store).unwrap());
    let state = every_field();
    store.write_group_rows(state.first_rows()).unwrap();
    assert!(rows::ready(store).unwrap());
    let read = State::read(store).unwrap();
    assert_eq!(hexed(&read.rows()), hexed(&state.rows()));
    store
        .write_group_rows(vec![(b"p/home".to_vec(), Some(vec![1, 2, 3]))])
        .unwrap();
    assert!(matches!(State::read(store), Err(Error::NeedsRepair(_))));
}

/// A local actor upgraded in place to a later release the app carries,
/// never downgraded to an earlier one.
#[test]
fn a_local_actor_is_upgraded_in_place() {
    let directory = tempfile::tempdir().unwrap();
    let artifacts = artifacts();
    let light = Light::open(directory.path(), &artifacts.agent, Config::default()).unwrap();
    assert!(install(&light, &artifacts.books).unwrap());
    assert!(!install(&light, &artifacts.books).unwrap());
    let (instance, package) = &artifacts.books[0];
    let first = crate::release::Package::decode_exact(package).unwrap();
    let next = crate::release::Package {
        release: first.release + 1,
        ..first.clone()
    };
    let books = vec![(*instance, next.encode())];
    assert!(install(&light, &books).unwrap());
    assert_eq!(light.release(*instance).unwrap(), Some(first.release + 1));
    // The upgrade stands: the earlier release is refused under it.
    assert!(matches!(
        light.install(*instance, &first, Vec::new()),
        Err(crate::Error::Release { installed }) if installed == first.release + 1
    ));
    assert!(!install(&light, &artifacts.books).unwrap());
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

/// A host that reaches nothing: a flow refused before its first request.
struct Nowhere;

impl Host for Nowhere {
    fn request(&self, _: &[u8; 32], _: Purpose, _: &[u8]) -> Result<Vec<u8>, String> {
        Err("nowhere".into())
    }

    fn pin(&self, _: &[u8; 32], _: &[Onion]) {}

    fn route(&self, _: &[u8; 32], _: Purpose) -> crate::route::Route {
        crate::route::Route::Onion
    }

    fn prove(&self, _: Proof) -> Result<Vec<u8>, Error> {
        Err(Error::Failed("nowhere".into()))
    }

    fn enrollments(&self) -> Result<Vec<Enrolled>, String> {
        Ok(Vec::new())
    }
}

/// A security key, and nothing else.
struct Key;

impl Prompts for Key {
    fn show_phrase(&self, _: &str, _: &Card) -> bool {
        false
    }
    fn show_card(&self, _: &Card) -> bool {
        false
    }
    fn enter_phrase(&self) -> Option<zeroize::Zeroizing<String>> {
        None
    }
    fn approve_admin(&self, _: &Approval) -> bool {
        false
    }
    fn confirm_pairing(&self, _: &str) -> bool {
        false
    }
    fn show_pairing(&self, _: &str) -> bool {
        false
    }
    fn create_source(&self) -> Result<Vec<u8>, Error> {
        Err(Error::Declined)
    }
    fn evaluate_source(
        &self,
        _: &[u8],
        _: &[u8; 32],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
        Err(Error::Declined)
    }
    fn create_kit_key(&self) -> Result<Vec<u8>, Error> {
        Err(Error::Declined)
    }
    fn kit_secret(&self, _: &[u8], salt: &[u8; 32]) -> Result<zeroize::Zeroizing<[u8; 32]>, Error> {
        Ok(zeroize::Zeroizing::new(*salt))
    }
    fn create_admin(&self) -> Result<AdminKey, Error> {
        Err(Error::Declined)
    }
    fn sign_admin(&self, _: &[u8; 32], _: &[u8]) -> Result<[u8; 64], Error> {
        Err(Error::Declined)
    }
}

/// A restore while a claim waits is refused: the claim holds the home and
/// agent the device keeps, which the restore would write over.
#[test]
fn a_restore_is_refused_while_a_claim_waits() {
    let directory = tempfile::tempdir().unwrap();
    let space = Personal::open(directory.path(), &artifacts(), Nowhere).unwrap();
    let state = every_field();
    let restoring = state.restoring.clone().unwrap();
    let home = state.home.clone().unwrap();
    {
        let held = space.held();
        let (device, _) = <(NewDevice, NewKit)>::decode_exact(&restoring.arguments).unwrap();
        crate::home::Claim::prepare(
            held.light.store(),
            device,
            vec![restoring.next],
            3,
            [4; 32],
            Vec::new(),
        )
        .unwrap();
    }
    let refused = space
        .restore(
            &Key,
            Claim {
                home,
                kit: KitKind::SecurityKey,
                label: "phone".into(),
            },
            KitKind::SecurityKey,
        )
        .unwrap_err();
    assert!(
        matches!(refused, Error::ClaimElsewhere { .. }),
        "{refused:?}"
    );
}

/// The device's store is the newest named: a store is made whole under a
/// partial directory and named once its first batch is written, so a leave
/// cut short (its partial store beside the device's) leaves the device's
/// standing, and is deleted at the next open; a leave named is the
/// device's; a named store its first batch did not mark is refused, kept.
#[test]
fn the_store_is_the_newest_named() {
    let artifacts = artifacts();
    let directory = tempfile::tempdir().unwrap();
    let (generation, light) = store(directory.path(), &artifacts).unwrap();
    assert_eq!(generation, 0);
    assert!(rows::ready(light.store()).unwrap());
    drop(light);
    let cut = partial(directory.path(), 1);
    create_private(&cut).unwrap();
    drop(Light::open(&cut, &artifacts.agent, Config::default()).unwrap());
    let (generation, light) = store(directory.path(), &artifacts).unwrap();
    assert_eq!(generation, 0, "a partial store is no generation");
    drop(light);
    drop_stores(directory.path(), 0);
    assert!(!cut.exists(), "the leave cut short deleted");
    drop(fresh(directory.path(), &artifacts, 1, &State::default()).unwrap());
    assert!(
        fresh(directory.path(), &artifacts, 1, &State::default()).is_err(),
        "a named store is never written over"
    );
    let (generation, light) = store(directory.path(), &artifacts).unwrap();
    assert_eq!(generation, 1, "the leave's store is the device's");
    drop(light);

    let unmarked = tempfile::tempdir().unwrap();
    let named = light_dir(unmarked.path(), 0);
    create_private(&named).unwrap();
    drop(Light::open(&named, &artifacts.agent, Config::default()).unwrap());
    assert!(matches!(
        store(unmarked.path(), &artifacts),
        Err(Error::NeedsRepair(_))
    ));
    assert!(named.exists(), "kept as it is");
}
