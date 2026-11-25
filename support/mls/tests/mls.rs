//! `vos-mls` over a fjall store: a group of three made and moved through
//! commits held and confirmed on copies; a copy leaving the current state
//! as it was; a held commit across a reopen, matched by its handshake and
//! deleted on a void; the device group's policy refusing what it does not
//! allow, from a member running other rules; a removed member; a leaf's
//! credential renewed; a restart into a new group; Welcomes of another
//! suite, of an over-long key-package reference or group id, and rows the
//! store cannot hold, refused without a write; stale candidates refused;
//! a key package from a clock ahead; and the limit of a key package's
//! year.

use std::collections::BTreeMap;

use mls_rs::client_builder::PaddingMode;
use mls_rs::group::{GroupContext, Roster};
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle,
};
use mls_rs::{Client, ExtensionList, MlsRules};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use vos_mls::{Error, Expected, Identity, Kind, Mls, Namespace, Refusal, Store, confirmation};

const T: u64 = 1_800_000_000;

struct Member {
    mls: Mls,
    namespace: Namespace,
    store: Store,
    keyspace: fjall::Keyspace,
    _dir: tempfile::TempDir,
}

fn credential(n: u8) -> Vec<u8> {
    let mut credential = vec![n; 64];
    credential[63] = 0xa5;
    credential
}

/// An empty store in a temporary directory, and its keyspace.
fn store() -> (tempfile::TempDir, fjall::Keyspace, Store) {
    let dir = tempfile::tempdir().unwrap();
    let db = fjall::Database::builder(dir.path()).open().unwrap();
    let keyspace = db
        .keyspace("group", fjall::KeyspaceCreateOptions::default)
        .unwrap();
    (dir, keyspace.clone(), Store::new(db, keyspace))
}

fn member(n: u8) -> Member {
    let (dir, keyspace, store) = store();
    let namespace = Namespace::current(store.clone(), b"mls/".to_vec());
    let mls = Mls::open(namespace.clone(), &credential(n)).unwrap();
    Member {
        mls,
        namespace,
        store,
        keyspace,
        _dir: dir,
    }
}

/// Row `key` of `member`'s store as committed, read through a namespace
/// of no prefix.
fn committed(member: &Member, key: &[u8]) -> Option<Vec<u8>> {
    Namespace::current(member.store.clone(), Vec::new())
        .get(key)
        .unwrap()
}

fn reopen(member: &Member, n: u8) -> Mls {
    Mls::open(member.namespace.clone(), &credential(n)).unwrap()
}

fn expected(committer: u8, adds: &[u8], removes: &[u8]) -> Expected {
    Expected {
        committer: credential(committer),
        adds: adds.iter().map(|n| credential(*n)).collect(),
        removes: removes.iter().map(|n| credential(*n)).collect(),
        renewed: None,
    }
}

/// A, B and C at epoch 1: A made the group and added B and C in one
/// commit, held until each had it on a copy.
fn three() -> (Member, Member, Member) {
    let mut a = member(1);
    let mut b = member(2);
    let mut c = member(3);
    a.mls.create(T, BTreeMap::new()).unwrap();
    let packages = [b.mls.key_package(T).unwrap(), c.mls.key_package(T).unwrap()];
    let commit = a
        .mls
        .commit(&packages, &[], T, |_| BTreeMap::new())
        .unwrap();
    assert_eq!(commit.epoch, 1);
    let welcome = commit.welcome.clone().expect("a Welcome for the adds");
    let joined_b = b.mls.join(&welcome, T).unwrap();
    let joined_c = c.mls.join(&welcome, T).unwrap();
    let own = a.mls.own(&commit.handshake).unwrap();
    assert_eq!(own.kind(), Kind::Own);
    assert_eq!(joined_b.kind(), Kind::Joined);
    let authenticator = own.authenticator().unwrap();
    assert_eq!(authenticator, joined_b.authenticator().unwrap());
    assert_eq!(authenticator, joined_c.authenticator().unwrap());
    a.mls.swap(own, BTreeMap::new()).unwrap();
    b.mls.swap(joined_b, BTreeMap::new()).unwrap();
    c.mls.swap(joined_c, BTreeMap::new()).unwrap();
    (a, b, c)
}

/// Every member's current epoch and its exporter's key, the same.
fn agree(members: &[&Member], epoch: u64) {
    let key = members[0].mls.export(b"vos/test", b"scope", 32).unwrap();
    for member in members {
        assert_eq!(member.mls.epoch().unwrap(), epoch);
        assert_eq!(member.mls.export(b"vos/test", b"scope", 32).unwrap(), key);
    }
}

/// A group made, added to, updated and removed from, each commit held by
/// its committer and processed on copies by the others, swapped in only
/// as a whole: every member's epoch and exported keys agree after each,
/// and the removed member keeps no group.
#[test]
fn commits_move_every_member_only_when_swapped() {
    let (mut a, mut b, mut c) = three();
    agree(&[&a, &b, &c], 1);
    assert!(
        a.mls.held().unwrap().is_none(),
        "the swap deleted the held commit"
    );

    let update = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    assert!(update.welcome.is_none());
    let on_a = a
        .mls
        .process(&update.handshake, T + 1, expected(2, &[], &[]))
        .unwrap();
    let on_c = c
        .mls
        .process(&update.handshake, T + 1, expected(2, &[], &[]))
        .unwrap();
    let own = b.mls.own(&update.handshake).unwrap();
    assert_eq!(on_a.epoch(), 2);
    agree(&[&a, &b, &c], 1);
    a.mls.swap(on_a, BTreeMap::new()).unwrap();
    c.mls.swap(on_c, BTreeMap::new()).unwrap();
    b.mls.swap(own, BTreeMap::new()).unwrap();
    agree(&[&a, &b, &c], 2);

    let removal = a
        .mls
        .commit(&[], &[credential(3)], T + 2, |_| BTreeMap::new())
        .unwrap();
    let on_b = b
        .mls
        .process(&removal.handshake, T + 2, expected(1, &[], &[3]))
        .unwrap();
    let on_c = c
        .mls
        .process(&removal.handshake, T + 2, expected(1, &[], &[3]))
        .unwrap();
    assert_eq!(on_c.kind(), Kind::Removed);
    assert_eq!(on_c.authenticator().unwrap(), None);
    b.mls.swap(on_b, BTreeMap::new()).unwrap();
    let own = a.mls.own(&removal.handshake).unwrap();
    a.mls.swap(own, BTreeMap::new()).unwrap();
    c.mls.swap(on_c, BTreeMap::new()).unwrap();
    assert!(!c.mls.grouped(), "the removed member keeps no group");
    agree(&[&a, &b], 3);
    assert_eq!(a.mls.credentials().unwrap().len(), 2);
}

/// A candidate processed on a copy leaves the current state's rows and
/// epoch as they were, and dropping it leaves a rival candidate for the
/// same epoch processable; processed in place, as mls-rs would, it would
/// not be.
#[test]
fn a_copy_never_writes_the_current_state() {
    let (a, mut b, mut c) = three();
    let before = rows(&a).len();
    let state = a.mls.state_bytes().unwrap();
    let rival = c.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    let update = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    let on_copy = a
        .mls
        .process(&rival.handshake, T + 1, expected(3, &[], &[]))
        .unwrap();
    assert_eq!(on_copy.epoch(), 2);
    drop(on_copy);
    assert_eq!(a.mls.epoch().unwrap(), 1);
    assert_eq!(a.mls.state_bytes().unwrap(), state);
    assert_eq!(rows(&a).len(), before);
    let reopened = reopen(&a, 1);
    assert_eq!(reopened.epoch().unwrap(), 1);
    let next = a
        .mls
        .process(&update.handshake, T + 1, expected(2, &[], &[]))
        .unwrap();
    assert_eq!(next.epoch(), 2);
    c.mls.void(BTreeMap::new()).unwrap();
    assert!(c.mls.held().unwrap().is_none());
    b.mls.void(BTreeMap::new()).unwrap();
}

/// A held commit is written with the state whose handshake generation it
/// spent, so it survives a reopen; it applies only for its own handshake
/// and the epoch after the current one, a second commit waits for it, and
/// a void deletes it.
#[test]
fn a_held_commit_survives_a_reopen_and_matches_only_its_handshake() {
    let (mut a, mut b, _c) = three();
    let mut rows = BTreeMap::new();
    rows.insert(b"caller/record".to_vec(), Some(b"commit 2".to_vec()));
    let commit = a.mls.commit(&[], &[], T + 1, |_| rows).unwrap();
    assert!(matches!(
        a.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()),
        Err(Error::Held)
    ));
    assert_eq!(
        committed(&a, b"caller/record").as_deref(),
        Some(&b"commit 2"[..]),
        "the caller's rows are the held commit's batch"
    );
    let mut reopened = reopen(&a, 1);
    assert_eq!(reopened.held().unwrap(), Some(2), "held across the reopen");
    let other = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    assert!(matches!(
        reopened.own(&other.handshake),
        Err(Error::NotHeld)
    ));
    let own = reopened.own(&commit.handshake).unwrap();
    let on_b = b
        .mls
        .process(&commit.handshake, T + 1, expected(1, &[], &[]))
        .unwrap();
    assert_eq!(own.authenticator().unwrap(), on_b.authenticator().unwrap());
    drop(own);
    reopened.void(BTreeMap::new()).unwrap();
    assert!(reopened.held().unwrap().is_none());
    assert!(matches!(
        reopened.own(&commit.handshake),
        Err(Error::NotHeld)
    ));
    assert_eq!(reopened.epoch().unwrap(), 1);
}

/// The logged effect binds a candidate: a commit whose committer, adds or
/// removals are not the expected ones is refused.
#[test]
fn a_candidate_is_its_logged_effect_exactly() {
    let (a, mut b, _c) = three();
    let update = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    for wrong in [
        expected(3, &[], &[]),
        expected(2, &[], &[3]),
        expected(2, &[4], &[]),
    ] {
        let refused = a.mls.process(&update.handshake, T + 1, wrong);
        assert!(matches!(refused, Err(Error::Refused(Refusal::Rejected(_)))));
    }
    b.mls.void(BTreeMap::new()).unwrap();
    let removal = b
        .mls
        .commit(&[], &[credential(3)], T + 1, |_| BTreeMap::new())
        .unwrap();
    let refused = a
        .mls
        .process(&removal.handshake, T + 1, expected(2, &[], &[]));
    assert!(matches!(refused, Err(Error::Refused(Refusal::Rejected(_)))));
    a.mls
        .process(&removal.handshake, T + 1, expected(2, &[], &[3]))
        .unwrap();
    assert!(matches!(
        a.mls.process(b"not mls", T + 1, expected(2, &[], &[])),
        Err(Error::Refused(Refusal::Malformed))
    ));
}

/// Rules a member running other code commits under.
#[derive(Clone, Copy)]
struct Loose {
    path: bool,
    encrypt: bool,
}

impl MlsRules for Loose {
    type Error = std::convert::Infallible;

    fn filter_proposals(
        &self,
        _: CommitDirection,
        _: CommitSource,
        _: &Roster,
        _: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, Self::Error> {
        Ok(proposals)
    }

    fn commit_options(
        &self,
        _: &Roster,
        _: &GroupContext,
        _: &ProposalBundle,
    ) -> Result<CommitOptions, Self::Error> {
        Ok(CommitOptions::new()
            .with_path_required(self.path)
            .with_ratchet_tree_extension(true))
    }

    fn encryption_options(
        &self,
        _: &Roster,
        _: &GroupContext,
    ) -> Result<EncryptionOptions, Self::Error> {
        Ok(EncryptionOptions::new(self.encrypt, PaddingMode::None))
    }
}

/// `member`'s group, as a client running `rules` loads it: over a copy of
/// its namespace, so the member's own state stays as it was.
fn loose(
    member: &Member,
    rules: Loose,
) -> mls_rs::Group<impl mls_rs::client_builder::MlsConfig + use<>> {
    let namespace = member.namespace.copy();
    let id = namespace.get(b"group").unwrap().unwrap();
    let client = Client::builder()
        .group_state_storage(namespace.clone())
        .key_package_repo(namespace)
        .identity_provider(Identity::default())
        .crypto_provider(RustCryptoProvider::default())
        .mls_rules(rules)
        .build();
    client.load_group(&id).unwrap()
}

/// What the device group does not allow is refused when received: a
/// group-context change, a handshake in the clear, an add without a path;
/// and a commit is built of key packages and members alone.
#[test]
fn the_policy_refuses_what_the_device_group_does_not_allow() {
    let (a, mut b, _c) = three();
    let mut group = loose(
        &b,
        Loose {
            path: true,
            encrypt: true,
        },
    );
    let context = group
        .commit_builder()
        .set_group_context_ext(ExtensionList::new())
        .unwrap()
        .build()
        .unwrap();
    let bytes = context.commit_message.to_bytes().unwrap();
    assert!(matches!(
        a.mls.process(&bytes, T + 1, expected(2, &[], &[])),
        Err(Error::Refused(Refusal::Rejected(_)))
    ));

    let mut group = loose(
        &b,
        Loose {
            path: true,
            encrypt: false,
        },
    );
    let clear = group.commit_builder().build().unwrap();
    let bytes = clear.commit_message.to_bytes().unwrap();
    assert!(matches!(
        a.mls.process(&bytes, T + 1, expected(2, &[], &[])),
        Err(Error::Refused(Refusal::Plaintext))
    ));

    let mut d = member(4);
    let package = d.mls.key_package(T).unwrap();
    let mut group = loose(
        &b,
        Loose {
            path: false,
            encrypt: true,
        },
    );
    let pathless = group
        .commit_builder()
        .add_member(mls_rs::MlsMessage::from_bytes(&package).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let bytes = pathless.commit_message.to_bytes().unwrap();
    assert!(matches!(
        a.mls.process(&bytes, T + 1, expected(2, &[4], &[])),
        Err(Error::Refused(Refusal::NoPath))
    ));

    assert!(matches!(
        b.mls.commit(
            &[b"no key package".to_vec()],
            &[],
            T + 1,
            |_| BTreeMap::new()
        ),
        Err(Error::Mls(_))
    ));
}

/// The confirmation hash is over its domain, the agent, the epoch and the
/// authenticator, each of which moves it.
#[test]
fn the_confirmation_hash_binds_its_parts() {
    let h = confirmation(b"vos/personal/confirm", &[1; 32], 7, &[9; 32]);
    assert_eq!(
        h,
        confirmation(b"vos/personal/confirm", &[1; 32], 7, &[9; 32])
    );
    assert_ne!(
        h,
        confirmation(b"vos/personal/other", &[1; 32], 7, &[9; 32])
    );
    assert_ne!(
        h,
        confirmation(b"vos/personal/confirm", &[2; 32], 7, &[9; 32])
    );
    assert_ne!(
        h,
        confirmation(b"vos/personal/confirm", &[1; 32], 8, &[9; 32])
    );
    assert_ne!(
        h,
        confirmation(b"vos/personal/confirm", &[1; 32], 7, &[8; 32])
    );
}

/// A restart: A starts a new group of itself alone, its commit held and
/// the old group kept until the swap, which deletes the group it leaves;
/// B and C, left out, are given no Welcome and cannot follow. A void
/// deletes a held restart's new group.
#[test]
fn a_restart_starts_a_new_group_and_leaves_the_old() {
    let (mut a, b, c) = three();
    let old = rows(&a).len();
    let void = a.mls.restart(T + 1, |_| BTreeMap::new()).unwrap();
    assert!(a.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).is_err());
    assert_eq!(a.mls.own(&void.handshake).unwrap().kind(), Kind::Started);
    a.mls.void(BTreeMap::new()).unwrap();
    assert_eq!(rows(&a).len(), old);
    agree(&[&a, &b, &c], 1);

    let restart = a.mls.restart(T + 2, |_| BTreeMap::new()).unwrap();
    assert_eq!(restart.epoch, 1);
    assert!(restart.welcome.is_none(), "no Welcome: it is alone");
    agree(&[&a, &b, &c], 1);
    a.mls = reopen(&a, 1);
    let own = a.mls.own(&restart.handshake).unwrap();
    assert_eq!(own.kind(), Kind::Started);
    a.mls.swap(own, BTreeMap::new()).unwrap();
    assert_eq!(a.mls.credentials().unwrap().len(), 1);
    assert_eq!(
        count(&a, b"mls/state/"),
        1,
        "the old group's state is deleted"
    );
}

/// A leaf's credential renewed by its own commit: received only under an
/// expected renewal to that credential, refused otherwise; held across a
/// void, which keeps the old one, and the member's from the swap, its next
/// commit by the new credential; and kept across a reopen.
#[test]
fn a_leafs_credential_is_renewed_only_as_expected() {
    let (mut a, mut b, mut c) = three();
    let renewed = credential(0x22);
    let void = b
        .mls
        .renew(&renewed, &[], &[], T + 1, |_| BTreeMap::new())
        .unwrap();
    assert!(matches!(
        a.mls.process(&void.handshake, T + 1, expected(2, &[], &[])),
        Err(Error::Refused(_))
    ));
    b.mls.void(BTreeMap::new()).unwrap();
    assert_eq!(
        b.mls.credential(),
        credential(2),
        "a void keeps the old one"
    );

    let update = b
        .mls
        .renew(&renewed, &[], &[], T + 1, |_| BTreeMap::new())
        .unwrap();
    let expecting = Expected {
        renewed: Some(renewed.clone()),
        ..expected(2, &[], &[])
    };
    let elsewhere = Expected {
        renewed: Some(credential(0x23)),
        ..expected(2, &[], &[])
    };
    assert!(matches!(
        a.mls.process(&update.handshake, T + 1, elsewhere),
        Err(Error::Refused(_))
    ));
    let on_a = a
        .mls
        .process(&update.handshake, T + 1, expecting.clone())
        .unwrap();
    let on_c = c.mls.process(&update.handshake, T + 1, expecting).unwrap();
    assert!(on_a.credentials().contains(&renewed));
    let own = b.mls.own(&update.handshake).unwrap();
    a.mls.swap(on_a, BTreeMap::new()).unwrap();
    c.mls.swap(on_c, BTreeMap::new()).unwrap();
    b.mls.swap(own, BTreeMap::new()).unwrap();
    agree(&[&a, &b, &c], 2);
    assert_eq!(b.mls.credential(), renewed);
    assert_eq!(reopen(&b, 2).credential(), renewed, "kept across a reopen");

    let next = b.mls.commit(&[], &[], T + 2, |_| BTreeMap::new()).unwrap();
    let by_new = Expected {
        committer: renewed.clone(),
        ..Expected::default()
    };
    let on_a = a.mls.process(&next.handshake, T + 2, by_new).unwrap();
    a.mls.swap(on_a, BTreeMap::new()).unwrap();
    let own = b.mls.own(&next.handshake).unwrap();
    b.mls.swap(own, BTreeMap::new()).unwrap();
    agree(&[&a, &b], 3);
}

/// MLS varint (RFC 9420 §2.1.2).
fn varint(out: &mut Vec<u8>, n: usize) {
    if n < 1 << 6 {
        out.push(n as u8);
    } else if n < 1 << 14 {
        out.extend_from_slice(&(0x4000u16 | n as u16).to_be_bytes());
    } else {
        out.extend_from_slice(&(0x8000_0000u32 | n as u32).to_be_bytes());
    }
}

/// A suite-1 Welcome of one encrypted secret for the key package
/// `reference`, its KEM output, ciphertext and group info empty.
fn welcome_for(reference: &[u8]) -> Vec<u8> {
    let mut secret = Vec::new();
    varint(&mut secret, reference.len());
    secret.extend_from_slice(reference);
    varint(&mut secret, 0);
    varint(&mut secret, 0);
    let mut welcome = vec![0, 1, 0, 3, 0, 1];
    varint(&mut welcome, secret.len());
    welcome.extend_from_slice(&secret);
    varint(&mut welcome, 0);
    welcome
}

/// The rows of `member`'s store, keys and values.
fn rows(member: &Member) -> Vec<(Vec<u8>, Vec<u8>)> {
    member
        .keyspace
        .iter()
        .map(|row| {
            let (key, value) = row.into_inner().unwrap();
            (key.to_vec(), value.to_vec())
        })
        .collect()
}

/// How many of `member`'s rows start with `prefix`.
fn count(member: &Member, prefix: &[u8]) -> usize {
    rows(member)
        .iter()
        .filter(|(key, _)| key.starts_with(prefix))
        .count()
}

/// A Welcome naming a key package by a reference of any length is
/// refused, and refused again after a reopen, writing nothing.
#[test]
fn a_welcome_naming_an_overlong_key_package_is_refused() {
    use mls_rs::error::MlsError;
    let member = member(2);
    let before = rows(&member);
    for length in [60_000, 70_000] {
        let welcome = welcome_for(&vec![0x41; length]);
        assert!(matches!(
            member.mls.join(&welcome, T),
            Err(Error::Refused(Refusal::Rejected(
                MlsError::WelcomeKeyPackageNotFound
            )))
        ));
        assert!(matches!(
            reopen(&member, 2).join(&welcome, T),
            Err(Error::Refused(Refusal::Rejected(
                MlsError::WelcomeKeyPackageNotFound
            )))
        ));
    }
    assert_eq!(rows(&member), before);
}

/// A Welcome into a group whose id is longer than the suite's hash is
/// refused before its state is staged.
#[test]
fn a_welcome_into_a_group_with_an_overlong_id_is_refused() {
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::BasicCredential;
    use mls_rs::time::MlsTime;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    let suite = RustCryptoProvider::default()
        .cipher_suite_provider(vos_mls::SUITE)
        .unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    let identity = SigningIdentity::new(
        BasicCredential::new(credential(1)).into_credential(),
        public,
    );
    let creator = Client::builder()
        .identity_provider(Identity::default())
        .crypto_provider(RustCryptoProvider::default())
        .mls_rules(Loose {
            path: true,
            encrypt: true,
        })
        .signing_identity(identity, secret, vos_mls::SUITE)
        .build();
    let mut group = creator
        .create_group_with_id(
            vec![0x47; 70_000],
            ExtensionList::new(),
            ExtensionList::new(),
            Some(MlsTime::from(T)),
        )
        .unwrap();
    let mut b = member(2);
    let package = b.mls.key_package(T).unwrap();
    let commit = group
        .commit_builder()
        .commit_time(MlsTime::from(T))
        .add_member(mls_rs::MlsMessage::from_bytes(&package).unwrap())
        .unwrap()
        .build()
        .unwrap();
    let welcome = commit.welcome_messages[0].to_bytes().unwrap();
    let before = rows(&b);
    assert!(matches!(
        b.mls.join(&welcome, T),
        Err(Error::Refused(Refusal::Group))
    ));
    assert_eq!(rows(&b), before);
}

/// A row the store cannot hold (an empty key, a key over 65,535 bytes)
/// is an error, its batch written as none, and no read of one fails.
#[test]
fn a_row_the_store_cannot_hold_is_an_error() {
    let (mut a, _b, _c) = three();
    let before = rows(&a);
    for key in [Vec::new(), vec![0x6b; 70_000]] {
        let mut bad = BTreeMap::new();
        bad.insert(b"caller/fine".to_vec(), Some(b"row".to_vec()));
        bad.insert(key.clone(), Some(b"row".to_vec()));
        assert!(matches!(a.mls.write(bad), Err(Error::Unstorable)));
        assert_eq!(rows(&a), before);
        assert_eq!(committed(&a, &key), None);
    }
    assert_eq!(a.namespace.get(&[0x6b; 70_000]).unwrap(), None);
    let mut bad = BTreeMap::new();
    bad.insert(vec![0x6b; 70_000], None);
    assert!(matches!(
        a.mls.commit(&[], &[], T + 1, |_| bad),
        Err(Error::Unstorable)
    ));
    assert!(a.mls.held().unwrap().is_none());
    a.mls.write(BTreeMap::new()).unwrap();
    assert!(a.mls.held().unwrap().is_none(), "nothing staged is left");
    assert_eq!(reopen(&a, 1).epoch().unwrap(), 1);
    a.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
}

/// A Welcome naming another suite is unsupported: no key of this member
/// is used under it.
#[test]
fn a_welcome_of_another_suite_is_unsupported() {
    use mls_rs::error::MlsError;
    let mut a = member(1);
    let mut d = member(4);
    a.mls.create(T, BTreeMap::new()).unwrap();
    let package = d.mls.key_package(T).unwrap();
    let commit = a
        .mls
        .commit(&[package], &[], T, |_| BTreeMap::new())
        .unwrap();
    let mut welcome = commit.welcome.unwrap();
    // MLSMessage: version (2 bytes), wire format (2), then the suite (2).
    assert_eq!(welcome[2..6], [0, 3, 0, 1], "a Welcome of suite 1");
    for suite in [2u8, 3, 7] {
        welcome[5] = suite;
        match d.mls.join(&welcome, T) {
            Err(Error::Refused(Refusal::Rejected(MlsError::UnsupportedCipherSuite(_)))) => {}
            other => panic!("suite {suite}: {:?}", other.map(|c| c.kind())),
        }
    }
}

/// A key package names the one suite its member runs.
#[test]
fn a_key_package_names_one_suite() {
    let mut b = member(2);
    let package = b.mls.key_package(T).unwrap();
    let package = mls_rs::MlsMessage::from_bytes(&package)
        .unwrap()
        .into_key_package()
        .unwrap();
    let leaf = format!("{package:?}");
    assert!(leaf.contains("cipher_suites: [CipherSuite(1)]"), "{leaf}");
}

/// A key package made by a device whose clock is ahead of the others'
/// (within the margin) is added, processed and joined with.
#[test]
fn a_key_package_from_a_clock_ahead_is_added() {
    let (mut a, b, _c) = three();
    let mut d = member(4);
    let package = d.mls.key_package(T + 120).unwrap();
    let commit = a
        .mls
        .commit(&[package], &[], T + 1, |_| BTreeMap::new())
        .unwrap();
    b.mls
        .process(&commit.handshake, T + 1, expected(1, &[4], &[]))
        .unwrap();
    d.mls.join(&commit.welcome.unwrap(), T + 1).unwrap();
}

/// The limit of a key package's year: a member added over a year ago that
/// has not committed since keeps a leaf a joiner refuses, until its own
/// commit gives it a leaf of its own.
#[test]
fn a_leaf_past_its_key_packages_year_bars_a_join_until_it_commits() {
    use mls_rs::error::MlsError;
    let (mut a, mut b, mut c) = three();
    let later = T + 400 * 24 * 3600;
    let mut d = member(4);
    let package = d.mls.key_package(later).unwrap();
    let commit = a
        .mls
        .commit(&[package], &[], later, |_| BTreeMap::new())
        .unwrap();
    assert!(matches!(
        d.mls.join(&commit.welcome.unwrap(), later),
        Err(Error::Refused(Refusal::Rejected(
            MlsError::InvalidLifetime { .. }
        )))
    ));
    a.mls.void(BTreeMap::new()).unwrap();
    update(&mut b, 2, &mut [&mut a, &mut c], later);
    update(&mut c, 3, &mut [&mut a, &mut b], later);
    let package = d.mls.key_package(later).unwrap();
    let commit = a
        .mls
        .commit(&[package], &[], later, |_| BTreeMap::new())
        .unwrap();
    d.mls.join(&commit.welcome.unwrap(), later).unwrap();
}

/// `committer`'s update at `time`, processed and swapped in by `others`
/// and by itself.
fn update(committer: &mut Member, n: u8, others: &mut [&mut Member], time: u64) {
    let update = committer
        .mls
        .commit(&[], &[], time, |_| BTreeMap::new())
        .unwrap();
    for other in others {
        let on = other
            .mls
            .process(&update.handshake, time, expected(n, &[], &[]))
            .unwrap();
        other.mls.swap(on, BTreeMap::new()).unwrap();
    }
    let own = committer.mls.own(&update.handshake).unwrap();
    committer.mls.swap(own, BTreeMap::new()).unwrap();
}

/// An expected renewal is required, not only allowed.
#[test]
fn an_expected_renewal_is_required() {
    let (a, mut b, _c) = three();
    let update = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    let expecting = Expected {
        renewed: Some(credential(0x22)),
        ..expected(2, &[], &[])
    };
    assert!(matches!(
        a.mls.process(&update.handshake, T + 1, expecting),
        Err(Error::Refused(Refusal::Leaf))
    ));
}

/// A committer keeps its leaf's signature key.
#[test]
fn a_committer_keeps_its_signature_key() {
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::BasicCredential;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};
    let (a, b, _c) = three();
    let mut group = loose(
        &b,
        Loose {
            path: true,
            encrypt: true,
        },
    );
    let suite = RustCryptoProvider::default()
        .cipher_suite_provider(vos_mls::SUITE)
        .unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    let identity = SigningIdentity::new(
        BasicCredential::new(credential(2)).into_credential(),
        public,
    );
    let rotated = group
        .commit_builder()
        .set_new_signing_identity(secret, identity)
        .build()
        .unwrap();
    let bytes = rotated.commit_message.to_bytes().unwrap();
    assert!(matches!(
        a.mls.process(&bytes, T + 1, expected(2, &[], &[])),
        Err(Error::Refused(Refusal::Leaf))
    ));
}

/// A rival swapped in over a held restart deletes the restart's new
/// group.
#[test]
fn a_held_restarts_group_goes_when_a_rival_is_swapped_in() {
    let (mut a, mut b, _c) = three();
    a.mls.restart(T + 1, |_| BTreeMap::new()).unwrap();
    assert_eq!(count(&a, b"mls/state/"), 2);
    let update = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    let on_a = a
        .mls
        .process(&update.handshake, T + 1, expected(2, &[], &[]))
        .unwrap();
    a.mls.swap(on_a, BTreeMap::new()).unwrap();
    assert!(a.mls.held().unwrap().is_none());
    assert_eq!(count(&a, b"mls/state/"), 1);
}

/// A candidate of the group a restart left is not swapped over the new
/// one.
#[test]
fn a_candidate_of_the_group_left_is_not_swapped_in() {
    let (mut a, mut b, _c) = three();
    let update = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    let stale = a
        .mls
        .process(&update.handshake, T + 1, expected(2, &[], &[]))
        .unwrap();
    let restart = a.mls.restart(T + 2, |_| BTreeMap::new()).unwrap();
    let own = a.mls.own(&restart.handshake).unwrap();
    a.mls.swap(own, BTreeMap::new()).unwrap();
    assert_eq!(a.mls.epoch().unwrap(), 1);
    assert!(matches!(
        a.mls.swap(stale, BTreeMap::new()),
        Err(Error::Stale)
    ));
    assert_eq!(a.mls.credentials().unwrap().len(), 1);
}

/// A device's own candidate kept across a void is not swapped in over the
/// commit held after it.
#[test]
fn an_own_candidate_kept_across_a_void_is_not_swapped_in() {
    let (_a, mut b, _c) = three();
    let first = b.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).unwrap();
    let kept = b.mls.own(&first.handshake).unwrap();
    b.mls.void(BTreeMap::new()).unwrap();
    b.mls
        .renew(&credential(0x22), &[], &[], T + 1, |_| BTreeMap::new())
        .unwrap();
    assert!(matches!(
        b.mls.swap(kept, BTreeMap::new()),
        Err(Error::Stale)
    ));
    assert_eq!(b.mls.credential(), credential(2));
    assert_eq!(b.mls.epoch().unwrap(), 1);
}

/// A key package's row that does not decode is a corrupt store, not a
/// Welcome for a key package this member never made.
#[test]
fn a_key_package_row_that_does_not_read_is_corrupt() {
    let mut a = member(1);
    let mut d = member(4);
    a.mls.create(T, BTreeMap::new()).unwrap();
    let package = d.mls.key_package(T).unwrap();
    let commit = a
        .mls
        .commit(&[package], &[], T, |_| BTreeMap::new())
        .unwrap();
    let (key, _) = rows(&d)
        .into_iter()
        .find(|(key, _)| key.starts_with(b"mls/package/"))
        .unwrap();
    let mut garbled = BTreeMap::new();
    garbled.insert(key, Some(b"not a key package".to_vec()));
    d.mls.write(garbled).unwrap();
    assert!(matches!(
        d.mls.join(&commit.welcome.unwrap(), T),
        Err(Error::Corrupt)
    ));
}

/// The key packages a device made and did not join with go when it joins.
#[test]
fn unused_key_packages_go_when_the_device_joins() {
    let mut a = member(1);
    let mut d = member(4);
    a.mls.create(T, BTreeMap::new()).unwrap();
    d.mls.key_package(T).unwrap();
    let package = d.mls.key_package(T).unwrap();
    assert_eq!(count(&d, b"mls/package/"), 2);
    let commit = a
        .mls
        .commit(&[package], &[], T, |_| BTreeMap::new())
        .unwrap();
    let joined = d.mls.join(&commit.welcome.unwrap(), T).unwrap();
    d.mls.swap(joined, BTreeMap::new()).unwrap();
    assert_eq!(count(&d, b"mls/package/"), 0);
}

/// A member is made only of a device's credential, 64 bytes; nothing is
/// written for another.
#[test]
fn a_member_of_a_credential_of_another_length_is_not_made() {
    let (_dir, keyspace, store) = store();
    let namespace = Namespace::current(store, b"mls/".to_vec());
    for length in [0, 63, 65] {
        assert!(matches!(
            Mls::open(namespace.clone(), &vec![1; length]),
            Err(Error::Credential)
        ));
    }
    assert_eq!(keyspace.iter().count(), 0);
}
