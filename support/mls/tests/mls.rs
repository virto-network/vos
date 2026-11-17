//! `vos-mls` over a fjall store: a group of three made and moved through
//! commits held and confirmed on copies; a copy leaving the current state
//! as it was; a held commit across a reopen, matched by its handshake and
//! deleted on a void; the device group's policy refusing what it does not
//! allow, from a member running other rules; a removed member; a leaf's
//! credential renewed; and a restart into a new group.

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
    _dir: tempfile::TempDir,
}

fn credential(n: u8) -> Vec<u8> {
    let mut credential = vec![n; 64];
    credential[63] = 0xa5;
    credential
}

fn member(n: u8) -> Member {
    let dir = tempfile::tempdir().unwrap();
    let db = fjall::Database::builder(dir.path()).open().unwrap();
    let keyspace = db
        .keyspace("group", fjall::KeyspaceCreateOptions::default)
        .unwrap();
    let namespace = Namespace::current(Store::new(db, keyspace), b"mls/".to_vec());
    let mls = Mls::open(namespace.clone(), &credential(n), BTreeMap::new()).unwrap();
    Member {
        mls,
        namespace,
        _dir: dir,
    }
}

fn reopen(member: &Member, n: u8) -> Mls {
    Mls::open(member.namespace.clone(), &credential(n), BTreeMap::new()).unwrap()
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
    let packages = [
        b.mls.key_package(T, BTreeMap::new()).unwrap(),
        c.mls.key_package(T, BTreeMap::new()).unwrap(),
    ];
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
    let before = a.namespace.store().keyspace().iter().count();
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
    assert_eq!(a.namespace.store().keyspace().iter().count(), before);
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
        a.namespace
            .store()
            .get(b"caller/record")
            .unwrap()
            .as_deref(),
        Some(&b"commit 2"[..]),
        "the caller's rows are the held commit's batch"
    );
    let mut reopened = reopen(&a, 1);
    let (hash, epoch) = reopened.held().unwrap().expect("held across the reopen");
    assert_eq!(
        (hash, epoch),
        (vos_mls::handshake_hash(&commit.handshake), 2)
    );
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
    let package = d.mls.key_package(T, BTreeMap::new()).unwrap();
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
    let old = a.namespace.store().keyspace().iter().count();
    let void = a.mls.restart(T + 1, |_| BTreeMap::new()).unwrap();
    assert!(a.mls.commit(&[], &[], T + 1, |_| BTreeMap::new()).is_err());
    assert_eq!(a.mls.own(&void.handshake).unwrap().kind(), Kind::Started);
    a.mls.void(BTreeMap::new()).unwrap();
    assert_eq!(a.namespace.store().keyspace().iter().count(), old);
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
    let states = |member: &Member| {
        member
            .namespace
            .store()
            .keyspace()
            .iter()
            .map(|row| row.into_inner().unwrap().0)
            .filter(|key| key.starts_with(b"mls/state/"))
            .count()
    };
    assert_eq!(states(&a), 1, "the old group's state is deleted");
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
    assert!(
        on_a.credentials()
            .iter()
            .any(|(_, credential)| *credential == renewed)
    );
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
