//! Moving home (`light-node.md` §3.9) end to end on three nodes holding
//! two home-only homes, each its own agent with its credential actor (its
//! own handle) and `Homes`, in the nodes' one space; every request as the
//! device library makes it and through a node's socket with the onion's
//! mark. Two phones at the first home sync a local actor's notes through
//! their personal agent; the first joins the second home by its open claim
//! and moves there, its claim of the pooled agent proved in the new home's
//! scope with a new phrase kit; once it is answered the first leaves its
//! notice at the old home; its new group starts from the new agent's log
//! and it pushes everything, the kit opening nothing there until the
//! recovery envelopes, the last push. The second phone reads the notice at
//! the old home and writes a note there, then pairs again from the first
//! through a slot at the new home, its "home" nullifier there recorded at
//! the new `Homes`, starts from the first's checkpoint and carries its
//! note, which the first reads; the old home still serves what it held.

use std::convert::Infallible;

use ed25519_dalek::SigningKey;
use vos_light::group::{Checkpoint, DeviceGroup};
use vos_light::home::{Claim, Home as HomeSpace};
use vos_light::kit::{KitKey, KitSecret};
use vos_light::moving::{self, Move};
use vos_light::pairing::{Hello, Joined, Joiner, Offer, Opened, Opener};
use vos_light::personal::{Answer, Frontier, Link, SealedSync, open_recovery};
use vos_light::route::Route;
use vos_light::{Prover, ProverConfig, Threads};
use vos_wire::credentials::CredentialError;
use vos_wire::homes::HomesError;
use vos_wire::ids::{InstanceId, MethodId, Principal};
use vos_wire::personal::{
    Body, Entry, Envelope, NewDevice, PersonalError, Pushed, RECOVERY, Scope, Woken,
};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::harness::NODES;
use crate::homes::{CREDENTIALS, Founded, HOMES, PERSONAL};
use crate::personal::{
    Personal, Phone, Signer, Sockets, answer, auth, inbox, leave, open_claim, policy, wait,
};

/// The second home's credential actor's handle.
const ELSEWHERE: [u8; 32] = [0x4e; 32];
/// The notes actor on each phone.
const NOTES: InstanceId = InstanceId(1);

/// The link to a personal agent through the nodes' sockets, as a phone's
/// sync key: a push a call, a read a query, each marked as the onion's.
struct AgentLink<'a> {
    sockets: &'a mut Sockets,
    personal: Personal,
    signer: &'a mut Signer,
}

impl Link for AgentLink<'_> {
    type Error = Infallible;

    fn route(&self) -> Route {
        Route::Onion
    }

    fn push(
        &mut self,
        envelopes: &[Vec<u8>],
    ) -> Result<Vec<Result<Pushed, PersonalError>>, Infallible> {
        Ok(envelopes
            .iter()
            .map(|envelope| {
                self.personal
                    .call::<Pushed>(self.sockets, self.signer, "push", envelope.encode())
                    .0
            })
            .collect())
    }

    fn since(
        &mut self,
        scope: Scope,
        position: u64,
    ) -> Result<Result<Vec<Envelope>, PersonalError>, Infallible> {
        Ok(self
            .personal
            .query(self.sockets, &self.signer.key, "since", (scope, position)))
    }

    fn wake(&mut self) -> Result<Result<Woken, PersonalError>, Infallible> {
        Ok(self
            .personal
            .call::<Woken>(self.sockets, self.signer, "wake", Vec::new())
            .0)
    }

    fn frontier(&mut self, device: u32) -> Answer<Frontier, Infallible> {
        Ok(self
            .personal
            .query(self.sockets, &self.signer.key, "frontier", device))
    }
}

/// Run `f` with `phone`'s sealed sync of its installed scopes at
/// `personal`.
fn sealed<T>(
    sockets: &mut Sockets,
    personal: Personal,
    phone: &mut Phone,
    f: impl FnOnce(&mut SealedSync<'_, AgentLink<'_>>) -> T,
) -> T {
    let Phone {
        light, group, sync, ..
    } = phone;
    let mut link = AgentLink {
        sockets,
        personal,
        signer: sync,
    };
    let instances = light.instances().unwrap();
    let mut sync = SealedSync::new(light, group.as_mut().unwrap(), &mut link, instances).unwrap();
    f(&mut sync)
}

/// Everything pushed from `phone` to `personal` ([`moving::finish`]); the
/// closure's lifetimes are the link's, which the function named alone does
/// not take.
#[allow(clippy::redundant_closure)]
fn finish(sockets: &mut Sockets, personal: Personal, phone: &mut Phone) -> moving::Finished {
    sealed(sockets, personal, phone, |sync| moving::finish(sync)).unwrap()
}

fn install(phone: &Phone) {
    let package = vos_light::release::package(
        &std::fs::read(vos_testkit::programs::actor_elf("notes")).unwrap(),
        1,
    )
    .unwrap();
    let outcome = phone.light.install(NOTES, &package, Vec::new()).unwrap();
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
}

fn set(phone: &Phone, key: u64, value: u64) {
    let method = MethodId(vos_light::method_id("set"));
    let outcome = phone
        .light
        .call(NOTES, method, (key, value).encode())
        .unwrap();
    assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
}

fn count(phone: &Phone, key: u64) -> Option<u64> {
    let method = MethodId(vos_light::method_id("count"));
    let caller = Principal::Client([0xd1; 32]);
    match phone
        .light
        .query(caller, NOTES, method, key.encode())
        .unwrap()
    {
        Outcome::Done(bytes) => Option::<u64>::decode_exact(&bytes).unwrap(),
        other => panic!("{other:?}"),
    }
}

/// A home as a device reaches it.
fn space_of(sockets: &mut Sockets, home: &Founded) -> HomeSpace {
    HomeSpace {
        space: home.space.0,
        handle: home.handle,
        agent: home.agent.0,
        identity: sockets.identity(home.agent.0),
        homes: HOMES,
        credentials: CREDENTIALS,
    }
}

/// A home-only space: its keeper's pool of two agents, its open claim's
/// difficulty low.
fn open(home: &Founded) {
    let personal = std::fs::read(vos_checker::programs::personal_elf()).unwrap();
    assert_eq!(home.keeper().top_up(2, &personal, 16).unwrap(), 2);
    home.write::<(), CredentialError>(CREDENTIALS, "open", (4u8, 16u32, 86_400_000u64))
        .unwrap();
}

/// The agent `Homes` at `space` answers `pooled` for, and its identity.
fn pooled(sockets: &mut Sockets, space: &HomeSpace) -> Personal {
    let pooled: Option<u32> = sockets.query(space.agent, &space.identity, HOMES, "pooled", ());
    let agent = pooled.expect("a pooled agent");
    Personal {
        agent,
        identity: sockets.identity(agent),
    }
}

/// `call` of `Homes` at `space` proved in its scope "home" with `phone`'s
/// secret there: the agent assigned.
fn claim_call(
    sockets: &mut Sockets,
    prover: &Prover,
    home: &Founded,
    space: &HomeSpace,
    phone: &Phone,
    call: &vos_light::Call,
) -> u32 {
    let path = phone
        .path(
            sockets,
            space.agent,
            &space.identity,
            CREDENTIALS,
            &space.handle,
        )
        .expect("a member");
    let proof = prover
        .prove_home(&phone.secret(&space.handle), &auth(&path), call, &home.auth)
        .unwrap();
    answer::<u32, HomesError>(&sockets.credentialed(call, &proof)).unwrap()
}

/// The agent's log once it holds an assignment, read as `key`.
fn assigned(sockets: &mut Sockets, personal: Personal, key: &SigningKey) -> Vec<(u64, Entry)> {
    let mut entries = Vec::new();
    wait("the claim assigned", || {
        let admitted: Result<Vec<(u64, Entry)>, PersonalError> =
            personal.query(sockets, key, "log", 0u64);
        if admitted.is_err() {
            return false;
        }
        entries = personal.log(sockets, key, 0);
        entries
            .iter()
            .any(|(_, entry)| matches!(entry.body, Body::Assigned { .. }))
    });
    entries
}

/// `joiner` paired at `personal` from `opener` through a slot, as `device`
/// there, handed `checkpoint`: its group joined, or rejoined when it is a
/// device of a group a move left; then the opener's commit adding it,
/// read by both.
fn pair(
    sockets: &mut Sockets,
    personal: Personal,
    space: &HomeSpace,
    opener_phone: &mut Phone,
    joiner_phone: &mut Phone,
    device: NewDevice,
    checkpoint: Option<Checkpoint>,
) {
    let offer = Offer {
        home: space.clone(),
        memberships: Vec::new(),
    };
    let item_bytes = opener_phone.group().policy().inbox_item_bytes;
    let (mut opener, drawn) = Opener::open(personal.identity, offer, item_bytes).unwrap();
    let at = personal
        .call::<u64>(
            sockets,
            &mut opener_phone.sync,
            "open_slot",
            drawn.slot.arguments(),
        )
        .0
        .unwrap();
    let code = opener.code(
        &drawn,
        at + policy().slot_ttl_ms,
        personal.agent,
        PERSONAL,
        vec![vos_wire::credentials::Onion {
            key: [0x0e; 32],
            ssh_host_key: [0x0f; 32],
        }],
    );
    let mut slot = Signer::new(code.slot_key());
    let (mut joiner, put) = Joiner::scan(&code).unwrap();
    leave(sockets, personal, &mut slot, &put);
    let Opened::Put(put) = opener
        .read(&inbox(sockets, personal, &opener_phone.sync.key))
        .unwrap()
    else {
        panic!("the handshake's last message")
    };
    leave(sockets, personal, &mut opener_phone.sync, &put);
    let Joined::Offer(_) = joiner.read(&inbox(sockets, personal, &slot.key)).unwrap() else {
        panic!("the offer")
    };
    let now = sockets.time();
    let hello = Hello {
        key_package: DeviceGroup::key_package(joiner_phone.light.store(), &device, now).unwrap(),
        device,
        handles: Vec::new(),
    };
    let put = joiner.hello(&hello).unwrap();
    leave(sockets, personal, &mut slot, &put);
    let Opened::Hello(heard) = opener
        .read(&inbox(sockets, personal, &opener_phone.sync.key))
        .unwrap()
    else {
        panic!("the hello")
    };
    let (prepared, mut pairing) = opener_phone
        .group()
        .pair(
            heard.device.clone(),
            heard.key_package.clone(),
            sockets.time(),
        )
        .unwrap();
    if let Some(checkpoint) = checkpoint {
        pairing.trust(checkpoint);
    }
    for put in opener.hand_over(&pairing).unwrap() {
        leave(sockets, personal, &mut opener_phone.sync, &put);
    }
    let Joined::Handover(pairing, ack) = joiner.read(&inbox(sockets, personal, &slot.key)).unwrap()
    else {
        panic!("the handover")
    };
    let store = joiner_phone.light.store();
    joiner_phone.group = Some(match joiner_phone.group.take() {
        Some(old) => moving::rejoin(
            &joiner_phone.light,
            Some(old),
            heard.device.clone(),
            *pairing,
        )
        .unwrap(),
        None => DeviceGroup::join(store, heard.device.clone(), *pairing).unwrap(),
    });
    leave(sockets, personal, &mut slot, &ack);
    assert!(matches!(
        opener
            .read(&inbox(sockets, personal, &opener_phone.sync.key))
            .unwrap(),
        Opened::Received
    ));
    opener_phone.commit(sockets, personal, &prepared);
    for _ in 0..3 {
        opener_phone.read(sockets, personal);
        joiner_phone.read(sockets, personal);
    }
}

/// The recovery scope's envelopes `kit` reads at `personal`.
fn kit_reads(sockets: &mut Sockets, personal: Personal, kit: &KitSecret) -> Vec<Envelope> {
    personal
        .query(sockets, &kit.signing(), "since", (RECOVERY, 0u64))
        .unwrap()
}

#[test]
fn a_personal_space_moves_home_and_its_other_phone_pairs_again() {
    let home = Founded::with(policy());
    let other = home.beside(ELSEWHERE, policy());
    open(&home);
    open(&other);
    let mut sockets = Sockets {
        paths: (1..=NODES)
            .map(|n| home.cluster.dir(n).join("api.sock"))
            .collect(),
        at: 0,
    };
    let space = space_of(&mut sockets, &home);
    let elsewhere = space_of(&mut sockets, &other);
    let prover = Prover::new(ProverConfig {
        threads: Threads::Count(4),
        ..ProverConfig::default()
    })
    .unwrap();
    let expires = |sockets: &mut Sockets| sockets.time() + 60_000;

    // The first phone claims an agent at the first home with a phrase kit;
    // the second is paired there; both sync their notes.
    let mut first = Phone::new(1, &space);
    open_claim(&mut sockets, &space, &first);
    let old = pooled(&mut sockets, &space);
    let phrase = KitSecret::phrase().unwrap();
    let claim = Claim::prepare(
        first.light.store(),
        first.keys.clone(),
        vec![phrase.key()],
        old.agent,
        old.identity,
    )
    .unwrap();
    let call = claim.call(&space, expires(&mut sockets)).unwrap();
    assert_eq!(
        claim_call(&mut sockets, &prover, &home, &space, &first, &call),
        old.agent
    );
    let entries = assigned(&mut sockets, old, &first.sync.key);
    first.group = Some(
        claim
            .claimed(first.light.store(), PERSONAL, &entries, sockets.time())
            .unwrap(),
    );
    first.read(&mut sockets, old);
    let mut second = Phone::new(2, &space);
    let device = second.keys.clone();
    pair(
        &mut sockets,
        old,
        &space,
        &mut first,
        &mut second,
        device,
        None,
    );
    assert_eq!(second.group().id(), Some(1));
    for (n, phone) in [&mut first, &mut second].into_iter().enumerate() {
        install(phone);
        set(phone, n as u64, 10 + n as u64);
        sealed(&mut sockets, old, phone, |sync| sync.push(NOTES)).unwrap();
    }
    for phone in [&mut first, &mut second] {
        sealed(&mut sockets, old, phone, |sync| sync.catch_up(NOTES)).unwrap();
        assert_eq!((count(phone, 0), count(phone, 1)), (Some(10), Some(11)));
    }
    let naming = first.group().archive().naming;

    // The first moves: its open claim at the other home, then its claim of
    // the pooled agent there with a new kit, held beside its group; its
    // notice left at the old home; the new group from the new agent's log.
    open_claim(&mut sockets, &elsewhere, &first);
    let new = pooled(&mut sockets, &elsewhere);
    let next = KitSecret::phrase().unwrap();
    let mut moved = first.keys.clone();
    moved.nullifier = elsewhere.nullifier(&first.secret(&ELSEWHERE));
    let keys: Vec<KitKey> = vec![next.key()];
    let held = Move::prepare(
        first.light.store(),
        first.group.as_ref().unwrap(),
        moved,
        keys,
        new.agent,
        new.identity,
    )
    .unwrap();
    let call = held.call(&elsewhere, expires(&mut sockets)).unwrap();
    assert_eq!(
        claim_call(&mut sockets, &prover, &other, &elsewhere, &first, &call),
        new.agent
    );
    let notice = held.notice(&elsewhere);
    sealed(&mut sockets, old, &mut first, |sync| sync.announce(&notice)).unwrap();
    first.sync = Signer::new(first.light.sync_key().clone());
    first.admin = Signer::new(first.admin.key.clone());
    let entries = assigned(&mut sockets, new, &first.sync.key);
    let group = first.group.take();
    first.group = Some(
        held.claimed(&first.light, group, PERSONAL, &entries, sockets.time())
            .unwrap(),
    );
    assert!(moving::carrying(first.light.store()).unwrap());
    first.read(&mut sockets, new);
    assert!(kit_reads(&mut sockets, new, &next).is_empty());

    // Everything pushed, the recovery envelopes last: the new kit's copy.
    let finished = finish(&mut sockets, new, &mut first);
    assert!(finished.done);
    assert_eq!(finished.scopes[0].2.pushed.len(), 2);
    let r = first.group().archive().recovery.as_ref().unwrap().r;
    let recovered = open_recovery(&r, &new.identity, &kit_reads(&mut sockets, new, &next));
    assert_eq!(recovered.unwrap().naming, naming);

    // The second phone, which missed the move, reads the notice at the old
    // home and writes there.
    let announced = sealed(&mut sockets, old, &mut second, |sync| sync.announced()).unwrap();
    assert_eq!(announced, Some(notice));
    set(&second, 30, 31);
    sealed(&mut sockets, old, &mut second, |sync| sync.push(NOTES)).unwrap();

    // It pairs again from the first at the new home: from the first's
    // checkpoint, carrying its note, which the first reads.
    let checkpoint = sealed(&mut sockets, new, &mut first, |sync| sync.checkpoint(NOTES)).unwrap();
    open_claim(&mut sockets, &elsewhere, &second);
    let mut device = second.keys.clone();
    device.nullifier = elsewhere.nullifier(&second.secret(&ELSEWHERE));
    second.sync = Signer::new(second.light.sync_key().clone());
    second.admin = Signer::new(second.admin.key.clone());
    pair(
        &mut sockets,
        new,
        &elsewhere,
        &mut first,
        &mut second,
        device.clone(),
        Some(checkpoint),
    );
    assert_eq!(second.group().agent().identity, new.identity);
    wait(
        "the second phone's nullifier recorded at the new home",
        || other.read::<Option<u32>>(HOMES, "agent", device.nullifier) == Some(new.agent),
    );
    let finished = finish(&mut sockets, new, &mut second);
    assert!(finished.done);
    assert_eq!(finished.scopes[0].1.started, Some(checkpoint.position));
    assert_eq!(finished.scopes[0].2.pushed.len(), 1);
    let caught = sealed(&mut sockets, new, &mut first, |sync| sync.catch_up(NOTES)).unwrap();
    assert!(caught.passed.is_empty(), "{:?}", caught.passed);
    assert_eq!(count(&first, 30), Some(31));

    // The old home keeps what it held.
    let scope = first.light.scope_id(NOTES).unwrap().0;
    let kept: Vec<Envelope> = old
        .query(
            &mut sockets,
            second.light.sync_key(),
            "since",
            (scope, 0u64),
        )
        .unwrap();
    assert_eq!(kept.len(), 3);
}
