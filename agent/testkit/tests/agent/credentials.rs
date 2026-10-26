//! The credential actor in the default agent, on a VOS host and on the
//! JAM-only host: its tree against a reference built from scratch, its
//! slots, its paths, its ring and its refusals; and the Poseidon2 call it
//! makes, as an actor's precompile.

use std::collections::{BTreeMap, BTreeSet};

use vos_pvm_poseidon2::{M31, P};
use vos_testkit::programs::{credentials, credentials_elf, method};
use vos_wire::abi::Failure;
use vos_wire::abi::cap::Target;
use vos_wire::batch::{Admin, Input};
use vos_wire::credentials::{CredentialError, DEPTH, Digest, Path, RootEntry};
use vos_wire::ids::{InstanceId, Principal};
use vos_wire::ingress::Grant;
use vos_wire::result::{Outcome, Step, WorkResult};
use vos_wire::{Decode, Encode};

use crate::common::{ALICE, BOB, COUNTER, Node, OUTER_GAS, Sessions, counter_only, ran};

const CREDENTIALS: InstanceId = InstanceId(9);
const REGISTRAR: u8 = 1;
const HANDLE: Digest = [0x42; 32];

/// The words of a digest, as the reference holds them.
type Words = [M31; 8];

fn compress(left: &Words, right: &Words) -> Words {
    vos_pvm_poseidon2::compress(left, right)
}

fn words(digest: &Digest) -> Words {
    core::array::from_fn(|i| {
        M31::new(u32::from_le_bytes(
            digest[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}

fn digest(words: &Words) -> Digest {
    let mut digest = [0u8; 32];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(words) {
        bytes.copy_from_slice(&word.value().to_le_bytes());
    }
    digest
}

/// The tree's reference, from `proving.md` §8 alone: each enrolled
/// member's slot, the lowest freed slot reused first, and every node
/// computed from scratch.
#[derive(Default)]
struct Reference {
    slots: BTreeMap<Digest, u32>,
    free: BTreeSet<u32>,
    next: u32,
}

impl Reference {
    fn tag_leaf() -> Words {
        let hash = vos_pvm::precompile::blake2b_256(b"vos/p2/leaf");
        let t = u32::from_le_bytes(hash[..4].try_into().unwrap()) & P;
        let mut block = [M31::ZERO; 8];
        block[0] = M31::new(if t == P { 0 } else { t });
        block
    }

    fn empty() -> [Words; DEPTH + 1] {
        let mut empty = [[M31::ZERO; 8]; DEPTH + 1];
        for level in 1..=DEPTH {
            empty[level] = compress(&empty[level - 1], &empty[level - 1]);
        }
        empty
    }

    fn enroll(&mut self, member: Digest) -> u32 {
        let slot = self.free.pop_first().unwrap_or_else(|| {
            self.next += 1;
            self.next - 1
        });
        assert!(self.slots.insert(member, slot).is_none());
        slot
    }

    fn revoke(&mut self, member: &Digest) {
        let slot = self.slots.remove(member).unwrap();
        self.free.insert(slot);
    }

    /// Every non-empty node, level by level, from the leaves up.
    fn levels(&self) -> Vec<BTreeMap<u32, Words>> {
        let empty = Self::empty();
        let mut level: BTreeMap<u32, Words> = self
            .slots
            .iter()
            .map(|(member, &slot)| (slot, compress(&Self::tag_leaf(), &words(member))))
            .collect();
        let mut levels = vec![level.clone()];
        for below in &empty[..DEPTH] {
            let parents: BTreeSet<u32> = level.keys().map(|index| index >> 1).collect();
            level = parents
                .into_iter()
                .map(|parent| {
                    let child = |index: u32| level.get(&index).copied().unwrap_or(*below);
                    (parent, compress(&child(2 * parent), &child(2 * parent + 1)))
                })
                .collect();
            levels.push(level.clone());
        }
        levels
    }

    fn root(&self) -> Digest {
        digest(
            self.levels()[DEPTH]
                .get(&0)
                .unwrap_or(&Self::empty()[DEPTH]),
        )
    }

    /// `member`'s path, from scratch.
    fn path(&self, member: &Digest) -> Option<Path> {
        let slot = *self.slots.get(member)?;
        let (levels, empty) = (self.levels(), Self::empty());
        let siblings = core::array::from_fn(|l| {
            digest(levels[l].get(&((slot >> l) ^ 1)).unwrap_or(&empty[l]))
        });
        Some(Path {
            root: self.root(),
            slot,
            siblings: vos_wire::credentials::Siblings(siblings),
        })
    }

    /// Whether `path` places `member`'s leaf under its root, walked here.
    fn verifies(path: &Path, member: &Digest) -> bool {
        let mut node = compress(&Self::tag_leaf(), &words(member));
        for (l, sibling) in path.siblings.0.iter().enumerate() {
            node = if path.slot >> l & 1 == 0 {
                compress(&node, &words(sibling))
            } else {
                compress(&words(sibling), &node)
            };
        }
        digest(&node) == path.root
    }
}

/// A node with the credential actor installed, `ALICE` its registrar, and
/// its handle set at time 1.
struct Actor {
    node: Node,
    program: Vec<u8>,
    sessions: Sessions,
}

impl Actor {
    fn on(mut node: Node, target: Target) -> Self {
        let elf = std::fs::read(credentials_elf()).unwrap();
        let derived = vos_pvm_compiler::derive(&elf).expect("derives");
        node.add(&derived.actor);
        let mut actor = Self {
            node,
            program: credentials(),
            sessions: Sessions::new(),
        };
        let install = Input::Admin(Admin::Install {
            instance: CREDENTIALS,
            derivation: derived.derivation(&elf),
            roles: vec![(b"registrar".to_vec(), REGISTRAR)],
            target,
            space: vos_wire::SpaceId::NONE,
            clock: vos_wire::WindowClock::DEFAULT,
        });
        let grant = Input::Admin(Admin::SetRole(Grant {
            principal: ALICE,
            role: Some(REGISTRAR),
        }));
        let installed = actor.node.batch(0, vec![install, grant]);
        assert!(
            installed
                .steps
                .iter()
                .all(|step| matches!(step, Step::Ran(_)))
        );
        actor
    }

    fn input<A: Encode>(&mut self, caller: Principal, name: &str, arguments: A) -> Input {
        let method = method(&self.program, name);
        self.sessions
            .request(caller, CREDENTIALS, method, arguments)
    }

    fn query<A: Encode, R: Decode>(&self, name: &str, arguments: A) -> R {
        match self.node.query(
            BOB,
            CREDENTIALS,
            method(&self.program, name),
            arguments.encode(),
        ) {
            Outcome::Done(bytes) => R::decode_exact(&bytes).expect("decodes"),
            other => panic!("{name}: {other:?}"),
        }
    }
}

/// A member digest from `seed`: eight words below p.
fn member(seed: u64) -> Digest {
    let mut digest = [0u8; 32];
    for (i, bytes) in digest.chunks_exact_mut(4).enumerate() {
        let word = (seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (i * 3)) as u32 % P;
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

/// A small deterministic generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// What a step replies, by its method.
#[derive(Debug, PartialEq)]
enum Reply {
    Slot(u32),
    Slots(Vec<u32>),
    Unit,
}

impl Reply {
    fn decode(&self, bytes: &[u8]) -> Self {
        match self {
            Reply::Slot(_) => Reply::Slot(decode(bytes)),
            Reply::Slots(_) => Reply::Slots(decode(bytes)),
            Reply::Unit => {
                decode::<()>(bytes);
                Reply::Unit
            }
        }
    }
}

fn decode<T: Decode>(bytes: &[u8]) -> T {
    T::decode_exact(bytes).expect("decodes")
}

/// Random enrollments, many-member enrollments and revocations, batch by
/// batch, on a VOS host and on the JAM-only host: both refine every batch
/// to the same work result and accumulate it to the same storage; each
/// enrollment's slot is the reference's, the lowest freed first; the root
/// is the reference's, rebuilt from scratch, and the ring holds it from
/// the batch's time; every member's path is the reference's, and verified
/// by the reference's walk and by `Path::proves`.
#[test]
fn the_tree_equals_a_reference_built_from_scratch_on_vos_and_jam() {
    let mut vos = Actor::on(Node::new(), Target::Vos);
    let mut jam = Actor::on(Node::jam(true), Target::Vos);
    let mut reference = Reference::default();
    let mut rng = Rng(0x5eed_c0de);
    let mut seed = 0;
    for time in 1..=12u64 {
        let mut inputs = Vec::new();
        let mut expected = Vec::new();
        if time == 1 {
            inputs.push(vos.input(ALICE, "found", HANDLE));
            expected.push(Reply::Unit);
        }
        for _ in 0..1 + rng.next() % 4 {
            let enrolled: Vec<Digest> = reference.slots.keys().copied().collect();
            let (name, arguments, reply) = match rng.next() % 5 {
                0 | 1 if !enrolled.is_empty() => {
                    let gone = enrolled[(rng.next() % enrolled.len() as u64) as usize];
                    reference.revoke(&gone);
                    ("revoke", gone.encode(), Reply::Unit)
                }
                2 => {
                    let members: Vec<Digest> = (0..1 + rng.next() % 5)
                        .map(|_| {
                            seed += 1;
                            member(seed)
                        })
                        .collect();
                    let slots = members.iter().map(|m| reference.enroll(*m)).collect();
                    ("enroll_many", members.encode(), Reply::Slots(slots))
                }
                _ => {
                    seed += 1;
                    let fresh = member(seed);
                    (
                        "enroll",
                        fresh.encode(),
                        Reply::Slot(reference.enroll(fresh)),
                    )
                }
            };
            let method = method(&vos.program, name);
            inputs.push(
                vos.sessions
                    .request_bytes(ALICE, CREDENTIALS, method, arguments),
            );
            expected.push(reply);
        }
        let work = vos.node.work(time, inputs);
        let (on_vos, on_jam) = (vos.node.refine(&work), jam.node.refine(&work));
        assert_eq!(on_vos, on_jam, "batch {time}");
        let result = WorkResult::decode(&on_vos).unwrap().0;
        assert_eq!(result.steps.len(), expected.len());
        for (step, expected) in result.steps.iter().zip(&expected) {
            let reply = match &ran(step).outcome {
                Outcome::Done(bytes) => expected.decode(bytes),
                other => panic!("batch {time}: {other:?}"),
            };
            assert_eq!(reply, *expected, "batch {time}: the slots");
        }
        for actor in [&mut vos, &mut jam] {
            actor.node.accumulate(&on_vos);
            actor.node.version += 1;
        }
        assert_eq!(vos.node.state, jam.node.state, "storage after batch {time}");
        for actor in [&vos, &jam] {
            let root: RootEntry = actor.query("root", ());
            let expected = RootEntry {
                root: reference.root(),
                since: time,
            };
            assert_eq!(root, expected, "batch {time}");
            assert_eq!(
                actor.query::<_, u64>("count", ()),
                reference.slots.len() as u64
            );
        }
        for member in reference.slots.keys() {
            let path = vos
                .query::<_, Option<Path>>("path", *member)
                .expect("enrolled");
            assert_eq!(Some(&path), reference.path(member).as_ref());
            assert!(Reference::verifies(&path, member));
            assert!(path.proves(member));
            assert!(!path.proves(&self::member(u64::MAX)), "another member's");
        }
    }
    assert!(reference.slots.len() > 8 && reference.next as usize > reference.slots.len());
}

/// A step's result: its reply, or the actor's error.
fn answer<T: Decode>(step: &Step) -> Result<T, CredentialError> {
    match &ran(step).outcome {
        Outcome::Done(bytes) => Ok(decode(bytes)),
        Outcome::Failed {
            code: Failure::Handler,
            detail,
        } => Err(decode(detail)),
        other => panic!("{other:?}"),
    }
}

/// A founded actor on a VOS host, with `members` enrolled at time 1.
fn founded(members: &[Digest]) -> Actor {
    let mut actor = Actor::on(Node::new(), Target::Vos);
    let mut inputs = vec![actor.input(ALICE, "found", HANDLE)];
    inputs.extend(members.iter().map(|m| actor.input(ALICE, "enroll", *m)));
    let result = actor.node.batch(1, inputs);
    assert_eq!(answer::<()>(&result.steps[0]), Ok(()));
    for (step, slot) in result.steps[1..].iter().zip(0..) {
        assert_eq!(answer(step), Ok(slot));
    }
    actor
}

/// A revoked member's slot is freed, and enrollments take the freed slots
/// lowest first, whatever order they were freed in, then the lowest never
/// used; a revoked member enrolls again as any other.
#[test]
fn freed_slots_are_reused_lowest_first() {
    let members: Vec<Digest> = (1..=6).map(member).collect();
    let mut actor = founded(&members);
    let revokes = [4, 1, 3].map(|i| actor.input(ALICE, "revoke", members[i]));
    let revoked = actor.node.batch(2, revokes.to_vec());
    assert!(
        revoked
            .steps
            .iter()
            .all(|step| answer::<()>(step) == Ok(()))
    );
    let enrolls: Vec<Input> = [10, 11, 12, 13]
        .map(|seed| actor.input(ALICE, "enroll", member(seed)))
        .into_iter()
        .chain([actor.input(ALICE, "enroll", members[1])])
        .collect();
    let enrolled = actor.node.batch(3, enrolls);
    let slots: Vec<Result<u32, _>> = enrolled.steps.iter().map(answer).collect();
    assert_eq!(slots, [Ok(1), Ok(3), Ok(4), Ok(6), Ok(7)]);
    assert_eq!(actor.query::<_, u64>("count", ()), 8);
    let path: Option<Path> = actor.query("path", members[1]);
    assert_eq!(path.map(|path| path.slot), Some(7));
    let gone: Option<Path> = actor.query("path", members[4]);
    assert_eq!(gone, None);
}

/// The refusals: no write before the handle is set, which is set once and
/// never to zeros; a digest with a word at or above p; a member enrolled
/// twice, or revoked unenrolled; more than 256 at once, and an enrollment
/// of many that fails on one enrolls none; every write but `claim` under
/// `registrar`.
#[test]
fn the_actor_refuses_what_its_rules_refuse() {
    let mut actor = Actor::on(Node::new(), Target::Vos);
    let early = actor.input(ALICE, "enroll", member(1));
    let zero = actor.input(ALICE, "found", [0u8; 32]);
    let found = actor.input(ALICE, "found", HANDLE);
    let again = actor.input(ALICE, "found", [7u8; 32]);
    let steps = actor.node.batch(1, vec![early, zero, found, again]).steps;
    assert_eq!(answer::<u32>(&steps[0]), Err(CredentialError::Unfounded));
    assert_eq!(answer::<()>(&steps[1]), Err(CredentialError::ZeroHandle));
    assert_eq!(answer::<()>(&steps[2]), Ok(()));
    assert_eq!(answer::<()>(&steps[3]), Err(CredentialError::Founded));
    assert_eq!(actor.query::<_, Digest>("handle", ()), HANDLE);

    let mut malformed = member(2);
    malformed[28..].copy_from_slice(&P.to_le_bytes());
    let empty_root: RootEntry = actor.query("root", ());
    let inputs = vec![
        actor.input(ALICE, "enroll", malformed),
        actor.input(ALICE, "enroll", member(1)),
        actor.input(ALICE, "enroll", member(1)),
        actor.input(ALICE, "revoke", member(3)),
        actor.input(ALICE, "enroll_many", vec![member(4); 257]),
        actor.input(ALICE, "enroll_many", vec![member(5), member(6), member(5)]),
        actor.input(BOB, "enroll", member(7)),
        actor.input(BOB, "revoke", member(1)),
    ];
    let steps = actor.node.batch(2, inputs).steps;
    assert_eq!(answer::<u32>(&steps[0]), Err(CredentialError::NotADigest));
    assert_eq!(answer::<u32>(&steps[1]), Ok(0));
    assert_eq!(answer::<u32>(&steps[2]), Err(CredentialError::Enrolled));
    assert_eq!(answer::<()>(&steps[3]), Err(CredentialError::NotEnrolled));
    assert_eq!(answer::<Vec<u32>>(&steps[4]), Err(CredentialError::TooMany));
    assert_eq!(
        answer::<Vec<u32>>(&steps[5]),
        Err(CredentialError::Enrolled)
    );
    for step in &steps[6..] {
        assert!(matches!(
            ran(step).outcome,
            Outcome::Failed {
                code: Failure::Forbidden,
                ..
            }
        ));
    }
    assert_eq!(actor.query::<_, u64>("count", ()), 1, "only member 1");
    assert_eq!(actor.query::<_, Option<Path>>("path", member(5)), None);
    let root: RootEntry = actor.query("root", ());
    assert_ne!(root.root, empty_root.root);
    assert_eq!(root.since, 2);
}

/// An invitation names its member's digest, which any caller may claim
/// until its expiry and no later, once; a claim enrolls no other member;
/// an enrolled member takes no invitation; a revocation of an invited
/// member withdraws the invitation.
#[test]
fn an_invitation_enrolls_its_member_until_its_expiry() {
    let mut actor = founded(&[member(1)]);
    let inputs = vec![
        actor.input(ALICE, "invite", (member(2), 5_000u64)),
        actor.input(ALICE, "invite", (member(3), 3_000u64)),
        actor.input(ALICE, "invite", (member(4), 9_000u64)),
        actor.input(ALICE, "invite", (member(1), 9_000u64)),
        actor.input(BOB, "invite", (member(5), 9_000u64)),
    ];
    let steps = actor.node.batch(2, inputs).steps;
    for step in &steps[..3] {
        assert_eq!(answer::<()>(step), Ok(()));
    }
    assert_eq!(answer::<()>(&steps[3]), Err(CredentialError::Enrolled));
    assert!(matches!(
        ran(&steps[4]).outcome,
        Outcome::Failed {
            code: Failure::Forbidden,
            ..
        }
    ));
    let inputs = vec![
        actor.input(ALICE, "revoke", member(4)),
        actor.input(BOB, "claim", member(4)),
    ];
    let steps = actor.node.batch(3, inputs).steps;
    assert_eq!(answer::<()>(&steps[0]), Ok(()), "withdrawn");
    assert_eq!(answer::<u32>(&steps[1]), Err(CredentialError::NotInvited));
    let inputs = vec![
        actor.input(BOB, "claim", member(2)),
        actor.input(BOB, "claim", member(2)),
        actor.input(BOB, "claim", member(3)),
        actor.input(BOB, "claim", member(6)),
    ];
    let steps = actor.node.batch(4_000, inputs).steps;
    assert_eq!(answer::<u32>(&steps[0]), Ok(1));
    assert_eq!(answer::<u32>(&steps[1]), Err(CredentialError::Enrolled));
    assert_eq!(answer::<u32>(&steps[2]), Err(CredentialError::Expired));
    assert_eq!(answer::<u32>(&steps[3]), Err(CredentialError::NotInvited));
    let at_expiry = vec![actor.input(BOB, "claim", member(3))];
    assert_eq!(
        answer::<u32>(&actor.node.batch(5_000, at_expiry).steps[0]),
        Err(CredentialError::Expired)
    );
    assert_eq!(actor.query::<_, u64>("count", ()), 2);
}

/// The ring: the install's entry is the empty tree's from the founding's
/// time; a batch's writes leave one entry, from its time; a root fallen out
/// of the last 64 is unknown, and a superseded one stale past
/// `ROOT_MAX_AGE`, as ingress and apply judge it from the stored row.
#[test]
fn the_ring_keeps_a_root_a_batch_from_its_time() {
    use vos_wire::credentials::{RING, Ring, RootRefusal, tables};
    let mut actor = founded(&[]);
    let empty: RootEntry = actor.query("root", ());
    assert_eq!(empty.since, 1);
    let mut roots = vec![empty.root];
    for time in 2..2 + RING as u64 {
        let inputs = vec![
            actor.input(ALICE, "enroll", member(2 * time)),
            actor.input(ALICE, "enroll", member(2 * time + 1)),
        ];
        actor.node.batch(time, inputs);
        let root: RootEntry = actor.query("root", ());
        assert_eq!(root.since, time);
        roots.push(root.root);
    }
    let rows = vos_wire::abi::Rows::Table {
        tag: vos_testkit::programs::table_tag(tables::RING),
        transform: vos_wire::keys::Transform::Hashed,
    };
    let key = vos_wire::keys::row(CREDENTIALS, rows, &[tables::RING_KEY]).unwrap();
    let ring: Ring = actor.node.value(&key).expect("the ring's row");
    assert_eq!(ring.0.len(), RING);
    assert_eq!(
        ring.0.iter().map(|entry| entry.root).collect::<Vec<_>>(),
        roots[1..]
    );
    let newest = ring.newest().unwrap().since;
    assert_eq!(ring.accepts(&roots[0], newest), Err(RootRefusal::Unknown));
    assert_eq!(ring.accepts(&roots[RING], u64::MAX), Ok(()));
    let superseded = ring.0[1].since + vos_wire::defaults::ROOT_MAX_AGE;
    assert_eq!(ring.accepts(&roots[1], superseded), Ok(()));
    assert_eq!(
        ring.accepts(&roots[1], superseded + 1),
        Err(RootRefusal::Stale)
    );
}

/// The re-seed: an enrollment of 256 members fits one handler's gas, at
/// slots 0 to 255, the tree the reference's; and what one enrollment and
/// one revocation cost a handler.
#[test]
fn an_enrollment_of_the_most_members_fits_a_handler() {
    let mut actor = founded(&[]);
    let mut reference = Reference::default();
    let members: Vec<Digest> = (1..=256).map(member).collect();
    for member in &members {
        reference.enroll(*member);
    }
    let input = actor.input(ALICE, "enroll_many", members.clone());
    let result = actor.node.batch(2, vec![input]);
    let slots: Vec<u32> = answer(&result.steps[0]).unwrap();
    assert_eq!(slots, (0..256).collect::<Vec<_>>());
    let many = ran(&result.steps[0]).gas_used;
    let root: RootEntry = actor.query("root", ());
    assert_eq!(root.root, reference.root());
    let enroll = actor.input(ALICE, "enroll", member(1_000));
    let revoke = actor.input(ALICE, "revoke", members[100]);
    let steps = actor.node.batch(3, vec![enroll, revoke]).steps;
    let (one, gone) = (ran(&steps[0]).gas_used, ran(&steps[1]).gas_used);
    println!("enroll_many(256): {many} gas; enroll: {one}; revoke: {gone}");
    assert!(many <= vos_wire::defaults::MAX_HANDLER_GAS);
    assert!(one <= vos_wire::defaults::HANDLER_GAS && gone <= vos_wire::defaults::HANDLER_GAS);
}

/// An actor's Poseidon2 call, which its agent serves: the reference
/// compression on a VOS host and on the JAM-only host, at one price; a
/// word at or above p, p itself included, traps it on both.
#[test]
fn an_actors_poseidon2_call_is_served_and_a_word_at_or_above_p_traps() {
    let words: Vec<u32> = (0..16).map(|i| (i * 0x0765_4321 + 11) % P).collect();
    let expected: Vec<u32> = {
        let state: [M31; 16] = core::array::from_fn(|i| M31::new(words[i]));
        let left = core::array::from_fn(|i| state[i]);
        let right = core::array::from_fn(|i| state[8 + i]);
        compress(&left, &right)
            .iter()
            .map(|word| word.value())
            .collect()
    };
    let mut gas = Vec::new();
    for node in [Node::new(), Node::jam(true)] {
        let (actors, node) = counter_only(node);
        let compress = actors.method(COUNTER, "compress");
        let mut sessions = Sessions::new();
        let mut inputs = vec![sessions.request(ALICE, COUNTER, compress, words.clone())];
        for (index, word) in [(0, P), (15, P), (8, u32::MAX)] {
            let mut refused = words.clone();
            refused[index] = word;
            inputs.push(sessions.request(ALICE, COUNTER, compress, refused));
        }
        let work = node.work(1, inputs);
        let result = WorkResult::decode(&node.refine_with(&work, OUTER_GAS))
            .unwrap()
            .0;
        let served = ran(&result.steps[0]);
        assert_eq!(served.outcome, Outcome::Done(expected.encode()));
        gas.push(served.gas_used);
        for step in &result.steps[1..] {
            assert!(matches!(
                ran(step).outcome,
                Outcome::Failed {
                    code: Failure::Trapped,
                    ..
                }
            ));
        }
    }
    assert_eq!(gas[0], gas[1], "one price on both hosts");
}
