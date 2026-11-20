//! The light node's local actors as the app ships them, and what it keeps
//! out of their state: the credential book and the device book read back
//! and synced; an operation of a later release, or of a kind this build
//! does not know, held, and the release's replayed once it is installed;
//! an invalid operation, and one of an author already cut off,
//! quarantined, never applied, and reported, while an equivocation's forks
//! apply in either order; and a full disk refusing every new write with
//! nothing written, until room is freed.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use merkle_crdt::{Author, Node};
use vos_abi::abi::Failure;
use vos_abi::ids::{InstanceId, MethodId, Principal};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_light::group::{Archive, archive};
use vos_light::release::{self, Package};
use vos_light::sync::{self, Blake2b256, Call, Cid, Hold, Op, Ops, Quarantine};
use vos_light::{Config, Disk, Error, Light, MAX_ARGUMENTS};
use vos_testkit::programs;

const BOOK: InstanceId = InstanceId(2);
const DEVICE: Principal = Principal::Client([0xd1; 32]);

/// The naming secret the tests' devices share, as pairing gives it.
const NAMING: [u8; 32] = [0x11; 32];

fn read(path: std::path::PathBuf) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

fn agent() -> Vec<u8> {
    release::agent(&read(programs::program_elf("vos-agent"))).unwrap()
}

/// The device book's first release, and its next.
fn device_books() -> (Package, Package) {
    (
        release::package(&read(programs::program_elf("vos-device-book")), 1).unwrap(),
        release::package(&read(programs::actor_elf("device-book-next")), 2).unwrap(),
    )
}

/// A light node at `dir`, its store's archive the devices' shared one.
fn open(dir: &std::path::Path, agent: &[u8], config: Config) -> Light {
    let light = Light::open(dir, agent, config).unwrap();
    let shared = Archive {
        naming: NAMING,
        previous: Vec::new(),
        scopes: Vec::new(),
        keys: Vec::new(),
        recovery: None,
        drawn: Vec::new(),
    };
    light.store().adopt(&shared).unwrap();
    light
}

/// A device: its light node at a directory of its own, `package`
/// installed at [`BOOK`].
struct Device {
    light: Light,
    package: Package,
    _dir: tempfile::TempDir,
}

impl Device {
    fn new(agent: &[u8], package: &Package) -> Self {
        Self::with(agent, package, Config::default())
    }

    fn with(agent: &[u8], package: &Package, config: Config) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let light = open(dir.path(), agent, config);
        let installed = light.install(BOOK, package, Vec::new()).unwrap();
        assert!(matches!(installed, Outcome::Done(_)), "{installed:?}");
        Self {
            light,
            package: package.clone(),
            _dir: dir,
        }
    }

    fn method(&self, name: &str) -> MethodId {
        programs::method(&self.package.programs[0], name)
    }

    fn call(&self, name: &str, arguments: Vec<u8>) -> Result<Outcome, Error> {
        self.light.call(BOOK, self.method(name), arguments)
    }

    fn done(&self, name: &str, arguments: Vec<u8>) {
        match self.call(name, arguments).unwrap() {
            Outcome::Done(_) => {}
            other => panic!("{name}: {other:?}"),
        }
    }

    fn query<T: Decode>(&self, name: &str, arguments: Vec<u8>) -> T {
        match self
            .light
            .query(DEVICE, BOOK, self.method(name), arguments)
            .unwrap()
        {
            Outcome::Done(reply) => T::decode_exact(&reply).unwrap(),
            other => panic!("{name}: {other:?}"),
        }
    }

    /// The local nodes not yet pushed, marked pushed.
    fn push(&self) -> Vec<Vec<u8>> {
        let outbox = self.light.outbox(BOOK).unwrap();
        let pushed: Vec<(Author, u64)> =
            outbox.iter().map(|node| (node.author, node.seq)).collect();
        self.light.pushed(BOOK, &pushed).unwrap();
        outbox.into_iter().map(|node| node.bytes).collect()
    }

    fn labels(&self) -> Vec<(u32, String)> {
        let mut labels: Vec<(u32, String)> = self.query("labels", Vec::new());
        labels.sort();
        labels
    }
}

/// A node of `ops` at `seq` in `key`'s chain of the book's scope, after
/// `parents`.
fn node(key: &SigningKey, seq: u64, ops: Ops, parents: BTreeSet<Cid>) -> Vec<u8> {
    let scope = merkle_crdt::Scope(archive::scope_id(&NAMING, &sync::scope_name(BOOK)));
    Node::<Blake2b256, Ops>::sign(key, &scope, seq, ops, parents).to_bytes()
}

fn call(method: MethodId, release: u32, arguments: Vec<u8>) -> Op {
    Op::Call(Call {
        release,
        method,
        arguments,
        time: 7,
        seed: [7; 32],
    })
}

fn cid(bytes: &[u8]) -> Cid {
    merkle_crdt::Cid(<Blake2b256 as merkle_crdt::Hasher>::hash(bytes))
}

/// The credential book and the device book, installed from their release
/// artifacts, read back what their merge handlers wrote, on the device
/// and opened again; a second device that ingests the first's nodes reads
/// the same; and what is out of bounds is declined, recording nothing.
#[test]
fn the_credential_book_and_the_device_book_read_back() {
    use vos_wire::books::{Agent, DeviceHandle, Enrolled, Guard, Location, Pinned};

    let agent = agent();
    let credentials =
        release::package(&read(programs::program_elf("vos-credential-book")), 1).unwrap();
    let (devices, _) = device_books();
    let dir = tempfile::tempdir().unwrap();
    let space = [0x5a; 32];
    let enrolled = Enrolled {
        name: "the co-op".into(),
        credentials: Location {
            agent: 3,
            instance: 1,
        },
        agents: vec![Agent {
            agent: 3,
            identity: [0x33; 32],
        }],
    };
    let handle = DeviceHandle {
        handle: [0x48; 32],
        member: [0x4d; 32],
        owner: [0x4f; 32],
    };
    let sign_in = Pinned {
        at: Location {
            agent: 3,
            instance: 4,
        },
        method: "sign_in".into(),
        guard: Guard::Auth {
            scope: "sign-in".into(),
            once: false,
        },
    };
    let transfer = Pinned {
        at: Location {
            agent: 3,
            instance: 5,
        },
        method: "transfer".into(),
        guard: Guard::Owner,
    };
    const CREDENTIALS: InstanceId = InstanceId(1);
    let method = |name: &str| programs::method(&credentials.programs[0], name);
    let book = |light: &Light, name: &str, arguments: Vec<u8>| match light
        .call(CREDENTIALS, method(name), arguments)
        .unwrap()
    {
        Outcome::Done(_) => {}
        other => panic!("{name}: {other:?}"),
    };
    let ask = |light: &Light, name: &str, arguments: Vec<u8>| match light
        .query(DEVICE, CREDENTIALS, method(name), arguments)
        .unwrap()
    {
        Outcome::Done(reply) => reply,
        other => panic!("{name}: {other:?}"),
    };
    let pushed = {
        let phone = Device::with(&agent, &devices, Config::default());
        let light = open(dir.path(), &agent, Config::default());
        light
            .install(CREDENTIALS, &credentials, Vec::new())
            .unwrap();
        book(&light, "join", (space, enrolled.clone()).encode());
        book(&light, "join", ([0x77u8; 32], enrolled.clone()).encode());
        book(&light, "leave", [0x77u8; 32].encode());
        book(&light, "handle", (space, 1u32, handle).encode());
        book(&light, "handle", (space, 2u32, handle).encode());
        book(&light, "unhandle", (space, 2u32).encode());
        book(&light, "pin", (space, sign_in.clone()).encode());
        book(&light, "pin", (space, transfer.clone()).encode());
        book(
            &light,
            "unpin",
            (space, transfer.at, transfer.method.clone()).encode(),
        );
        // Out of bounds: declined, nothing recorded.
        let unnamed = Enrolled {
            name: String::new(),
            ..enrolled.clone()
        };
        let declined = light
            .call(CREDENTIALS, method("join"), (space, unnamed).encode())
            .unwrap();
        assert!(
            matches!(
                declined,
                Outcome::Failed {
                    code: Failure::Handler,
                    ..
                }
            ),
            "{declined:?}"
        );
        assert_eq!(light.outbox(CREDENTIALS).unwrap().len(), 9);

        phone.done("label", (1u32, "phone".to_string()).encode());
        phone.done("label", (2u32, "laptop".to_string()).encode());
        phone.done("label", (3u32, "old tablet".to_string()).encode());
        phone.done("unlabel", 3u32.encode());
        phone.done(
            "set",
            (1u32, "theme".to_string(), b"dark".to_vec()).encode(),
        );
        phone.done("set", (1u32, "sync".to_string(), b"wifi".to_vec()).encode());
        phone.done(
            "set",
            (2u32, "theme".to_string(), b"light".to_vec()).encode(),
        );
        phone.done("unset", (1u32, "sync".to_string()).encode());
        let long = "x".repeat(vos_wire::books::LABEL_BYTES + 1);
        assert!(matches!(
            phone.call("label", (1u32, long).encode()).unwrap(),
            Outcome::Failed {
                code: Failure::Handler,
                ..
            }
        ));
        assert_eq!(
            phone.labels(),
            [(1, "phone".to_string()), (2, "laptop".to_string())]
        );
        assert_eq!(
            phone.query::<Vec<(String, Vec<u8>)>>("settings", 1u32.encode()),
            [("theme".to_string(), b"dark".to_vec())]
        );
        assert_eq!(
            phone.query::<Option<String>>("label_of", 2u32.encode()),
            Some("laptop".into())
        );

        let laptop = Device::new(&agent, &devices);
        laptop.light.ingest(BOOK, phone.push(), None).unwrap();
        assert_eq!(laptop.labels(), phone.labels());
        assert_eq!(
            laptop.query::<Vec<(String, Vec<u8>)>>("settings", 2u32.encode()),
            [("theme".to_string(), b"light".to_vec())]
        );
        light.outbox(CREDENTIALS).unwrap()
    };

    let light = Light::open(dir.path(), &agent, Config::default()).unwrap();
    let spaces = Vec::<([u8; 32], Enrolled)>::decode_exact(&ask(&light, "spaces", Vec::new()));
    assert_eq!(spaces.unwrap(), [(space, enrolled.clone())]);
    let enrolled_again =
        Option::<Enrolled>::decode_exact(&ask(&light, "member_of", space.encode())).unwrap();
    assert_eq!(enrolled_again, Some(enrolled.clone()));
    let handles = Vec::<(u32, DeviceHandle)>::decode_exact(&ask(&light, "handles", space.encode()));
    assert_eq!(handles.unwrap(), [(1, handle)]);
    let pins = Vec::<Pinned>::decode_exact(&ask(&light, "pins", space.encode())).unwrap();
    assert_eq!(pins, [sign_in]);

    // Another device reads the same from the nodes.
    let other = tempfile::tempdir().unwrap();
    let tablet = open(other.path(), &agent, Config::default());
    tablet
        .install(CREDENTIALS, &credentials, Vec::new())
        .unwrap();
    let ingested = tablet
        .ingest(CREDENTIALS, pushed.into_iter().map(|node| node.bytes), None)
        .unwrap();
    assert_eq!(ingested.nodes.applied.len(), 9);
    assert!(ingested.held.is_empty() && ingested.quarantined.is_empty());
    assert_eq!(
        ask(&tablet, "spaces", Vec::new()),
        ask(&light, "spaces", Vec::new())
    );
    for name in ["handles", "pins", "member_of"] {
        assert_eq!(
            ask(&tablet, name, space.encode()),
            ask(&light, name, space.encode())
        );
    }
}

/// A device on the device book's next release labels a device and retires
/// one, a handler the first release lacks; a device still on the first
/// holds both operations, as it holds one of a kind its build does not
/// know, and writes on. Once it installs the next release, the release's
/// operations are replayed and both devices read the same; the unknown
/// kind is held still. A release before the one installed is refused.
#[test]
fn an_operation_of_a_later_release_is_held_then_replayed() {
    let agent = agent();
    let (first, next) = device_books();
    let newer = Device::new(&agent, &next);
    let older = Device::new(&agent, &first);
    newer.done("label", (1u32, "phone".to_string()).encode());
    newer.done("retire", 9u32.encode());
    let pushed = newer.push();
    let retire = newer.light.outbox(BOOK).unwrap();
    assert!(retire.is_empty());

    // The older device takes the nodes and holds their operations, each
    // of a release it does not run: a label's too, whose meaning a later
    // release may change.
    older.done("label", (2u32, "laptop".to_string()).encode());
    let ingested = older.light.ingest(BOOK, pushed.clone(), None).unwrap();
    assert_eq!(ingested.nodes.applied.len(), 2);
    assert_eq!(ingested.held.len(), 2);
    for held in &ingested.held {
        assert_eq!(held.why, Hold::Release);
        assert_eq!(held.origin.author, newer.light.author().0);
    }
    assert_eq!(older.labels(), [(2, "laptop".to_string())]);
    newer.light.ingest(BOOK, older.push(), None).unwrap();

    // An operation of a kind no build here knows, from a third author.
    let stranger = SigningKey::from_bytes(&[3; 32]);
    let unknown = node(
        &stranger,
        0,
        vec![Op::Unknown {
            kind: 9,
            body: vec![1, 2, 3],
        }],
        BTreeSet::from([cid(&pushed[1])]),
    );
    let ingested = older.light.ingest(BOOK, [unknown.clone()], None).unwrap();
    assert_eq!(ingested.held.len(), 1);
    assert_eq!(ingested.held[0].why, Hold::Kind);
    newer.light.ingest(BOOK, [unknown], None).unwrap();
    assert_eq!(older.light.held(BOOK).unwrap().len(), 3);
    // A replay before the update runs nothing.
    let replayed = older.light.replay(BOOK).unwrap();
    assert!(replayed.applied.is_empty() && replayed.quarantined.is_empty());
    assert_eq!(replayed.held, 3);

    // The update: the next release installed over the first.
    let installed = older.light.install(BOOK, &next, Vec::new()).unwrap();
    assert!(matches!(installed, Outcome::Done(_)), "{installed:?}");
    let older = Device {
        package: next.clone(),
        ..older
    };
    let held = older.light.held(BOOK).unwrap();
    assert_eq!(held.len(), 1, "the unknown kind waits for the app's update");
    assert_eq!(held[0].why, Hold::Kind);
    assert_eq!(older.query::<Vec<u32>>("retired", Vec::new()), [9]);
    assert_eq!(older.labels(), newer.labels());
    assert_eq!(
        older.query::<Vec<u32>>("retired", Vec::new()),
        newer.query::<Vec<u32>>("retired", Vec::new())
    );
    // Its own operations now carry the next release.
    older.done("retire", 4u32.encode());
    newer.light.ingest(BOOK, older.push(), None).unwrap();
    assert_eq!(newer.query::<Vec<u32>>("retired", Vec::new()).len(), 2);

    // No going back, and no other program under an installed release.
    assert!(matches!(
        older.light.install(BOOK, &first, Vec::new()),
        Err(Error::Release { installed: 2 })
    ));
    let other = Package {
        release: 2,
        ..first.clone()
    };
    assert!(matches!(
        older.light.install(BOOK, &other, Vec::new()),
        Err(Error::Release { installed: 2 })
    ));
}

/// A peer's operations that no device records: a label past its bound,
/// which the handler refuses; arguments that do not decode; arguments past
/// what a call takes; and a command, which no merge entry runs. Each is
/// quarantined with its author named, writes nothing, and stays out after
/// a replay; the node's valid operation beside them applies.
#[test]
fn invalid_operations_are_quarantined_never_applied_and_reported() {
    let agent = agent();
    let (first, _) = device_books();
    let device = Device::new(&agent, &first);
    let label = device.method("label");
    let garbler = SigningKey::from_bytes(&[4; 32]);
    let long = "x".repeat(vos_wire::books::LABEL_BYTES + 1);
    let ops = vec![
        call(label, 1, (1u32, long).encode()),
        call(label, 1, vec![0xff; 3]),
        call(label, 1, vec![0; MAX_ARGUMENTS + 1]),
        call(MethodId(0x1234_5678), 1, Vec::new()),
        call(label, 1, (2u32, "fine".to_string()).encode()),
    ];
    let before = device.light.store().rows().unwrap();
    let garbage = node(&garbler, 0, ops, BTreeSet::new());
    let ingested = device.light.ingest(BOOK, [garbage.clone()], None).unwrap();
    assert_eq!(ingested.nodes.applied, [cid(&garbage)]);
    assert!(ingested.held.is_empty());
    let whys: Vec<Quarantine> = ingested.quarantined.iter().map(|kept| kept.why).collect();
    assert_eq!(
        whys,
        [
            Quarantine::Failed(Failure::Handler),
            Quarantine::Failed(Failure::Trapped),
            Quarantine::Invalid,
            Quarantine::Failed(Failure::Unknown),
        ]
    );
    for kept in &ingested.quarantined {
        assert_eq!(kept.origin.author, Author::from(&garbler).0);
        assert_eq!(kept.cid, cid(&garbage));
    }
    assert_eq!(device.labels(), [(2, "fine".to_string())]);
    // Stored and listed, for the chrome to name its author.
    assert_eq!(
        device.light.quarantined(BOOK).unwrap(),
        ingested.quarantined
    );
    // Nothing but the node's own rows and its one valid write.
    let after = device.light.store().rows().unwrap();
    let new: Vec<_> = after.iter().filter(|row| !before.contains(row)).collect();
    let quarantined_rows = new
        .iter()
        .filter(|(key, _)| key.starts_with(&vos_abi::keys::quarantined_op_prefix(BOOK)))
        .count();
    assert_eq!(quarantined_rows, 4);
    let replayed = device.light.replay(BOOK).unwrap();
    assert!(replayed.applied.is_empty() && replayed.held == 0);
    assert_eq!(device.labels(), [(2, "fine".to_string())]);
    assert_eq!(device.light.quarantined(BOOK).unwrap().len(), 4);
}

/// An author already cut off in the scope, by the device set past its
/// frontier: its operations at the cutoff and after, arriving later, are
/// quarantined and never applied, its earlier ones applied, and nothing it
/// wrote before the cutoff is hidden by what it wrote after.
#[test]
fn operations_of_a_cut_off_author_are_held_out() {
    let agent = agent();
    let (first, _) = device_books();
    let phone = Device::new(&agent, &first);
    let thief = Device::new(&agent, &first);
    thief.done("label", (1u32, "mine".to_string()).encode());
    let before = thief.push();
    thief.done("label", (1u32, "stolen".to_string()).encode());
    thief.done("label", (2u32, "stolen too".to_string()).encode());
    let after = thief.push();
    phone.light.cut_off(BOOK, thief.light.author(), 1).unwrap();
    assert_eq!(
        phone.light.cutoff(BOOK, &thief.light.author()).unwrap(),
        Some(1)
    );

    let ingested = phone
        .light
        .ingest(BOOK, before.into_iter().chain(after), None)
        .unwrap();
    assert_eq!(ingested.nodes.applied.len(), 3);
    assert_eq!(ingested.quarantined.len(), 2);
    assert!(
        ingested
            .quarantined
            .iter()
            .all(|kept| kept.why == Quarantine::CutOff && kept.origin.seq >= 1)
    );
    // Its write before the cutoff stands: the later one never replaced it.
    assert_eq!(phone.labels(), [(1, "mine".to_string())]);
    // A replay applies none of them.
    phone.light.replay(BOOK).unwrap();
    assert_eq!(phone.labels(), [(1, "mine".to_string())]);
}

/// A full disk: below the reserve a call, an ingest and an install are
/// refused with nothing written, the store's rows, its outbox and its
/// scope as they were, and queries still answer; once room is freed,
/// each succeeds, and the refused ingest's nodes apply.
#[test]
fn a_full_disk_refuses_new_writes_until_room_is_freed() {
    let agent = agent();
    let (first, next) = device_books();
    let free = Arc::new(AtomicU64::new(u64::MAX));
    let probe = Arc::clone(&free);
    let config = Config {
        disk: Disk::Probe(Arc::new(move || probe.load(Ordering::SeqCst))),
    };
    let phone = Device::with(&agent, &first, config.clone());
    let laptop = Device::new(&agent, &first);
    phone.done("label", (1u32, "phone".to_string()).encode());
    laptop.done("label", (2u32, "laptop".to_string()).encode());
    let from_laptop = laptop.push();

    free.store(vos_light::RESERVE_BYTES - 1, Ordering::SeqCst);
    let rows = phone.light.store().rows().unwrap();
    let outbox = phone.light.outbox(BOOK).unwrap().len();
    let have = phone.light.have(BOOK).unwrap();
    assert!(matches!(
        phone.call("label", (3u32, "tablet".to_string()).encode()),
        Err(Error::Full { free }) if free == vos_light::RESERVE_BYTES - 1
    ));
    assert!(matches!(
        phone.light.ingest(BOOK, from_laptop.clone(), Some(1)),
        Err(Error::Full { .. })
    ));
    assert!(matches!(
        phone.light.install(BOOK, &next, Vec::new()),
        Err(Error::Full { .. })
    ));
    assert_eq!(phone.light.store().rows().unwrap(), rows);
    assert_eq!(phone.light.outbox(BOOK).unwrap().len(), outbox);
    assert_eq!(phone.light.have(BOOK).unwrap(), have);
    assert_eq!(phone.light.cursor(BOOK).unwrap(), None);
    assert_eq!(phone.labels(), [(1, "phone".to_string())]);
    // A reopened store holds the same: nothing was half-written.
    drop(phone.light);
    let light = Light::open(phone._dir.path(), &agent, config).unwrap();
    let phone = Device { light, ..phone };
    assert_eq!(phone.light.store().rows().unwrap(), rows);

    free.store(vos_light::RESERVE_BYTES, Ordering::SeqCst);
    phone.done("label", (3u32, "tablet".to_string()).encode());
    let ingested = phone.light.ingest(BOOK, from_laptop, Some(1)).unwrap();
    assert_eq!(ingested.nodes.applied.len(), 1);
    assert_eq!(phone.light.cursor(BOOK).unwrap(), Some(1));
    assert_eq!(
        phone.labels(),
        [
            (1, "phone".to_string()),
            (2, "laptop".to_string()),
            (3, "tablet".to_string())
        ]
    );
}

/// An author signs two forks at one number, and two devices meet them in
/// opposite orders: both apply both, filtered at read from the fork's
/// number, so both read the same, and neither quarantines.
#[test]
fn forks_met_in_either_order_read_the_same() {
    let agent = agent();
    let (first, _) = device_books();
    let phone = Device::new(&agent, &first);
    let laptop = Device::new(&agent, &first);
    let label = phone.method("label");
    let forker = SigningKey::from_bytes(&[5; 32]);
    let base = node(
        &forker,
        0,
        vec![
            call(label, 1, (1u32, "one".to_string()).encode()),
            call(label, 1, (2u32, "two".to_string()).encode()),
        ],
        BTreeSet::new(),
    );
    let after = BTreeSet::from([cid(&base)]);
    let left = node(
        &forker,
        1,
        vec![call(label, 1, (1u32, "left".to_string()).encode())],
        after.clone(),
    );
    let right = node(
        &forker,
        1,
        vec![call(label, 1, (2u32, "right".to_string()).encode())],
        after,
    );
    for (device, forks) in [(&phone, [&left, &right]), (&laptop, [&right, &left])] {
        device.light.ingest(BOOK, [base.clone()], None).unwrap();
        for fork in forks {
            let ingested = device.light.ingest(BOOK, [fork.clone()], None).unwrap();
            assert!(ingested.quarantined.is_empty());
        }
    }
    assert_eq!(phone.labels(), laptop.labels());
}

/// The install's replay meets a full disk: the install stands, and the
/// release's operations stay held until a replay with room runs them.
/// Release 0 is no release.
#[test]
fn an_install_stands_when_its_replay_finds_no_room() {
    let agent = agent();
    let (first, next) = device_books();
    // The checks of room the disk answers yes to, then no.
    let roomy = Arc::new(AtomicU64::new(u64::MAX));
    let probe = Arc::clone(&roomy);
    let config = Config {
        disk: Disk::Probe(Arc::new(move || {
            match probe.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            }) {
                Ok(_) => u64::MAX,
                Err(_) => 0,
            }
        })),
    };
    let older = Device::with(&agent, &first, config);
    let newer = Device::new(&agent, &next);
    newer.done("retire", 9u32.encode());
    older.light.ingest(BOOK, newer.push(), None).unwrap();
    assert_eq!(older.light.held(BOOK).unwrap().len(), 1);

    let unnumbered = Package {
        release: 0,
        ..next.clone()
    };
    assert!(matches!(
        older.light.install(BOOK, &unnumbered, Vec::new()),
        Err(Error::Package)
    ));
    // Room for the install's check alone.
    roomy.store(1, Ordering::SeqCst);
    let installed = older.light.install(BOOK, &next, Vec::new()).unwrap();
    assert!(matches!(installed, Outcome::Done(_)), "{installed:?}");
    let older = Device {
        package: next.clone(),
        ..older
    };
    assert_eq!(older.light.held(BOOK).unwrap().len(), 1);
    assert!(matches!(
        older.light.replay(BOOK),
        Err(Error::Full { free: 0 })
    ));
    roomy.store(u64::MAX, Ordering::SeqCst);
    let replayed = older.light.replay(BOOK).unwrap();
    assert_eq!(replayed.applied.len(), 1);
    assert!(older.light.held(BOOK).unwrap().is_empty());
    assert_eq!(older.query::<Vec<u32>>("retired", Vec::new()), [9]);
}
