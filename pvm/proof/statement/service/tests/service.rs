//! The JAM statements service's program (`statement-service.elf`, built by
//! `just check-no-std`) on the JAM-only host, refine and accumulate, each
//! item a work package's: a proof read from a 256 KiB extrinsic; every
//! golden fixture judged as every venue judges it; registrations, anchors
//! (an unregistered key, an equivocation), migrations; and the rows aging
//! out past `MaxRootAge`, a rootless statement's `Seen` entry never.

#[path = "../../tests/support/jam.rs"]
mod jam;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ed25519_dalek::{Signer, SigningKey};
use vos_pvm::ExitReason;
use vos_pvm::refine::PreparedProgram;
use vos_pvm::refine_host::{JamItem, JamRefine};
use vos_statement::fixtures::{self, Fixture};
use vos_statement::model::{Policy, Range};
use vos_statement::vos_anchor::{
    Anchor, MAX_ROOT_AGE_MS, Migrate, RootKind, SpaceGenesis, SpaceId, VenueId, WindowClock,
    register_digest, space_id,
};
use vos_statement::vos_pvm_final_verifier::{MAX_PROOF_BYTES, masked};
use vos_statement::{Pin, Refusal, blake2b_256};
use vos_statement_service::config::{self, Config, configure};
use vos_statement_service::item::{
    Item, MAX_STATEMENT_BYTES, Register, SignedMigrate, migrate_digest,
};
use vos_statement_service::state::{self, AnchorRecord, Outcome, SpaceRecord, Storage, keys};
use vos_statement_service::verdict::{AnchorCode, MigrateCode, RegisterCode};
use vos_statement_service::{MAX_VERDICT_BYTES, SLOT_MS};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};

/// The JAM chain the fixtures' venues are services of
/// (`VenueId::jam(&[0x4A; 32], 7)`, and 8 for another venue), timed from
/// the Unix epoch as the fixtures' venues are.
const GENESIS: [u8; 32] = [0x4A; 32];
/// Gray Paper 0.8.0's common era: a live chain's genesis time.
const EPOCH_MS: u64 = 1_735_732_800_000;
/// A package's refine gas: PolkaJam's testnet's.
const REFINE_GAS: u64 = 1_000_000_000;
/// A report's accumulate gas.
const ACCUMULATE_GAS: u64 = 10_000_000;

/// The service's program as linked, unconfigured.
fn linked() -> &'static [u8] {
    static PROGRAM: OnceLock<Vec<u8>> = OnceLock::new();
    PROGRAM.get_or_init(|| jam::guest("statement-service").0)
}

/// What an item came to: its outcome, and the gas its refine and the
/// package's accumulate took.
#[derive(Debug)]
struct Landed {
    outcome: Outcome,
    refine: u64,
    accumulate: u64,
}

/// The service on the JAM-only host, its storage in memory, at a slot.
struct Rig {
    config: Config,
    program: Vec<u8>,
    prepared: PreparedProgram,
    service: u32,
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
    slot: u64,
}

impl Rig {
    fn new(config: Config, service: u32) -> Self {
        let mut program = linked().to_vec();
        configure(&mut program, &config).expect("one configuration block");
        let prepared = PreparedProgram::new(&program).expect("the program");
        Self {
            config,
            program,
            prepared,
            service,
            storage: BTreeMap::new(),
            slot: 0,
        }
    }

    fn venue(&self) -> VenueId {
        VenueId::jam(&self.config.genesis, self.service)
    }

    /// The venue's time now.
    fn now(&self) -> u64 {
        self.config.genesis_ms + self.slot * SLOT_MS
    }

    /// The slot holding `time`, or the first after it.
    fn at(&mut self, time: u64) {
        self.slot = (time - self.config.genesis_ms).div_ceil(SLOT_MS);
    }

    /// A work package of `items`, each a payload and its extrinsics, refined
    /// then accumulated: each item's outcome.
    fn package(&mut self, items: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Vec<Landed> {
        let jam_items: Vec<JamItem> = items
            .iter()
            .map(|(payload, extrinsics)| JamItem {
                payload: payload.clone(),
                extrinsics: extrinsics.clone(),
                ..JamItem::default()
            })
            .collect();
        let package_hash =
            blake2b_256(&[&items.iter().map(|(p, _)| p.len() as u8).collect::<Vec<_>>()]);
        let mut inputs = Vec::new();
        let mut refines = Vec::new();
        for (index, (payload, _)) in items.iter().enumerate() {
            let args = RefineArgs {
                core: 0,
                item: index as u64,
                service: u64::from(self.service),
                payload: payload.clone(),
                package_hash,
            };
            let jam = JamRefine {
                service: u64::from(self.service),
                items: jam_items.clone(),
                item: index,
                ..JamRefine::default()
            };
            let refined = jam::refine(&self.program, &args.encode(), jam, REFINE_GAS);
            assert_eq!(refined.exit, ExitReason::Halt, "refine");
            assert!(refined.output.len() <= MAX_VERDICT_BYTES);
            refines.push(refined.gas);
            let operand = Operand {
                package_hash,
                segment_root: [0; 32],
                authorizer: [0; 32],
                payload_hash: blake2b_256(&[payload]),
                gas_limit: ACCUMULATE_GAS,
                result: Ok(refined.output),
                auth_trace: Vec::new(),
            };
            inputs.push(AccumulateInput::Operand(operand).encode());
        }
        let (exit, accumulate) = jam::accumulate(
            &self.prepared,
            self.slot,
            u64::from(self.service),
            &inputs,
            &mut self.storage,
            ACCUMULATE_GAS,
        );
        assert_eq!(exit, ExitReason::Halt, "accumulate");
        items
            .iter()
            .zip(refines)
            .map(|((payload, _), refine)| Landed {
                outcome: state::outcome(&mut self.storage, &blake2b_256(&[payload]))
                    .expect("an outcome"),
                refine,
                accumulate,
            })
            .collect()
    }

    /// A package of the one item `payload`, with `extrinsics`.
    fn item(&mut self, payload: Vec<u8>, extrinsics: Vec<Vec<u8>>) -> Landed {
        self.package(&[(payload, extrinsics)]).remove(0)
    }

    /// The item's code, and its outcome's time the venue's.
    fn code(&mut self, payload: Vec<u8>, extrinsics: Vec<Vec<u8>>) -> u32 {
        let landed = self.item(payload, extrinsics);
        assert_eq!(landed.outcome.time, self.now());
        landed.outcome.code
    }

    fn space(&mut self, space: &SpaceId) -> Option<SpaceRecord> {
        state::space(&mut self.storage, space)
    }

    /// The storage holding `policy`'s spaces, anchors and `Seen` entries,
    /// as a venue whose state the fixture names: each space with no key,
    /// each anchor signed by none.
    fn hold(&mut self, policy: &Policy) {
        for space in &policy.spaces {
            let record = SpaceRecord {
                clock: space.clock,
                controller: [0; 32],
                keys: Vec::new(),
                range: space.range,
                last: None,
                suspended: false,
            };
            self.storage
                .write(&keys::space(&space.id), Some(&record.encode()));
        }
        for root in &policy.anchors {
            let record = AnchorRecord {
                root: root.root,
                signer: [0; 32],
            };
            let key = keys::anchor(&root.space, root.kind, root.window);
            self.storage.write(&key, Some(&record.encode()));
        }
        for (id, expiry) in &policy.seen {
            self.storage
                .write(&keys::seen(id), Some(&expiry.to_le_bytes()));
        }
    }
}

/// The fixtures' configuration, pinning `pins`.
fn fixture_config(pins: Vec<Pin>) -> Config {
    Config {
        genesis: GENESIS,
        genesis_ms: 0,
        pins,
    }
}

fn load() -> Vec<Fixture> {
    fixtures::load(&fixtures::directory())
}

fn fixture(name: &str) -> Fixture {
    load()
        .into_iter()
        .find(|fixture| fixture.name == name)
        .unwrap_or_else(|| panic!("the fixture {name:?}"))
}

/// A rig of `fixture`'s venue: its pin, its state, its time, the service
/// whose venue it names.
fn fixture_rig(fixture: &Fixture) -> Rig {
    fixture_rig_pinning(fixture, vec![fixture.input.pin])
}

/// A rig of `fixture`'s venue pinning `pins`.
fn fixture_rig_pinning(fixture: &Fixture, pins: Vec<Pin>) -> Rig {
    let policy = &fixture.input.policy;
    let service = (0..=u16::MAX as u32)
        .find(|&service| VenueId::jam(&GENESIS, service) == policy.venue)
        .expect("a JAM venue's id");
    let mut rig = Rig::new(fixture_config(pins), service);
    rig.hold(policy);
    rig.at(policy.now_ms);
    rig
}

fn submit(statement: &[u8]) -> Vec<u8> {
    Item::Submit(statement.to_vec()).encode()
}

/// The proof is the `Submit` item's first extrinsic, read whole: the valid
/// fixture's accepted; 256 KiB, `MAX_PROOF_BYTES`, read and refused by the
/// verifier; a byte more refused by its length before it is read; none, as
/// an empty proof.
#[test]
fn a_256_kib_extrinsic_is_read_as_the_proof() {
    let valid = fixture("valid");
    let statement = valid.input.statement.encode();
    let mut rig = fixture_rig(&valid);
    let landed = rig.item(submit(&statement), vec![valid.proof.clone()]);
    assert_eq!(landed.outcome.code, 0);
    assert_eq!(landed.outcome.subject, valid.input.statement.id().0);
    eprintln!(
        "valid, {} B proof: refine {:.2}M gas by the host, {:.2}M by its own count; accumulate \
         {} gas",
        valid.proof.len(),
        landed.refine as f64 / 1e6,
        landed.outcome.refine_gas as f64 / 1e6,
        landed.accumulate
    );
    assert!(landed.refine <= 150_000_000, "{}", landed.refine);

    let length = Refusal::Proof(vos_statement::vos_pvm_final_verifier::Error::Length).code();
    let mut rig = fixture_rig(&valid);
    let full = rig.item(submit(&statement), vec![vec![0x5a; MAX_PROOF_BYTES]]);
    assert_eq!(full.outcome.code >> 8, 1, "the proof's class");
    assert_ne!(full.outcome.code, length);
    let over = rig.item(submit(&statement), vec![vec![0x5a; MAX_PROOF_BYTES + 1]]);
    assert_eq!(over.outcome.code, length);
    let none = rig.item(submit(&statement), Vec::new());
    assert_eq!(none.outcome.code >> 8, 1, "an empty proof's");
    eprintln!(
        "a {} B extrinsic read: refine {} gas; a byte more, unread: {} gas; none: {} gas",
        MAX_PROOF_BYTES, full.refine, over.refine, none.refine
    );
    assert!(full.refine > over.refine + 96 * 256, "the 256 KiB fetched");
}

/// Every golden fixture, at a service of its venue's configured with its
/// pin and holding its venue's state, at its time: the verdict every venue
/// reaches under the formats the service links (39 alone), and an
/// accepted statement's id.
#[test]
fn every_fixture_is_judged_by_the_service_as_recorded() {
    for fixture in load() {
        let expected = fixture.verdict_linking(&[masked::FORMAT]);
        let mut rig = fixture_rig(&fixture);
        let statement = fixture.input.statement.encode();
        let landed = rig.item(submit(&statement), vec![fixture.proof.clone()]);
        eprintln!(
            "{}: {:#x}, refine {:.2}M gas, accumulate {} gas",
            fixture.name,
            landed.outcome.code,
            landed.refine as f64 / 1e6,
            landed.accumulate
        );
        assert_eq!(landed.outcome.code, expected, "{}", fixture.name);
        if expected == 0 {
            assert_eq!(landed.outcome.subject, fixture.input.statement.id().0);
            let id = fixture.input.statement.id();
            assert!(state::seen(&mut rig.storage, &id).is_some());
        }
    }
}

/// A suspended space's roots are not anchored, those anchored before
/// included: the valid statement at a venue that holds its roots and
/// suspended its space is refused as unanchored.
#[test]
fn a_suspended_spaces_roots_go_dark() {
    let valid = fixture("valid");
    let mut rig = fixture_rig(&valid);
    let space = valid.input.statement.space;
    let mut record = rig.space(&space).unwrap();
    record.suspended = true;
    rig.storage
        .write(&keys::space(&space), Some(&record.encode()));
    let code = rig.code(
        submit(&valid.input.statement.encode()),
        vec![valid.proof.clone()],
    );
    assert_eq!(code, Refusal::Unanchored.code());
}

/// An item that does not decode, a statement that does not, and one past
/// `MAX_STATEMENT_BYTES`, each refused at refine with no proof read: the
/// statements as undecodable, code 1, as Kreivo's pallet refuses them.
#[test]
fn what_does_not_decode_is_refused() {
    let valid = fixture("valid");
    let mut rig = fixture_rig(&valid);
    let unknown = rig.item(vec![9, 1, 2], Vec::new());
    assert_eq!((unknown.outcome.kind, unknown.outcome.code), (u8::MAX, 1));
    let statement = valid.input.statement.encode();
    let short = rig.code(
        submit(&statement[..statement.len() - 1]),
        vec![valid.proof.clone()],
    );
    assert_eq!(short, 1);
    let mut long = valid.input.statement.clone();
    long.output = vec![0; MAX_STATEMENT_BYTES];
    let long = rig.code(submit(&long.encode()), vec![valid.proof.clone()]);
    assert_eq!(long, 1);
    let empty = rig.item(Vec::new(), Vec::new());
    assert_eq!((empty.outcome.kind, empty.outcome.code), (u8::MAX, 1));
}

// ── Spaces and anchors ────────────────────────────────────────────────────

/// A space's founders, its genesis and the service at a live chain's time.
struct Space {
    founders: Vec<SigningKey>,
    genesis: SpaceGenesis,
    id: SpaceId,
    controller: SigningKey,
}

/// A clock of ten-minute windows from the epoch's.
const CLOCK: WindowClock = WindowClock {
    origin_ms: EPOCH_MS,
    length_ms: 600_000,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn founded(founders: u8) -> Space {
    founded_on(founders, CLOCK)
}

/// A space of `founders` founders on `clock`.
fn founded_on(founders: u8, clock: WindowClock) -> Space {
    let founders: Vec<SigningKey> = (1..=founders).map(key).collect();
    let genesis = SpaceGenesis {
        version: 1,
        nodes: founders
            .iter()
            .enumerate()
            .map(|(number, key)| (number as u8, key.verifying_key().to_bytes()))
            .collect(),
        clock,
        time: clock.origin_ms,
        nonce: [7; 16],
    };
    Space {
        id: space_id(&genesis),
        founders,
        genesis,
        controller: key(0xc0),
    }
}

/// The service of a live chain, at window `w`'s start of [`CLOCK`].
fn live_rig(window: u64) -> Rig {
    let config = Config {
        genesis: [0x6a; 32],
        genesis_ms: EPOCH_MS,
        pins: Vec::new(),
    };
    let mut rig = Rig::new(config, 3);
    rig.at(CLOCK.boundary(window).unwrap() - CLOCK.length_ms);
    rig
}

fn register(rig: &Rig, space: &Space, founder: &SigningKey, start: u64) -> Vec<u8> {
    let controller = space.controller.verifying_key().to_bytes();
    let digest = register_digest(&rig.venue(), &space.id, &controller, start);
    Item::Register(Register {
        genesis: space.genesis.clone(),
        controller,
        start_window: start,
        founder_key: founder.verifying_key().to_bytes(),
        signature: founder.sign(&digest).to_bytes(),
    })
    .encode()
}

fn anchor(rig: &Rig, space: &SpaceId, window: u64, root: u8, signer: &SigningKey) -> Vec<u8> {
    let mut anchor = Anchor {
        space: *space,
        window,
        kind: RootKind::Space,
        root: [root; 32],
        signer: signer.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    anchor.signature = signer.sign(&anchor.digest(&rig.venue())).to_bytes();
    Item::Anchor(anchor).encode()
}

fn migrate(rig: &Rig, space: &SpaceId, to: VenueId, from_window: u64, by: &SigningKey) -> Vec<u8> {
    let migrate = Migrate {
        space: *space,
        from: rig.venue(),
        to,
        from_window,
    };
    Item::Migrate(SignedMigrate {
        migrate,
        controller: by.verifying_key().to_bytes(),
        signature: by.sign(&migrate_digest(&migrate)).to_bytes(),
    })
    .encode()
}

/// A registration: a founding key's signature over its digest at this
/// venue, its start window within `[now_w − MaxRootAge / length, now_w +
/// 1]`, its genesis of 1 to 16 founders and a length the venue registers;
/// once.
#[test]
fn a_space_registers_once_signed_by_a_founder_from_a_bounded_start() {
    let space = founded(3);
    let mut rig = live_rig(1_000);
    let back = MAX_ROOT_AGE_MS / CLOCK.length_ms;
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());

    let stranger = key(0x99);
    let payload = register(&rig, &space, &stranger, 1_000);
    assert_eq!(code(&mut rig, payload), RegisterCode::Founder as u32);
    let mut forged = Item::decode(&register(&rig, &space, &space.founders[1], 1_000)).unwrap();
    if let Item::Register(register) = &mut forged {
        register.start_window = 999;
    }
    assert_eq!(
        code(&mut rig, forged.encode()),
        RegisterCode::Signature as u32
    );
    for start in [1_000 - back - 1, 1_002] {
        let payload = register(&rig, &space, &space.founders[1], start);
        assert_eq!(
            code(&mut rig, payload),
            RegisterCode::Start as u32,
            "{start}"
        );
    }
    let mut wide = founded(17);
    wide.genesis.clock.length_ms = 600_000;
    let payload = register(&rig, &wide, &wide.founders[0], 1_000);
    assert_eq!(code(&mut rig, payload), RegisterCode::Genesis as u32);
    let mut short = founded(1);
    short.genesis.clock.length_ms = 60_000;
    short.id = space_id(&short.genesis);
    let payload = register(&rig, &short, &short.founders[0], 1_000);
    assert_eq!(code(&mut rig, payload), RegisterCode::Genesis as u32);
    let mut early = founded(1);
    early.genesis.clock.origin_ms = rig.now() + 1;
    early.id = space_id(&early.genesis);
    let payload = register(&rig, &early, &early.founders[0], 0);
    assert_eq!(code(&mut rig, payload), RegisterCode::Clock as u32);

    let payload = register(&rig, &space, &space.founders[1], 1_000 - back);
    let landed = rig.item(payload, Vec::new());
    assert_eq!(landed.outcome.code, RegisterCode::Registered as u32);
    assert_eq!(landed.outcome.subject, space.id.0);
    eprintln!(
        "register: refine {:.2}M gas, accumulate {} gas",
        landed.refine as f64 / 1e6,
        landed.accumulate
    );
    let record = rig.space(&space.id).unwrap();
    assert_eq!(
        record.range,
        Range {
            from: 1_000 - back,
            until: None
        }
    );
    assert_eq!(record.keys.len(), 3);
    assert_eq!(
        record.controller,
        space.controller.verifying_key().to_bytes()
    );
    let again = register(&rig, &space, &space.founders[0], 1_001);
    assert_eq!(code(&mut rig, again), RegisterCode::Again as u32);
}

/// Pin D's anchor rule at the venue's time: a registered space; a key of
/// its; the signature over its digest at this venue; `Last < w < now_w`;
/// no older than `MaxRootAge`; the same root again a repeat.
#[test]
fn anchors_follow_pin_ds_rule() {
    let space = founded(2);
    let mut rig = live_rig(1_000);
    let founder = &space.founders[0];
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());

    let payload = anchor(&rig, &space.id, 998, 1, founder);
    assert_eq!(code(&mut rig, payload), AnchorCode::Unregistered as u32);
    let payload = register(&rig, &space, founder, 990);
    assert_eq!(code(&mut rig, payload), 0);

    let stranger = key(0x99);
    let payload = anchor(&rig, &space.id, 998, 1, &stranger);
    assert_eq!(
        code(&mut rig, payload),
        AnchorCode::Key as u32,
        "an unregistered key"
    );
    let mut forged = Item::decode(&anchor(&rig, &space.id, 998, 1, founder)).unwrap();
    if let Item::Anchor(anchor) = &mut forged {
        anchor.root = [2; 32];
    }
    assert_eq!(
        code(&mut rig, forged.encode()),
        AnchorCode::Signature as u32
    );
    let elsewhere = Rig::new(rig.config.clone(), 4);
    let payload = anchor(&elsewhere, &space.id, 998, 1, founder);
    assert_eq!(
        code(&mut rig, payload),
        AnchorCode::Signature as u32,
        "another venue's"
    );
    for open in [1_000, 1_001] {
        let payload = anchor(&rig, &space.id, open, 1, founder);
        assert_eq!(code(&mut rig, payload), AnchorCode::Open as u32, "{open}");
    }
    let payload = anchor(&rig, &space.id, 989, 1, founder);
    assert_eq!(
        code(&mut rig, payload),
        AnchorCode::Window as u32,
        "before its start"
    );

    let payload = anchor(&rig, &space.id, 998, 1, founder);
    let landed = rig.item(payload.clone(), Vec::new());
    assert_eq!(landed.outcome.code, AnchorCode::New as u32);
    eprintln!(
        "anchor: refine {:.2}M gas, accumulate {} gas",
        landed.refine as f64 / 1e6,
        landed.accumulate
    );
    let held = state::anchor(&mut rig.storage, &space.id, RootKind::Space, 998).unwrap();
    assert_eq!(held.root, [1; 32]);
    assert_eq!(held.signer, founder.verifying_key().to_bytes());
    assert_eq!(rig.space(&space.id).unwrap().last, Some(998));
    let second = anchor(&rig, &space.id, 998, 1, &space.founders[1]);
    assert_eq!(code(&mut rig, second), AnchorCode::Again as u32);
    let payload = anchor(&rig, &space.id, 997, 1, founder);
    assert_eq!(
        code(&mut rig, payload),
        AnchorCode::Window as u32,
        "at or before Last"
    );
    let payload = anchor(&rig, &space.id, 999, 1, founder);
    assert_eq!(code(&mut rig, payload), 0, "a later window; gaps allowed");

    // A window whose boundary is past `MaxRootAge` by the venue's clock.
    let mut late = live_rig(1_000);
    let payload = register(&late, &space, founder, 990);
    assert_eq!(code(&mut late, payload), 0);
    late.at(CLOCK.boundary(995).unwrap() + MAX_ROOT_AGE_MS + 1);
    let payload = anchor(&late, &space.id, 995, 1, founder);
    assert_eq!(code(&mut late, payload), AnchorCode::Age as u32);
    late.at(CLOCK.boundary(995).unwrap() + MAX_ROOT_AGE_MS);
    let payload = anchor(&late, &space.id, 995, 1, founder);
    assert_eq!(code(&mut late, payload), 0, "at MaxRootAge exactly");
}

/// A second root for a window held is kept as evidence, with both signers,
/// whoever submits it, and suspends the space: its anchors refused after.
#[test]
fn a_second_root_is_evidence_and_suspends_the_space() {
    let space = founded(2);
    let mut rig = live_rig(1_000);
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());
    let payload = register(&rig, &space, &space.founders[0], 990);
    assert_eq!(code(&mut rig, payload), 0);
    let payload = anchor(&rig, &space.id, 998, 1, &space.founders[0]);
    assert_eq!(code(&mut rig, payload), 0);
    let other = anchor(&rig, &space.id, 998, 2, &space.founders[1]);
    assert_eq!(
        code(&mut rig, other.clone()),
        AnchorCode::Equivocation as u32
    );
    assert!(rig.space(&space.id).unwrap().suspended);
    let evidence = rig
        .storage
        .read(&keys::evidence(&space.id, RootKind::Space, 998))
        .unwrap();
    let evidence = state::Evidence::decode(&evidence).unwrap();
    assert_eq!(
        evidence.held.signer,
        space.founders[0].verifying_key().to_bytes()
    );
    assert_eq!(
        evidence.other.signer,
        space.founders[1].verifying_key().to_bytes()
    );
    assert_eq!(evidence.other.root, [2; 32]);
    let payload = anchor(&rig, &space.id, 999, 3, &space.founders[0]);
    assert_eq!(code(&mut rig, payload), AnchorCode::Suspended as u32);
    assert_eq!(code(&mut rig, other), AnchorCode::Suspended as u32);
}

/// A migration away: the controller's, once, to another venue, from a
/// window past every one anchored and not before the venue's next; the
/// space's anchors at or past it refused after.
#[test]
fn a_migration_ends_the_spaces_range_here() {
    let space = founded(1);
    let mut rig = live_rig(1_000);
    let founder = &space.founders[0];
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());
    let elsewhere = VenueId([0xee; 32]);
    let payload = migrate(&rig, &space.id, elsewhere, 1_005, &space.controller);
    assert_eq!(code(&mut rig, payload), MigrateCode::Unregistered as u32);
    let payload = register(&rig, &space, founder, 990);
    assert_eq!(code(&mut rig, payload), 0);
    let payload = anchor(&rig, &space.id, 998, 1, founder);
    assert_eq!(code(&mut rig, payload), 0);

    let payload = migrate(&rig, &space.id, elsewhere, 1_005, founder);
    assert_eq!(code(&mut rig, payload), MigrateCode::Controller as u32);
    let payload = migrate(&rig, &space.id, rig.venue(), 1_005, &space.controller);
    assert_eq!(code(&mut rig, payload), MigrateCode::Venue as u32);
    let mut forged = Item::decode(&migrate(
        &rig,
        &space.id,
        elsewhere,
        1_005,
        &space.controller,
    ))
    .unwrap();
    if let Item::Migrate(signed) = &mut forged {
        signed.migrate.from_window = 1_006;
    }
    assert_eq!(
        code(&mut rig, forged.encode()),
        MigrateCode::Signature as u32
    );
    for window in [998, 1_000] {
        let payload = migrate(&rig, &space.id, elsewhere, window, &space.controller);
        assert_eq!(
            code(&mut rig, payload),
            MigrateCode::Window as u32,
            "{window}"
        );
    }
    let payload = migrate(&rig, &space.id, elsewhere, 1_001, &space.controller);
    let landed = rig.item(payload, Vec::new());
    assert_eq!(landed.outcome.code, MigrateCode::Migrated as u32);
    eprintln!(
        "migrate: refine {:.2}M gas, accumulate {} gas",
        landed.refine as f64 / 1e6,
        landed.accumulate
    );
    assert_eq!(rig.space(&space.id).unwrap().range.until, Some(1_001));
    let payload = migrate(&rig, &space.id, elsewhere, 1_002, &space.controller);
    assert_eq!(code(&mut rig, payload), MigrateCode::AlreadyMigrated as u32);

    rig.at(CLOCK.boundary(1_002).unwrap());
    let payload = anchor(&rig, &space.id, 1_000, 1, founder);
    assert_eq!(code(&mut rig, payload), 0, "within its range");
    let payload = anchor(&rig, &space.id, 1_001, 1, founder);
    assert_eq!(
        code(&mut rig, payload),
        AnchorCode::Window as u32,
        "migrated"
    );
}

// ── Aging out ─────────────────────────────────────────────────────────────

/// Past `MaxRootAge`, an anchor, a rooted statement's `Seen` entry and an
/// item's outcome are dropped, a few each accumulate once their hour is
/// over; a rootless statement's `Seen` entry is kept: replayed, the rooted
/// statement is refused as unanchored and the rootless one as repeated.
#[test]
fn rows_age_out_past_max_root_age_and_a_rootless_entry_never() {
    let valid = fixture("valid");
    let rootless = fixture("rootless");
    let mut rig = fixture_rig_pinning(&valid, vec![valid.input.pin, rootless.input.pin]);

    let rooted = submit(&valid.input.statement.encode());
    let lone = submit(&rootless.input.statement.encode());
    let landed = rig.package(&[
        (rooted.clone(), vec![valid.proof.clone()]),
        (lone.clone(), vec![rootless.proof.clone()]),
    ]);
    assert_eq!([landed[0].outcome.code, landed[1].outcome.code], [0, 0]);
    let (rooted_id, lone_id) = (valid.input.statement.id(), rootless.input.statement.id());
    let expiry = state::seen(&mut rig.storage, &rooted_id).unwrap();
    assert_eq!(
        expiry,
        CLOCK_FIXTURE.boundary(42).unwrap() + MAX_ROOT_AGE_MS
    );
    assert_eq!(state::seen(&mut rig.storage, &lone_id), Some(u64::MAX));

    // An anchor of a space on the fixtures' clock, queued too.
    let space = founded_on(1, CLOCK_FIXTURE);
    let payload = register(&rig, &space, &space.founders[0], 40);
    assert_eq!(rig.code(payload, Vec::new()), 0);
    let anchored = anchor(&rig, &space.id, 41, 9, &space.founders[0]);
    assert_eq!(rig.code(anchored.clone(), Vec::new()), 0);
    assert!(state::anchor(&mut rig.storage, &space.id, RootKind::Space, 41).is_some());

    // Past every expiry's hour, packages of an item each until the queue
    // is drained.
    rig.at(expiry + 2 * 3_600_000);
    for _ in 0..16 {
        rig.item(vec![9], Vec::new());
    }
    assert_eq!(state::seen(&mut rig.storage, &rooted_id), None, "dropped");
    assert_eq!(
        state::seen(&mut rig.storage, &lone_id),
        Some(u64::MAX),
        "kept"
    );
    assert!(state::anchor(&mut rig.storage, &space.id, RootKind::Space, 41).is_none());
    assert_eq!(
        state::outcome(&mut rig.storage, &blake2b_256(&[&anchored])),
        None
    );
    let hour = rig.now() / 3_600_000;
    let queued = rig.storage.keys().filter(|key| key[0] == keys::QUEUED);
    assert!(
        queued
            .map(|key| u64::from_be_bytes(key[1..9].try_into().unwrap()))
            .all(|bucket| bucket >= hour),
        "the queue drained to the hour"
    );

    let replays = rig.package(&[
        (rooted, vec![valid.proof.clone()]),
        (lone, vec![rootless.proof.clone()]),
    ]);
    assert_eq!(replays[0].outcome.code, Refusal::Unanchored.code());
    assert_eq!(replays[1].outcome.code, Refusal::Repeated.code());
}

/// The fixtures' venue clock (`WindowClock::DEFAULT`).
const CLOCK_FIXTURE: WindowClock = WindowClock::DEFAULT;

/// The service's program within JAM's 4,000,000-byte bound on a service's
/// code, its only size bound, holding one configuration block, unset as
/// built.
#[test]
fn the_service_fits_jams_code_bound_with_one_configuration_block() {
    let (program, elf) = jam::guest("statement-service");
    eprintln!(
        "statement-service: program {} B (ELF {elf} B)",
        program.len()
    );
    assert!(program.len() <= 4_000_000, "{} bytes", program.len());
    let at: Vec<usize> = program
        .windows(config::MARKER.len())
        .enumerate()
        .filter(|(_, window)| *window == config::MARKER)
        .map(|(at, _)| at)
        .collect();
    assert_eq!(at.len(), 1);
    assert_eq!(&program[at[0]..at[0] + config::BYTES], &config::UNSET);
}
