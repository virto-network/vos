//! The JAM statements service's program (`statement-service.elf`, built by
//! `just check-no-std`) on the JAM-only host, refine and accumulate, each
//! item a work package's: a proof read from a 256 KiB extrinsic; every
//! golden fixture judged as every venue judges it; registrations, anchors
//! and an equivocation, which ends the space; the controller's controls;
//! a row that does not decode, or a write past the balance, trapping the
//! accumulate; and the rows aging out past `MaxRootAge`. The venue rules'
//! suite runs over the service's own refine and accumulate (`rules`).

#[path = "../../../tests/support/jam.rs"]
mod jam;
mod rig;
mod rules;

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use vos_pvm::ExitReason;
use vos_statement::Refusal;
use vos_statement::vos_anchor::{
    Anchor, MAX_ROOT_AGE_MS, RootKind, SpaceGenesis, SpaceId, WindowClock, register_digest,
    space_id,
};
use vos_statement::vos_pvm_final_verifier::{MAX_PROOF_BYTES, masked};
use vos_statement_service::config::{self, Config};
use vos_statement_service::item::{
    Control, Item, MAX_ROOTS, MAX_STATEMENT_BYTES, Op, Register, SignedControl, control_digest,
};
use vos_statement_service::state::{self, Storage, keys};
use vos_statement_service::verdict::{AnchorCode, ControlCode, RegisterCode};

use rig::{ACCUMULATE_GAS, EPOCH_MS, Rig, fixture, fixture_rig, load, submit};

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

/// An ended space's roots are not anchored, those anchored before
/// included: the valid statement at a venue that holds its roots and ended
/// its space is refused as unanchored.
#[test]
fn an_ended_spaces_roots_go_dark() {
    let valid = fixture("valid");
    let mut rig = fixture_rig(&valid);
    let space = valid.input.statement.space;
    let mut record = rig.space(&space).unwrap();
    record.ended = true;
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

/// `space`'s registration under its controller, signed by `founder`.
fn register(rig: &Rig, space: &Space, founder: &SigningKey) -> Vec<u8> {
    register_under(
        rig,
        space,
        founder,
        space.controller.verifying_key().to_bytes(),
    )
}

/// `space`'s registration under its controller, `founder` signing it
/// under `signed_for`.
fn register_under(rig: &Rig, space: &Space, founder: &SigningKey, signed_for: [u8; 32]) -> Vec<u8> {
    let digest = register_digest(&rig.venue(), &space.id, &signed_for);
    Item::Register(Register {
        genesis: space.genesis.clone(),
        controller: space.controller.verifying_key().to_bytes(),
        founder_key: founder.verifying_key().to_bytes(),
        signature: founder.sign(&digest).to_bytes(),
    })
    .encode()
}

/// `space` registered while window `start − 1` of its clock is open, so it
/// anchors from `start`, the rig's time then put back.
fn registered_from(rig: &mut Rig, space: &Space, start: u64) {
    let slot = rig.slot;
    let clock = space.genesis.clock;
    rig.at(clock.boundary(start - 1).unwrap() - clock.length_ms);
    let payload = register(rig, space, &space.founders[0]);
    assert_eq!(
        rig.code(payload, Vec::new()),
        RegisterCode::Registered as u32
    );
    assert_eq!(rig.space(&space.id).unwrap().start, start);
    rig.slot = slot;
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

/// A registration: a founding key's signature over its digest at this
/// venue under the controller it names; its genesis of 1 to 16 distinct
/// founders, none of small order, and a length the venue registers; once.
/// It anchors from the venue's next window, from window 0 before its
/// clock's origin.
#[test]
fn a_space_registers_once_from_the_venues_next_window() {
    let space = founded(3);
    let mut rig = live_rig(1_000);
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());

    let stranger = key(0x99);
    let payload = register(&rig, &space, &stranger);
    assert_eq!(code(&mut rig, payload), RegisterCode::Founder as u32);
    let payload = register_under(&rig, &space, &space.founders[1], [0xc1; 32]);
    assert_eq!(
        code(&mut rig, payload),
        RegisterCode::Founder as u32,
        "signed under another controller"
    );
    let mut wide = founded(17);
    wide.id = space_id(&wide.genesis);
    let payload = register(&rig, &wide, &wide.founders[0]);
    assert_eq!(code(&mut rig, payload), RegisterCode::Genesis as u32);
    let mut short = founded(1);
    short.genesis.clock.length_ms = 60_000;
    short.id = space_id(&short.genesis);
    let payload = register(&rig, &short, &short.founders[0]);
    assert_eq!(code(&mut rig, payload), RegisterCode::Genesis as u32);
    for (name, second) in [
        ("twice", space.genesis.nodes[0].1),
        ("small order", {
            let mut identity = [0; 32];
            identity[0] = 1;
            identity
        }),
    ] {
        let mut odd = founded(2);
        odd.genesis.nodes[1].1 = second;
        odd.id = space_id(&odd.genesis);
        let payload = register(&rig, &odd, &odd.founders[0]);
        assert_eq!(
            code(&mut rig, payload),
            RegisterCode::Genesis as u32,
            "{name}"
        );
    }

    let payload = register(&rig, &space, &space.founders[1]);
    let landed = rig.item(payload, Vec::new());
    assert_eq!(landed.outcome.code, RegisterCode::Registered as u32);
    assert_eq!(landed.outcome.subject, space.id.0);
    eprintln!(
        "register: refine {:.2}M gas, accumulate {} gas",
        landed.refine as f64 / 1e6,
        landed.accumulate
    );
    let record = rig.space(&space.id).unwrap();
    assert_eq!(record.start, 1_001, "the venue's next window");
    assert_eq!(record.keys.len(), 3);
    assert_eq!(
        record.controller,
        space.controller.verifying_key().to_bytes()
    );
    let again = register(&rig, &space, &space.founders[0]);
    assert_eq!(code(&mut rig, again), RegisterCode::Again as u32);

    let mut early = founded(1);
    early.genesis.clock.origin_ms = rig.now() + 1;
    early.id = space_id(&early.genesis);
    let payload = register(&rig, &early, &early.founders[0]);
    assert_eq!(code(&mut rig, payload), RegisterCode::Registered as u32);
    assert_eq!(rig.space(&early.id).unwrap().start, 0);
}

/// Pin D's anchor rule at the venue's time: a registered space; a key of
/// its; the signature over its digest at this venue; the window at or past
/// the space's first, past `Last` and before `now_w`; no older than
/// `MaxRootAge`; the same root again a repeat.
#[test]
fn anchors_follow_the_venue_rules() {
    let space = founded(2);
    let mut rig = live_rig(1_000);
    let founder = &space.founders[0];
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());

    let payload = anchor(&rig, &space.id, 998, 1, founder);
    assert_eq!(code(&mut rig, payload), AnchorCode::Unregistered as u32);
    registered_from(&mut rig, &space, 990);

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
        "before its first window"
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
    registered_from(&mut late, &space, 990);
    late.at(CLOCK.boundary(995).unwrap() + MAX_ROOT_AGE_MS + 1);
    let payload = anchor(&late, &space.id, 995, 1, founder);
    assert_eq!(code(&mut late, payload), AnchorCode::Age as u32);
    late.at(CLOCK.boundary(995).unwrap() + MAX_ROOT_AGE_MS);
    let payload = anchor(&late, &space.id, 995, 1, founder);
    assert_eq!(code(&mut late, payload), 0, "at MaxRootAge exactly");
}

/// A second root for a window held is kept as evidence, with both signers,
/// whoever submits it, and ends the space for good: its anchors refused
/// after, its registration refused again, its controls still taken.
#[test]
fn a_second_root_is_evidence_and_ends_the_space() {
    let space = founded(2);
    let mut rig = live_rig(1_000);
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());
    registered_from(&mut rig, &space, 990);
    let payload = anchor(&rig, &space.id, 998, 1, &space.founders[0]);
    assert_eq!(code(&mut rig, payload), 0);
    let other = anchor(&rig, &space.id, 998, 2, &space.founders[1]);
    assert_eq!(
        code(&mut rig, other.clone()),
        AnchorCode::Equivocation as u32
    );
    assert!(rig.space(&space.id).unwrap().ended);
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
    assert_eq!(code(&mut rig, payload), AnchorCode::Ended as u32);
    assert_eq!(code(&mut rig, other), AnchorCode::Ended as u32);
    let again = register(&rig, &space, &space.founders[0]);
    assert_eq!(code(&mut rig, again), RegisterCode::Again as u32);
    let op = Op::SetController(key(0xc1).verifying_key().to_bytes());
    let payload = control(&rig, &space.id, 0, op, &space.controller);
    assert_eq!(code(&mut rig, payload), ControlCode::Done as u32);
}

/// A control of `space` at `nonce`, signed by `by`.
fn control(rig: &Rig, space: &SpaceId, nonce: u64, op: Op, by: &SigningKey) -> Vec<u8> {
    let control = Control {
        space: *space,
        nonce,
        op,
    };
    Item::Control(SignedControl {
        control,
        controller: by.verifying_key().to_bytes(),
        signature: by.sign(&control_digest(&rig.venue(), &control)).to_bytes(),
    })
    .encode()
}

/// The controller's key controls, each at the space's next nonce: a key
/// added anchors, a replay of its control refused, a key removed anchors
/// no more; one of small order never listed; at most `MAX_FOUNDING_KEYS`.
#[test]
fn the_controller_adds_and_removes_keys() {
    let space = founded(2);
    let mut rig = live_rig(1_000);
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());
    let first = &space.founders[0];
    let controller = &space.controller;
    let rotated = key(0x33);
    let add = Op::AddKey(rotated.verifying_key().to_bytes());
    let payload = control(&rig, &space.id, 0, add, controller);
    assert_eq!(code(&mut rig, payload), ControlCode::Unregistered as u32);
    registered_from(&mut rig, &space, 990);

    let payload = control(&rig, &space.id, 0, add, first);
    assert_eq!(code(&mut rig, payload), ControlCode::Controller as u32);
    let mut forged = Item::decode(&control(&rig, &space.id, 0, add, controller)).unwrap();
    if let Item::Control(signed) = &mut forged {
        signed.control.nonce = 1;
    }
    assert_eq!(
        code(&mut rig, forged.encode()),
        ControlCode::Signature as u32
    );
    let payload = control(&rig, &space.id, 1, add, controller);
    assert_eq!(code(&mut rig, payload), ControlCode::Nonce as u32, "ahead");
    let added = control(&rig, &space.id, 0, add, controller);
    let landed = rig.item(added.clone(), Vec::new());
    assert_eq!(landed.outcome.code, ControlCode::Done as u32);
    eprintln!(
        "control: refine {:.2}M gas, accumulate {} gas",
        landed.refine as f64 / 1e6,
        landed.accumulate
    );
    let payload = anchor(&rig, &space.id, 997, 1, &rotated);
    assert_eq!(code(&mut rig, payload), 0, "the added key anchors");
    let remove = Op::RemoveKey(rotated.verifying_key().to_bytes());
    let payload = control(&rig, &space.id, 1, remove, controller);
    assert_eq!(code(&mut rig, payload), 0);
    assert_eq!(
        code(&mut rig, added),
        ControlCode::Nonce as u32,
        "a replayed add does not list the key again"
    );
    let payload = anchor(&rig, &space.id, 998, 1, &rotated);
    assert_eq!(code(&mut rig, payload), AnchorCode::Key as u32);
    let payload = control(&rig, &space.id, 2, remove, controller);
    assert_eq!(
        code(&mut rig, payload),
        ControlCode::Key as u32,
        "not listed"
    );
    let mut identity = [0; 32];
    identity[0] = 1;
    let payload = control(&rig, &space.id, 2, Op::AddKey(identity), controller);
    assert_eq!(
        code(&mut rig, payload),
        ControlCode::Key as u32,
        "small order"
    );
    // At most `MAX_FOUNDING_KEYS` listed.
    for nonce in 2..2 + 14 {
        let op = Op::AddKey(key(nonce as u8 + 0x40).verifying_key().to_bytes());
        let payload = control(&rig, &space.id, nonce, op, controller);
        assert_eq!(code(&mut rig, payload), 0, "{nonce}");
    }
    let op = Op::AddKey(key(0xfe).verifying_key().to_bytes());
    let payload = control(&rig, &space.id, 16, op, controller);
    assert_eq!(code(&mut rig, payload), ControlCode::Key as u32, "the 17th");
}

/// The controller hands the space to another key: the old one refused
/// after, the new one taken.
#[test]
fn the_controller_hands_the_space_over() {
    let space = founded(1);
    let mut rig = live_rig(1_000);
    let code = |rig: &mut Rig, payload| rig.code(payload, Vec::new());
    registered_from(&mut rig, &space, 990);
    let (controller, successor) = (&space.controller, key(0xc1));
    let op = Op::SetController(successor.verifying_key().to_bytes());
    let payload = control(&rig, &space.id, 0, op, controller);
    assert_eq!(code(&mut rig, payload), 0);
    let remove = Op::RemoveKey(space.founders[0].verifying_key().to_bytes());
    let payload = control(&rig, &space.id, 1, remove, controller);
    assert_eq!(code(&mut rig, payload), ControlCode::Controller as u32);
    let payload = control(&rig, &space.id, 1, remove, &successor);
    assert_eq!(code(&mut rig, payload), 0);
}

/// A statement reading more than `MAX_ROOTS` roots is refused at refine as
/// undecodable, its proof unread.
#[test]
fn a_statement_of_too_many_roots_is_refused() {
    let valid = fixture("valid");
    let mut rig = fixture_rig(&valid);
    let mut statement = valid.input.statement.clone();
    let root = statement.roots[0];
    statement.roots = vec![root; MAX_ROOTS + 1];
    let landed = rig.item(submit(&statement.encode()), vec![valid.proof.clone()]);
    assert_eq!(landed.outcome.code, 1);
    assert!(landed.refine < 1_000_000, "{} gas", landed.refine);
}

/// Each package's outcome is its own: a package of the same payload with
/// a junk proof does not overwrite the accepted one's.
#[test]
fn a_later_package_of_the_same_payload_keeps_its_own_outcome() {
    let valid = fixture("valid");
    let mut rig = fixture_rig(&valid);
    let payload = submit(&valid.input.statement.encode());
    let accepted = rig.item(payload.clone(), vec![valid.proof.clone()]);
    let junk = rig.item(payload, vec![vec![0; 16]]);
    assert_ne!(accepted.id, junk.id);
    assert_eq!(junk.outcome.code >> 8, 1);
    assert_eq!(
        state::outcome(&mut rig.storage, &accepted.id).unwrap().code,
        0
    );
}

/// A storage past what the service's balance holds answers `write` `FULL`:
/// the program traps, so a JAM node reverts the whole accumulate.
#[test]
fn a_full_storage_traps_the_accumulate() {
    use vos_pvm::accumulate_host::ServiceStorage;
    struct Full(BTreeMap<Vec<u8>, Vec<u8>>);
    impl ServiceStorage for Full {
        fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.0.get(key).cloned()
        }
        fn write(&mut self, key: &[u8], value: Option<&[u8]>) -> Option<usize> {
            let previous = match value {
                Some(value) => self.0.insert(key.to_vec(), value.to_vec()),
                None => self.0.remove(key),
            };
            previous.map(|value| value.len())
        }
        fn full(&self, key: &[u8], _: Option<&[u8]>) -> bool {
            key[0] == keys::SEEN
        }
    }
    let valid = fixture("valid");
    let mut rig = fixture_rig(&valid);
    let payload = submit(&valid.input.statement.encode());
    let input = rig.operand(&payload, vec![valid.proof.clone()], [1; 32]);
    let mut full = Full(std::mem::take(&mut rig.storage));
    let (exit, _) = jam::accumulate(
        &rig.prepared,
        rig.slot,
        u64::from(rig.service),
        &[input],
        &mut full,
        ACCUMULATE_GAS,
    );
    assert_eq!(exit, ExitReason::Panic);
}

/// A row of the service's own that does not decode is a fault: reading it,
/// the program traps, so the accumulate reverts rather than take it as
/// absent.
#[test]
fn an_undecodable_row_traps_the_accumulate() {
    let space = founded(1);
    let mut rig = live_rig(1_000);
    rig.storage.write(&keys::space(&space.id), Some(&[1, 2, 3]));
    let payload = anchor(&rig, &space.id, 998, 1, &space.founders[0]);
    let input = rig.operand(&payload, Vec::new(), [2; 32]);
    let (exit, _) = jam::accumulate(
        &rig.prepared,
        rig.slot,
        u64::from(rig.service),
        &[input],
        &mut rig.storage,
        ACCUMULATE_GAS,
    );
    assert_eq!(exit, ExitReason::Panic);
}

// ── Aging out ─────────────────────────────────────────────────────────────

/// Past `MaxRootAge`, an anchor, a statement's `Seen` entry and an item's
/// outcome are dropped, a few each accumulate once their hour is over:
/// replayed, the statement is refused as unanchored.
#[test]
fn rows_age_out_past_max_root_age() {
    let valid = fixture("valid");
    let mut rig = fixture_rig(&valid);

    let rooted = submit(&valid.input.statement.encode());
    let landed = rig.item(rooted.clone(), vec![valid.proof.clone()]);
    assert_eq!(landed.outcome.code, 0);
    let id = valid.input.statement.id();
    let expiry = state::seen(&mut rig.storage, &id).unwrap();
    assert_eq!(
        expiry,
        CLOCK_FIXTURE.boundary(42).unwrap() + MAX_ROOT_AGE_MS
    );

    // An anchor of a space on the fixtures' clock, queued too.
    let space = founded_on(1, CLOCK_FIXTURE);
    registered_from(&mut rig, &space, 40);
    let anchored = anchor(&rig, &space.id, 41, 9, &space.founders[0]);
    let anchored = rig.item(anchored, Vec::new());
    assert_eq!(anchored.outcome.code, 0);
    assert!(state::anchor(&mut rig.storage, &space.id, RootKind::Space, 41).is_some());

    // Past every expiry's hour, packages of an item each until the queue
    // is drained.
    rig.at(expiry + 2 * 3_600_000);
    for _ in 0..16 {
        rig.item(vec![9], Vec::new());
    }
    assert_eq!(state::seen(&mut rig.storage, &id), None, "dropped");
    assert!(state::anchor(&mut rig.storage, &space.id, RootKind::Space, 41).is_none());
    assert_eq!(state::outcome(&mut rig.storage, &anchored.id), None);
    assert!(rig.space(&space.id).is_some(), "a space is never dropped");
    let hour = rig.now() / 3_600_000;
    let queued = rig.storage.keys().filter(|key| key[0] == keys::QUEUED);
    assert!(
        queued
            .map(|key| u64::from_be_bytes(key[1..9].try_into().unwrap()))
            .all(|bucket| bucket >= hour),
        "the queue drained to the hour"
    );

    let replay = rig.item(rooted, vec![valid.proof.clone()]);
    assert_eq!(replay.outcome.code, Refusal::Unanchored.code());
}

// Every row queued expires within a day of its queueing, the horizon a
// client reading the queue scans.
const _: () = assert!(vos_statement_service::accumulate::OUTCOME_KEEP_MS >= MAX_ROOT_AGE_MS);

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
