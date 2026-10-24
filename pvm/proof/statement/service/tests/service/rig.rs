//! The service on the JAM-only host: a rig holding its storage in memory at
//! a slot, refining and accumulating work packages, and the fixtures' rigs.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use vos_pvm::ExitReason;
use vos_pvm::refine::PreparedProgram;
use vos_pvm::refine_host::{JamItem, JamRefine};
use vos_statement::fixtures::{self, Fixture};
use vos_statement::model::Policy;
use vos_statement::vos_anchor::{SpaceId, VenueId};
use vos_statement::{Pin, blake2b_256};
use vos_statement_service::config::{Config, configure};
use vos_statement_service::item::Item;
use vos_statement_service::state::{self, AnchorRecord, Outcome, SpaceRecord, Storage, keys};
use vos_statement_service::{MAX_VERDICT_BYTES, SLOT_MS};
use vos_wire::jam::{AccumulateInput, Operand, RefineArgs};

use crate::jam;

/// The JAM chain the fixtures' venues are services of
/// (`VenueId::jam(&[0x4A; 32], 7)`, and 8 for another venue), timed from
/// the Unix epoch as the fixtures' venues are.
pub(crate) const GENESIS: [u8; 32] = [0x4A; 32];
/// Gray Paper 0.8.0's common era: a live chain's genesis time.
pub(crate) const EPOCH_MS: u64 = 1_735_732_800_000;
/// A package's refine gas: PolkaJam's testnet's.
pub(crate) const REFINE_GAS: u64 = 1_000_000_000;
/// A report's accumulate gas.
pub(crate) const ACCUMULATE_GAS: u64 = 10_000_000;

/// The service's program as linked, unconfigured.
fn linked() -> &'static [u8] {
    static PROGRAM: OnceLock<Vec<u8>> = OnceLock::new();
    PROGRAM.get_or_init(|| jam::guest("statement-service").0)
}

/// What an item came to: its outcome, and the gas its refine and the
/// package's accumulate took.
#[derive(Debug)]
pub(crate) struct Landed {
    pub(crate) outcome: Outcome,
    /// Its outcome's id: its package's and its payload's hashes.
    pub(crate) id: [u8; 32],
    pub(crate) refine: u64,
    pub(crate) accumulate: u64,
}

/// The service on the JAM-only host, its storage in memory, at a slot.
pub(crate) struct Rig {
    pub(crate) config: Config,
    pub(crate) program: Vec<u8>,
    pub(crate) prepared: PreparedProgram,
    pub(crate) service: u32,
    pub(crate) storage: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(crate) slot: u64,
    /// The packages refined: each package's hash differs by it.
    packages: u64,
}

impl Rig {
    pub(crate) fn new(config: Config, service: u32) -> Self {
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
            packages: 0,
        }
    }

    pub(crate) fn venue(&self) -> VenueId {
        VenueId::jam(&self.config.genesis, self.service)
    }

    /// The venue's time now.
    pub(crate) fn now(&self) -> u64 {
        self.config.genesis_ms + self.slot * SLOT_MS
    }

    /// The slot holding `time`, or the first after it.
    pub(crate) fn at(&mut self, time: u64) {
        self.slot = (time - self.config.genesis_ms).div_ceil(SLOT_MS);
    }

    /// A work package of `items`, each a payload and its extrinsics, refined
    /// then accumulated: each item's outcome.
    pub(crate) fn package(&mut self, items: &[(Vec<u8>, Vec<Vec<u8>>)]) -> Vec<Landed> {
        let jam_items: Vec<JamItem> = items
            .iter()
            .map(|(payload, extrinsics)| JamItem {
                payload: payload.clone(),
                extrinsics: extrinsics.clone(),
                ..JamItem::default()
            })
            .collect();
        self.packages += 1;
        let package_hash = blake2b_256(&[&self.packages.to_le_bytes()]);
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
            .map(|((payload, _), refine)| {
                let id = state::outcome_id(&package_hash, &blake2b_256(&[payload]));
                Landed {
                    outcome: state::outcome(&mut self.storage, &id).expect("an outcome"),
                    id,
                    refine,
                    accumulate,
                }
            })
            .collect()
    }

    /// A package of the one item `payload`, with `extrinsics`.
    pub(crate) fn item(&mut self, payload: Vec<u8>, extrinsics: Vec<Vec<u8>>) -> Landed {
        self.package(&[(payload, extrinsics)]).remove(0)
    }

    /// The item's code, and its outcome's time the venue's.
    pub(crate) fn code(&mut self, payload: Vec<u8>, extrinsics: Vec<Vec<u8>>) -> u32 {
        let landed = self.item(payload, extrinsics);
        assert_eq!(landed.outcome.time, self.now());
        landed.outcome.code
    }

    pub(crate) fn space(&mut self, space: &SpaceId) -> Option<SpaceRecord> {
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
                equivocators: Vec::new(),
                nonce: 0,
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

pub(crate) fn load() -> Vec<Fixture> {
    fixtures::load(&fixtures::directory())
}

pub(crate) fn fixture(name: &str) -> Fixture {
    load()
        .into_iter()
        .find(|fixture| fixture.name == name)
        .unwrap_or_else(|| panic!("the fixture {name:?}"))
}

/// A rig of `fixture`'s venue: its pin, its state, its time, the service
/// whose venue it names.
pub(crate) fn fixture_rig(fixture: &Fixture) -> Rig {
    fixture_rig_pinning(fixture, vec![fixture.input.pin])
}

/// A rig of `fixture`'s venue pinning `pins`.
pub(crate) fn fixture_rig_pinning(fixture: &Fixture, pins: Vec<Pin>) -> Rig {
    let policy = &fixture.input.policy;
    let service = (0..=u16::MAX as u32)
        .find(|&service| VenueId::jam(&GENESIS, service) == policy.venue)
        .expect("a JAM venue's id");
    let mut rig = Rig::new(fixture_config(pins), service);
    rig.hold(policy);
    rig.at(policy.now_ms);
    rig
}

pub(crate) fn submit(statement: &[u8]) -> Vec<u8> {
    Item::Submit(statement.to_vec()).encode()
}
