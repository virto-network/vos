//! The venue rules' suite (`vos_anchor::suite`) over the service's own
//! refine and accumulate, run natively on a storage in memory: each item
//! refined, its verdict accumulated at the venue's time to the
//! millisecond, and its outcome's code mapped back to the rules' terms.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use vos_statement::vos_anchor::suite::{self, Answer, Harness};
use vos_statement::vos_anchor::venue::{AnchorRefusal, RegisterRefusal, Status};
use vos_statement::vos_anchor::{Anchor, RootRead, SpaceGenesis, SpaceId, VenueId};
use vos_statement_service::accumulate::{Operand, accumulate, anchored};
use vos_statement_service::config::Config;
use vos_statement_service::item::{Control, Item, Op, Register, SignedControl, control_digest};
use vos_statement_service::refine::{Extrinsics, refine, venue};
use vos_statement_service::state::{self, keys};
use vos_statement_service::verdict::{AnchorCode, ControlCode, RegisterCode};

/// The service's library, its storage in memory, timed to the millisecond.
struct Service {
    config: Config,
    storage: BTreeMap<Vec<u8>, Vec<u8>>,
    now: u64,
    items: u64,
}

/// The spaces' controller: on JAM an ed25519 key.
fn controller() -> SigningKey {
    SigningKey::from_bytes(&[0xc0; 32])
}

/// No extrinsic: the suite submits no statement.
struct None_;

impl Extrinsics for None_ {
    fn proof_len(&mut self) -> Option<usize> {
        None
    }

    fn proof(&mut self, _: usize) -> Vec<u8> {
        Vec::new()
    }
}

impl Service {
    fn new() -> Self {
        Self {
            config: Config {
                genesis: [0x6a; 32],
                genesis_ms: 0,
                pins: Vec::new(),
            },
            storage: BTreeMap::new(),
            now: 0,
            items: 0,
        }
    }

    /// `item` refined and accumulated at the venue's time: its code.
    fn land(&mut self, item: Item) -> u32 {
        let payload = item.encode();
        let mut output = refine(&self.config, self.venue(), &payload, &mut None_).encode();
        output.extend_from_slice(&0u64.to_le_bytes());
        self.items += 1;
        let package_hash = vos_statement::blake2b_256(&[&self.items.to_le_bytes()]);
        let payload_hash = vos_statement::blake2b_256(&[&payload]);
        let operand = Operand {
            package_hash,
            payload_hash,
            result: Ok(output),
        };
        let at = Config {
            genesis_ms: self.now,
            ..self.config.clone()
        };
        accumulate(&at, self.venue(), 0, &[operand], &mut self.storage);
        let id = state::outcome_id(&package_hash, &payload_hash);
        state::outcome(&mut self.storage, &id)
            .expect("an outcome")
            .code
    }

    /// `op` by the space's controller, its next nonce.
    fn control(&mut self, space: &SpaceId, op: Op) -> bool {
        let nonce = state::space(&mut self.storage, space).map_or(0, |record| record.nonce);
        let control = Control {
            space: *space,
            nonce,
            op,
        };
        let signer = controller();
        let signed = SignedControl {
            control,
            controller: signer.verifying_key().to_bytes(),
            signature: signer
                .sign(&control_digest(&self.venue(), &control))
                .to_bytes(),
        };
        self.land(Item::Control(signed)) == ControlCode::Done as u32
    }
}

impl Harness for Service {
    fn venue(&self) -> VenueId {
        venue(&self.config, 3)
    }

    fn set_now(&mut self, now: u64) {
        self.now = now;
    }

    fn key(&self, seed: u8) -> [u8; 32] {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    fn sign(&self, seed: u8, digest: &[u8; 32]) -> [u8; 64] {
        SigningKey::from_bytes(&[seed; 32]).sign(digest).to_bytes()
    }

    fn controller(&self) -> [u8; 32] {
        controller().verifying_key().to_bytes()
    }

    fn register(
        &mut self,
        genesis: &SpaceGenesis,
        controller: &[u8; 32],
        founder_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<(), RegisterRefusal> {
        let item = Item::Register(Register {
            genesis: genesis.clone(),
            controller: *controller,
            founder_key,
            signature,
        });
        match self.land(item) {
            code if code == RegisterCode::Registered as u32 => Ok(()),
            code if code == RegisterCode::Genesis as u32 => {
                let registrable = genesis.clock.registrable();
                Err(if registrable {
                    RegisterRefusal::Genesis
                } else {
                    RegisterRefusal::Clock
                })
            }
            code if code == RegisterCode::Founder as u32 => Err(RegisterRefusal::Founder),
            code if code == RegisterCode::Again as u32 => Err(RegisterRefusal::Exists),
            code => panic!("register: {code}"),
        }
    }

    fn start(&self, space: &SpaceId) -> Option<u64> {
        let bytes = self.storage.get(&keys::space(space))?;
        Some(state::SpaceRecord::decode(bytes).expect("a record").start)
    }

    fn anchor(&mut self, anchor: &Anchor) -> Answer {
        let code = self.land(Item::Anchor(*anchor));
        let codes = [
            (AnchorCode::New, Answer::New),
            (AnchorCode::Again, Answer::Again),
            (AnchorCode::Equivocation, Answer::Evidence),
            (
                AnchorCode::Unregistered,
                Answer::Refused(AnchorRefusal::Unregistered),
            ),
            (AnchorCode::Ended, Answer::Refused(AnchorRefusal::Stopped)),
            (AnchorCode::Key, Answer::Refused(AnchorRefusal::Key)),
            (
                AnchorCode::Signature,
                Answer::Refused(AnchorRefusal::Signature),
            ),
            (AnchorCode::Window, Answer::Refused(AnchorRefusal::Window)),
            (AnchorCode::Open, Answer::Refused(AnchorRefusal::Open)),
            (AnchorCode::Age, Answer::Refused(AnchorRefusal::Age)),
        ];
        codes
            .into_iter()
            .find(|(known, _)| *known as u32 == code)
            .map(|(_, answer)| answer)
            .unwrap_or_else(|| panic!("anchor: {code}"))
    }

    fn add_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool {
        self.control(space, Op::AddKey(key))
    }

    fn remove_key(&mut self, space: &SpaceId, key: [u8; 32]) -> bool {
        self.control(space, Op::RemoveKey(key))
    }

    fn status(&self, space: &SpaceId) -> Option<Status> {
        let bytes = self.storage.get(&keys::space(space))?;
        let record = state::SpaceRecord::decode(bytes).expect("a record");
        Some(if record.ended {
            Status::Ended
        } else {
            Status::Active
        })
    }

    fn anchored(&self, root: &RootRead) -> bool {
        anchored(&mut self.storage.clone(), self.venue(), self.now, root)
    }
}

/// The service judges as the venue rules do.
#[test]
fn the_service_passes_the_venue_rules_suite() {
    suite::run(Service::new);
}
