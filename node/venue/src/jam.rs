//! A JAM statements service as a node's venue ([`JamVenue`]), through
//! `vos_jam::live::statements`: each call an item in a work package of its
//! own, waited for until its outcome lands in the service's storage, about
//! two slots past the finalized block it was anchored at.
//!
//! Its answers are the service's (`vos_statement_service::verdict`'s
//! codes), mapped onto the trait's. An anchor is queued and answered at
//! once (`Anchored::Queued`): the [`AnchorQueue`]'s worker lands it, again
//! while the venue is not ready for it, until the venue holds it or will
//! never take it. A statement's code is its refusal's class; a repeat (6)
//! is the venue holding it accepted; a transport failure, or a package that
//! never lands, leaves it unjudged (`Unjudged::Unknown`).
//!
//! A `JamVenue` is made only for a service whose code is the one the node
//! expects: its code hash the deployed blob's, that blob's configuration
//! block the expected configuration, whose genesis hash is the chain's.
//! The service never calls `upgrade`, so its id, the chain and the
//! service's number, fixes its code and its pins for good.
//!
//! [`Jam`]'s own calls, which a run's tooling makes, wait for their items
//! to land, about three slots.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use vos_anchor::{Anchor, Migrate, RootRead, SpaceGenesis, SpaceId, VenueId, register_digest};
use vos_jam::Error;
use vos_jam::live::statements::{Item as Package, Statements};
use vos_statement::{MAX_ROOT_AGE_MS, Statement, StatementId};
use vos_statement_service::config::{Config, configure};
use vos_statement_service::item::{
    Control, Item, Op, Register, SignedControl, SignedMigrate, control_digest, migrate_digest,
};
use vos_statement_service::state::{AnchorRecord, Outcome, SpaceRecord, keys};
use vos_statement_service::verdict::{AnchorCode, MigrateCode, RegisterCode};

use crate::queue::{AnchorQueue, AnchorSend, Fate};
use crate::{AnchorRefusal, Anchored, MigrateRefusal, NotAccepted, Status, Unjudged, VenueClient};

/// How long an item's outcome may take to land.
pub const LANDING: Duration = Duration::from_secs(120);

/// A JAM statements service, its calls waiting for their items to land.
pub struct Jam {
    pub statements: Statements,
    /// The deployment's constants, which its code holds.
    pub config: Config,
}

/// A JAM statements service, as a node's venue: [`Jam`]'s calls, its
/// anchors through an [`AnchorQueue`].
pub struct JamVenue {
    jam: Arc<Jam>,
    queue: AnchorQueue,
}

impl std::ops::Deref for JamVenue {
    type Target = Jam;

    fn deref(&self) -> &Jam {
        &self.jam
    }
}

/// How long the queue waits to offer an anchor again: a slot, or a window's
/// worth of slots when the venue waits for someone to act.
const SLOT: Duration = Duration::from_secs(6);
const AWHILE: Duration = Duration::from_secs(120);

/// What a service's code is checked for.
#[derive(Debug)]
pub enum Mismatch {
    /// The chain holds another code for the service than `code`.
    Code,
    /// `code`'s configuration is not the expected one.
    Config,
    /// The configuration names another chain than the node's.
    Genesis,
    Node(Error),
}

impl JamVenue {
    /// The service `statements`, checked to run `code`, the service blob
    /// deployed, whose configuration block holds `config`, `config` naming
    /// the chain the node is on; its time from `config`'s genesis time.
    pub fn new(mut statements: Statements, config: Config, code: &[u8]) -> Result<Self, Mismatch> {
        if vos_statement::blake2b_256(&[code]) != statements.code_hash {
            return Err(Mismatch::Code);
        }
        let mut configured = code.to_vec();
        configure(&mut configured, &config).map_err(|_| Mismatch::Config)?;
        if configured != code {
            return Err(Mismatch::Config);
        }
        if statements.node.genesis().map_err(Mismatch::Node)? != config.genesis {
            return Err(Mismatch::Genesis);
        }
        statements.genesis_ms = config.genesis_ms;
        let jam = Arc::new(Jam { statements, config });
        let queue = AnchorQueue::spawn("jam-anchors", JamSend(Arc::clone(&jam)));
        Ok(Self { jam, queue })
    }
}

/// The anchors' sending, as the queue's worker drives it.
struct JamSend(Arc<Jam>);

impl AnchorSend for JamSend {
    fn send(&self, anchor: &Anchor) -> Fate {
        let Ok(code) = self.0.anchor_now(anchor) else {
            return Fate::Again(SLOT);
        };
        match code {
            code if code == AnchorCode::New as u32 || code == AnchorCode::Again as u32 => {
                Fate::Done
            }
            code if code == AnchorCode::Window as u32 || code == AnchorCode::Age as u32 => {
                Fate::Dead
            }
            code if code == AnchorCode::Equivocation as u32 => Fate::Dead,
            code if code == AnchorCode::Open as u32 => Fate::Again(SLOT),
            _ => Fate::Again(AWHILE),
        }
    }
}

impl Jam {
    /// The venue's id: `VenueId::jam(genesis, service)`.
    pub fn id(&self) -> VenueId {
        let service = u32::try_from(self.statements.service).unwrap_or(u32::MAX);
        VenueId::jam(&self.config.genesis, service)
    }

    /// Land `anchor`: the service's code (`AnchorCode`).
    pub fn anchor_now(&self, anchor: &Anchor) -> Result<u32, Error> {
        Ok(self.land(Item::Anchor(*anchor).encode(), Vec::new())?.code)
    }

    /// A space's control by its controller, at its next nonce as the
    /// finalized block holds it: the service's code (`ControlCode`).
    pub fn control(&self, space: &SpaceId, op: Op, controller: &SigningKey) -> Result<u32, Error> {
        let nonce = self.space(space)?.map_or(0, |record| record.nonce);
        let control = Control {
            space: *space,
            nonce,
            op,
        };
        let item = Item::Control(SignedControl {
            control,
            controller: controller.verifying_key().to_bytes(),
            signature: controller
                .sign(&control_digest(&self.id(), &control))
                .to_bytes(),
        });
        Ok(self.land(item.encode(), Vec::new())?.code)
    }

    /// One item, landed: its outcome.
    pub fn land(&self, payload: Vec<u8>, extrinsics: Vec<Vec<u8>>) -> Result<Outcome, Error> {
        self.land_package(payload, extrinsics)
            .map(|(_, outcome)| outcome)
    }

    /// One item, landed: the encoding of its package and its outcome.
    pub fn land_package(
        &self,
        payload: Vec<u8>,
        extrinsics: Vec<Vec<u8>>,
    ) -> Result<(Vec<u8>, Outcome), Error> {
        let (package, mut outcomes) = self
            .statements
            .land_package(&[(payload, extrinsics)], LANDING)?;
        let outcome = outcomes
            .pop()
            .ok_or_else(|| Error::Node("no outcome".into()))?;
        Ok((package, outcome))
    }

    /// Items landed together, in one package: each one's outcome.
    pub fn land_all(&self, items: &[Package]) -> Result<Vec<Outcome>, Error> {
        self.statements.land(items, LANDING)
    }

    /// Register the space `genesis` founds under `controller` (an ed25519
    /// key's 32 bytes), anchoring from `start_window`, signed by `founder`,
    /// one of its founding keys: the service's code
    /// (`RegisterCode`).
    pub fn register(
        &self,
        genesis: &SpaceGenesis,
        controller: [u8; 32],
        start_window: u64,
        founder: &SigningKey,
    ) -> Result<u32, Error> {
        let space = vos_anchor::space_id(genesis);
        let digest = register_digest(&self.id(), &space, &controller, start_window);
        self.register_signed(
            genesis,
            controller,
            start_window,
            founder.verifying_key().to_bytes(),
            founder.sign(&digest).to_bytes(),
        )
    }

    /// Register the space `genesis` founds, as [`Jam::register`] does, by
    /// the signature a founding key `founder_key` made over its digest
    /// (a founding node's, `vos_node::Node::sign_registration`).
    pub fn register_signed(
        &self,
        genesis: &SpaceGenesis,
        controller: [u8; 32],
        start_window: u64,
        founder_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<u32, Error> {
        let item = Item::Register(Register {
            genesis: genesis.clone(),
            controller,
            start_window,
            founder_key,
            signature,
        });
        Ok(self.land(item.encode(), Vec::new())?.code)
    }

    /// A space's migration away from this venue, signed by its controller.
    pub fn migrate(
        &self,
        migrate: &Migrate,
        controller: &SigningKey,
    ) -> Result<(), MigrateRefusal> {
        let item = Item::Migrate(SignedMigrate {
            migrate: *migrate,
            controller: controller.verifying_key().to_bytes(),
            signature: controller.sign(&migrate_digest(migrate)).to_bytes(),
        });
        let code = self
            .land(item.encode(), Vec::new())
            .map_err(|_| MigrateRefusal::Window)?
            .code;
        match code {
            code if code == MigrateCode::Migrated as u32 => Ok(()),
            code if code == MigrateCode::Unregistered as u32 => Err(MigrateRefusal::Unregistered),
            code if code == MigrateCode::Venue as u32 => Err(MigrateRefusal::Venue),
            code if code == MigrateCode::AlreadyMigrated as u32 => {
                Err(MigrateRefusal::AlreadyMigrated)
            }
            _ => Err(MigrateRefusal::Window),
        }
    }

    /// Submit `statement` with its final proof as the item's extrinsic: the
    /// service's code (`vos_statement::code`'s) and the statement's id.
    pub fn submit_code(&self, statement: &Statement, proof: &[u8]) -> Result<u32, Error> {
        let payload = Item::Submit(statement.encode()).encode();
        Ok(self.land(payload, vec![proof.to_vec()])?.code)
    }

    /// The space `space` as the finalized block holds it.
    pub fn space(&self, space: &SpaceId) -> Result<Option<SpaceRecord>, Error> {
        Ok(self
            .statements
            .value(&keys::space(space))?
            .and_then(|bytes| SpaceRecord::decode(&bytes).ok()))
    }
}

impl VenueClient for JamVenue {
    fn id(&self) -> VenueId {
        self.jam.id()
    }

    /// Queued, answered at once: an anchor not signed by its signer over
    /// its digest here is refused; the rest the queue's worker lands.
    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        let signed = VerifyingKey::from_bytes(&anchor.signer).is_ok_and(|key| {
            key.verify_strict(
                &anchor.digest(&self.id()),
                &Signature::from_bytes(&anchor.signature),
            )
            .is_ok()
        });
        if !signed {
            return Err(AnchorRefusal::Signature);
        }
        self.queue.push(anchor);
        Ok(Anchored::Queued)
    }

    /// A statement the service holds seen is answered accepted unsent: a
    /// package refined again only to be refused a repeat costs a whole
    /// refine.
    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        let id = statement.id();
        if let Ok(Some(_)) = self.statements.value(&keys::seen(&id)) {
            return Ok(id);
        }
        match self.submit_code(statement, proof) {
            Ok(0 | 6) => Ok(statement.id()),
            Ok(code) => Err(NotAccepted::Refused(code)),
            Err(_) => Err(NotAccepted::Unjudged(Unjudged::Unknown)),
        }
    }

    /// The space's standing at the finalized block; unregistered while the
    /// node cannot say.
    fn status(&self, space: &SpaceId) -> Status {
        match self.space(space) {
            Ok(Some(record)) if record.suspended => Status::Suspended,
            Ok(Some(_)) => Status::Active,
            _ => Status::Unregistered,
        }
    }

    fn anchored(&self, root: &RootRead) -> bool {
        let Ok(Some(space)) = self.space(&root.space) else {
            return false;
        };
        let Ok(now) = self.statements.now() else {
            return false;
        };
        let fresh = space
            .clock
            .boundary(root.window)
            .and_then(|boundary| boundary.checked_add(MAX_ROOT_AGE_MS))
            .is_some_and(|last| now <= last);
        let held = self
            .statements
            .value(&keys::anchor(&root.space, root.kind, root.window))
            .ok()
            .flatten()
            .and_then(|bytes| AnchorRecord::decode(&bytes).ok())
            .is_some_and(|held| held.root == root.root);
        !space.suspended && space.range.contains(root.window) && fresh && held
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.space(space)
            .ok()
            .flatten()
            .map(|space| space.keys)
            .unwrap_or_default()
    }
    /// The finalized block's slot time (slot × 6 s from JAM's genesis
    /// time); none while the node cannot say.
    fn time(&self) -> Option<u64> {
        self.statements.now().ok()
    }
}

/// A registration's code read as its name, for a record.
pub fn register_code(code: u32) -> &'static str {
    [
        (RegisterCode::Registered, "registered"),
        (RegisterCode::Item, "undecodable"),
        (RegisterCode::Genesis, "genesis"),
        (RegisterCode::Founder, "not a founder"),
        (RegisterCode::Signature, "signature"),
        (RegisterCode::Again, "registered already"),
        (RegisterCode::Start, "start window"),
        (RegisterCode::Clock, "before the clock's origin"),
    ]
    .into_iter()
    .find(|(named, _)| *named as u32 == code)
    .map_or("unknown", |(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An anchor is queued and answered at once, whatever the node: one
    /// of a node that never answers returns within 500 ms, a signature's
    /// check in a debug build on a loaded host and no wait on the node,
    /// whose calls time out in seconds; one not signed over this venue's
    /// digest is refused.
    #[test]
    fn an_anchor_is_answered_at_once() {
        use std::net::TcpListener;
        use std::path::PathBuf;
        use std::time::Instant;

        use vos_anchor::RootKind;
        use vos_jam::live::PolkaJam;

        // A node that takes connections and never answers.
        let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
        let node = PolkaJam {
            rpc: stalled.local_addr().unwrap().to_string(),
            jamt: PathBuf::from("jamt"),
            files: std::env::temp_dir(),
        };
        let statements = Statements {
            node,
            service: 3,
            code_hash: [0; 32],
            refine_gas: 1_000_000_000,
            genesis_ms: 0,
        };
        let jam = Arc::new(Jam {
            statements,
            config: Config {
                genesis: [0x6a; 32],
                genesis_ms: 0,
                pins: Vec::new(),
            },
        });
        let venue = JamVenue {
            queue: AnchorQueue::spawn("jam-anchors-test", JamSend(Arc::clone(&jam))),
            jam,
        };
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut anchor = Anchor {
            space: SpaceId([1; 32]),
            window: 5,
            kind: RootKind::Space,
            root: [2; 32],
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        assert_eq!(venue.anchor(&anchor), Err(AnchorRefusal::Signature));
        anchor.signature = key.sign(&anchor.digest(&venue.id())).to_bytes();
        let start = Instant::now();
        assert_eq!(venue.anchor(&anchor), Ok(Anchored::Queued));
        let took = start.elapsed();
        assert!(took < Duration::from_millis(500), "{took:?}");
        assert!(venue.queue.holds(&anchor.space, 5));
    }
}
