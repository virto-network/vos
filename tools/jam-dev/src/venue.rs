//! A JAM statements service as a node's venue ([`JamVenue`]), through
//! [`crate::live::statements`]: each call an item in a work package of its
//! own, waited for until its outcome lands in the service's storage, about
//! two slots past the finalized block it was anchored at.
//!
//! Its answers are the service's (`vos_statement_service::verdict`'s
//! codes), mapped onto the trait's; the client judges no anchor itself,
//! the service does by the venue rules (`vos_anchor::venue`). An anchor is
//! queued and answered at once (`Anchored::Queued`): the [`AnchorQueue`]'s
//! worker lands it, again while the venue is not ready for it, until the
//! venue holds it, holds another root there (this node's anchor is then
//! the equivocation's evidence, which ends the space), or will never take
//! it; one whose key the service does not list is handed back to the
//! leader to sign again with a key it lists ([`VenueClient::unsettled`]),
//! and the same anchor offered again is refused for its key. Every refusal
//! but `Open` alerts. A statement's code is its refusal's class; a repeat
//! (`Refusal::Repeated`) is the venue holding it accepted; a transport
//! failure, or a package that never lands, leaves it unjudged
//! (`Unjudged::Unknown`).
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

use crate::live::statements::Statements;
use ed25519_dalek::{Signer, SigningKey};
use vos_anchor::venue::{self as rules, Held, Roots};
use vos_anchor::{Anchor, RootKind, RootRead, SpaceGenesis, SpaceId, VenueId, register_digest};
use vos_jam::Error;
use vos_statement::{Refusal, Statement, StatementId};
use vos_statement_service::config::{Config, configure};
use vos_statement_service::item::{Control, Item, Op, Register, SignedControl, control_digest};
use vos_statement_service::state::{AnchorRecord, Outcome, SpaceRecord, keys};
use vos_statement_service::verdict::{AnchorCode, RegisterCode};

use vos_venue::queue::{AnchorQueue, AnchorSend, Fate};
use vos_venue::{AnchorRefusal, Anchored, NotAccepted, Status, Unjudged, VenueClient};

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

/// What the anchors' sending reads of a statements service, as its
/// finalized block holds it, and lands on it.
trait Service: Send + Sync + 'static {
    fn space(&self, space: &SpaceId) -> Result<Option<SpaceRecord>, Error>;
    /// The venue's time.
    fn now(&self) -> Result<u64, Error>;
    /// Land `anchor`: the service's code (`AnchorCode`).
    fn land_anchor(&self, anchor: &Anchor) -> Result<u32, Error>;
}

impl Service for Jam {
    fn space(&self, space: &SpaceId) -> Result<Option<SpaceRecord>, Error> {
        Jam::space(self, space)
    }

    fn now(&self) -> Result<u64, Error> {
        self.statements.now()
    }

    fn land_anchor(&self, anchor: &Anchor) -> Result<u32, Error> {
        self.anchor_now(anchor)
    }
}

/// The anchors' sending, as the queue's worker drives it.
struct JamSend<S = Jam>(Arc<S>);

impl<S: Service> AnchorSend for JamSend<S> {
    fn send(&self, anchor: &Anchor) -> Fate {
        let window = anchor.window;
        let code = match self.0.land_anchor(anchor) {
            Ok(code) => code,
            Err(error) => {
                tracing::warn!(window, %error, "an anchor not landed: again a slot later");
                return Fate::Again(SLOT);
            }
        };
        let fate = fate(code);
        match anchor_code(code) {
            Some(AnchorCode::Equivocation) => tracing::error!(
                window,
                "an equivocation: the JAM service holds another root of the space at this \
                 window, signed by a listed anchor key, and this node's anchor is its evidence, \
                 which ends the space for good; it re-founds under a new genesis"
            ),
            Some(AnchorCode::Open) => {}
            _ if fate != Fate::Done => {
                tracing::error!(window, code, ?fate, "the JAM service refused an anchor");
            }
            _ => {}
        }
        fate
    }

    /// As the finalized block holds the space: a window at or past the
    /// anchor's anchored, or the window past `MaxRootAge`.
    fn settled(&self, anchor: &Anchor) -> bool {
        let (Ok(Some(space)), Ok(now)) = (self.0.space(&anchor.space), self.0.now()) else {
            return false;
        };
        let passed = space.last.is_some_and(|last| last >= anchor.window);
        passed || rules::aged(&space.clock, anchor.window, now)
    }
}

/// The anchor outcome the service's `code` is; none for another code.
pub fn anchor_code(code: u32) -> Option<AnchorCode> {
    use AnchorCode::*;
    [
        New,
        Again,
        Item,
        Signature,
        Unregistered,
        Ended,
        Key,
        Window,
        Open,
        Age,
        Equivocation,
    ]
    .into_iter()
    .find(|known| *known as u32 == code)
}

/// What becomes of an anchor the service answered `code`.
fn fate(code: u32) -> Fate {
    match anchor_code(code) {
        Some(AnchorCode::New | AnchorCode::Again) => Fate::Done,
        Some(
            AnchorCode::Window | AnchorCode::Age | AnchorCode::Equivocation | AnchorCode::Ended,
        ) => Fate::Dead,
        Some(AnchorCode::Open) => Fate::Again(SLOT),
        Some(AnchorCode::Key) => Fate::Resign,
        _ => Fate::Again(AWHILE),
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
        self.control_at(space, nonce, op, controller)
    }

    /// A space's control by its controller at `nonce`: the service's code
    /// (`ControlCode`), `ControlCode::Nonce` for a nonce not the space's
    /// next.
    pub fn control_at(
        &self,
        space: &SpaceId,
        nonce: u64,
        op: Op,
        controller: &SigningKey,
    ) -> Result<u32, Error> {
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
        let mut outcomes = self.statements.land(&[(payload, extrinsics)], LANDING)?;
        outcomes
            .pop()
            .ok_or_else(|| Error::Node("no outcome".into()))
    }

    /// Register the space `genesis` founds under `controller` (an ed25519
    /// key's 32 bytes), signed by `founder`, one of its founding keys: the
    /// service's code (`RegisterCode`). It anchors from the venue's next
    /// window.
    pub fn register(
        &self,
        genesis: &SpaceGenesis,
        controller: [u8; 32],
        founder: &SigningKey,
    ) -> Result<u32, Error> {
        let space = vos_anchor::space_id(genesis);
        let digest = register_digest(&self.id(), &space, &controller);
        self.register_signed(
            genesis,
            controller,
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
        founder_key: [u8; 32],
        signature: [u8; 64],
    ) -> Result<u32, Error> {
        let item = Item::Register(Register {
            genesis: genesis.clone(),
            controller,
            founder_key,
            signature,
        });
        Ok(self.land(item.encode(), Vec::new())?.code)
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
    /// its digest here is refused, one of a window the service refused for
    /// good, and the one handed back for its key; the rest the queue's
    /// worker lands.
    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        if !vos_venue::signed(anchor, &self.id()) {
            return Err(AnchorRefusal::Signature);
        }
        if self.queue.dead(&anchor.space, anchor.window) {
            self.queue.settle(&anchor.space, anchor.window);
            return Err(AnchorRefusal::Window);
        }
        if !self.queue.push(anchor) {
            return Err(AnchorRefusal::Key);
        }
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
            Ok(0) => Ok(id),
            Ok(code) if code == Refusal::Repeated.code() => Ok(id),
            Ok(code) => Err(NotAccepted::Refused(code)),
            Err(_) => Err(NotAccepted::Unjudged(Unjudged::Unknown)),
        }
    }

    /// The space's standing at the finalized block; unregistered while the
    /// node cannot say.
    fn status(&self, space: &SpaceId) -> Status {
        match self.space(space) {
            Ok(Some(record)) if record.ended => Status::Ended,
            Ok(Some(_)) => Status::Active,
            _ => Status::Unregistered,
        }
    }

    /// The venue rules' `anchored` over the finalized block's record of the
    /// space and root at the window, and its slot's time.
    fn anchored(&self, root: &RootRead) -> bool {
        let (Ok(Some(space)), Ok(now)) = (self.space(&root.space), self.statements.now()) else {
            return false;
        };
        let held = self
            .statements
            .value(&keys::anchor(&root.space, root.kind, root.window))
            .ok()
            .flatten()
            .and_then(|bytes| AnchorRecord::decode(&bytes).ok());
        rules::anchored(&Read { space, now, held }, root)
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

    fn unsettled(&self, space: &SpaceId) -> Vec<Anchor> {
        self.queue.unsettled(space)
    }
}

/// One window of a space as the finalized block holds it, for the venue
/// rules.
struct Read {
    space: SpaceRecord,
    now: u64,
    held: Option<AnchorRecord>,
}

impl Roots for Read {
    fn now(&self) -> u64 {
        self.now
    }

    fn space(&self, _: &SpaceId) -> Option<rules::Space> {
        Some(rules::Space {
            clock: self.space.clock,
            start: self.space.start,
            status: if self.space.ended {
                rules::Status::Ended
            } else {
                rules::Status::Active
            },
        })
    }

    fn held(&self, _: &SpaceId, _: RootKind, _: u64) -> Option<Held> {
        self.held.map(|held| Held {
            root: held.root,
            signer: held.signer,
        })
    }
}

/// A registration's code read as its name, for a record.
pub fn register_code(code: u32) -> &'static str {
    [
        (RegisterCode::Registered, "registered"),
        (RegisterCode::Item, "undecodable"),
        (RegisterCode::Genesis, "genesis"),
        (RegisterCode::Founder, "not a founder, or its signature"),
        (RegisterCode::Again, "registered already"),
    ]
    .into_iter()
    .find(|(named, _)| *named as u32 == code)
    .map_or("unknown", |(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key refused hands the anchor back to be signed again; a
    /// signature refused waits, since signing again with the same key
    /// makes the same signature; an unregistered space waits; a window the
    /// service will never take, or an ended space's, is dead.
    #[test]
    fn each_anchor_code_has_its_fate() {
        use AnchorCode::*;
        for (code, expected) in [
            (New, Fate::Done),
            (Again, Fate::Done),
            (Item, Fate::Again(AWHILE)),
            (Signature, Fate::Again(AWHILE)),
            (Unregistered, Fate::Again(AWHILE)),
            (Ended, Fate::Dead),
            (Key, Fate::Resign),
            (Window, Fate::Dead),
            (Open, Fate::Again(SLOT)),
            (Age, Fate::Dead),
            (Equivocation, Fate::Dead),
        ] {
            assert_eq!(fate(code as u32), expected, "{code:?}");
        }
        assert_eq!(fate(0x1001), Fate::Again(AWHILE), "refine failed");
    }

    /// The statements service's refine and accumulate in memory, at a
    /// slot: what the anchors' sending reads and lands on.
    struct Local {
        config: Config,
        service: u32,
        state: std::sync::Mutex<Landed>,
    }

    /// The service's storage, its slot and the packages landed.
    type Landed = (std::collections::BTreeMap<Vec<u8>, Vec<u8>>, u64, u64);

    struct NoExtrinsics;

    impl vos_statement_service::refine::Extrinsics for NoExtrinsics {
        fn proof_len(&mut self) -> Option<usize> {
            None
        }

        fn proof(&mut self, _: usize) -> Vec<u8> {
            Vec::new()
        }
    }

    impl Local {
        fn venue(&self) -> VenueId {
            vos_statement_service::refine::venue(&self.config, self.service)
        }

        fn at(&self, time: u64) {
            self.state.lock().unwrap().1 = time.div_ceil(vos_statement_service::SLOT_MS);
        }

        /// `payload` refined and accumulated, a package of its own: its code.
        fn land(&self, payload: &[u8]) -> u32 {
            use vos_statement_service::accumulate::{Operand, accumulate};
            use vos_statement_service::{refine, state};
            let verdict = refine::refine(&self.config, self.venue(), payload, &mut NoExtrinsics);
            let mut output = verdict.encode();
            output.extend(0u64.to_le_bytes());
            let mut guard = self.state.lock().unwrap();
            let (storage, slot, packages) = &mut *guard;
            *packages += 1;
            let payload_hash = vos_statement::blake2b_256(&[payload]);
            let package_hash = vos_statement::blake2b_256(&[&packages.to_le_bytes()]);
            let operand = Operand {
                package_hash,
                payload_hash,
                result: Ok(output),
            };
            accumulate(&self.config, self.venue(), *slot, &[operand], storage);
            let id = state::outcome_id(&package_hash, &payload_hash);
            state::outcome(storage, &id).expect("an outcome").code
        }

        fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.state.lock().unwrap().0.get(key).cloned()
        }
    }

    impl Service for Local {
        fn space(&self, space: &SpaceId) -> Result<Option<SpaceRecord>, Error> {
            Ok(self
                .read(&keys::space(space))
                .and_then(|bytes| SpaceRecord::decode(&bytes).ok()))
        }

        fn now(&self) -> Result<u64, Error> {
            let slot = self.state.lock().unwrap().1;
            Ok(vos_statement_service::accumulate::time(&self.config, slot))
        }

        fn land_anchor(&self, anchor: &Anchor) -> Result<u32, Error> {
            Ok(self.land(&Item::Anchor(*anchor).encode()))
        }
    }

    /// A listed key stolen anchors another root of a window first: the
    /// node's anchor of it is sent all the same, the equivocation's
    /// evidence, which ends the space; offered again, the ended space
    /// refuses it for good.
    #[test]
    fn an_anchor_over_another_root_goes_as_evidence() {
        use vos_anchor::{RootKind, WindowClock};
        use vos_statement_service::state::Evidence;

        let local = Arc::new(Local {
            config: Config {
                genesis: [0x6a; 32],
                genesis_ms: 0,
                pins: Vec::new(),
            },
            service: 3,
            state: std::sync::Mutex::default(),
        });
        let (honest, stolen) = (
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
        );
        let controller = SigningKey::from_bytes(&[0xc0; 32]);
        let clock = WindowClock::DEFAULT;
        let genesis = SpaceGenesis {
            version: vos_anchor::GENESIS_VERSION,
            nodes: vec![
                (0, honest.verifying_key().to_bytes()),
                (1, stolen.verifying_key().to_bytes()),
            ],
            clock,
            time: clock.origin_ms,
            nonce: [7; 16],
        };
        let space = vos_anchor::space_id(&genesis);
        let window = 10;
        let controller_key = controller.verifying_key().to_bytes();
        let digest = register_digest(&local.venue(), &space, &controller_key);
        let register = Item::Register(Register {
            genesis,
            controller: controller_key,
            founder_key: honest.verifying_key().to_bytes(),
            signature: honest.sign(&digest).to_bytes(),
        });
        assert_eq!(
            local.land(&register.encode()),
            RegisterCode::Registered as u32
        );
        local.at(clock.boundary(window).unwrap());
        let anchor = |root: u8, key: &SigningKey| {
            let mut anchor = Anchor {
                space,
                window,
                kind: RootKind::Space,
                root: [root; 32],
                signer: key.verifying_key().to_bytes(),
                signature: [0; 64],
            };
            anchor.signature = key.sign(&anchor.digest(&local.venue())).to_bytes();
            anchor
        };
        assert_eq!(
            local.land_anchor(&anchor(9, &stolen)).unwrap(),
            AnchorCode::New as u32
        );

        let send = JamSend(Arc::clone(&local));
        let ours = anchor(1, &honest);
        assert_eq!(send.send(&ours), Fate::Dead, "sent, the evidence");
        let record = local.space(&space).unwrap().unwrap();
        assert!(record.ended);
        let evidence = local
            .read(&keys::evidence(&space, RootKind::Space, window))
            .expect("the evidence");
        let evidence = Evidence::decode(&evidence).unwrap();
        assert_eq!(evidence.held.signer, stolen.verifying_key().to_bytes());
        assert_eq!(evidence.other.signer, honest.verifying_key().to_bytes());
        assert_eq!(send.send(&ours), Fate::Dead, "the space ended");
        assert!(send.settled(&ours), "its window anchored");
    }

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

        use crate::live::PolkaJam;
        use vos_anchor::RootKind;

        // A node that takes connections and never answers.
        let stalled = TcpListener::bind("127.0.0.1:0").unwrap();
        let node = PolkaJam {
            rpc: stalled.local_addr().unwrap().to_string(),
            jamt: PathBuf::from("jamt"),
            files: std::env::temp_dir(),
            watch: None,
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
