//! A JAM statements service as a node's venue ([`JamVenue`]), through
//! [`crate::live::statements`]: each call an item in a work package of its
//! own, waited for until its outcome lands in the service's storage, about
//! two slots past the finalized block it was anchored at.
//!
//! Its answers are the service's (`vos_statement_service::verdict`'s
//! codes), mapped onto the leader's outcome by one table ([`outcome`]);
//! the client judges no anchor itself, the service does by the venue rules
//! (`vos_anchor::venue`). A reader thread reads each space the node asks
//! of (its record: status, anchor keys, last window; and the roots at the
//! windows the leader asks of) every slot, and the client answers from
//! that read: not yet while unread or unregistered, stopped once ended,
//! unlisted while the record does not list the signer, never for a window
//! refused for good, else taken and queued. The [`AnchorQueue`]'s worker
//! lands it, again while the venue is not ready for it, unless the
//! service already holds a root there: the same root settles it, another
//! is sent only once the leader, having read it, offered the anchor again
//! (its divergence guard passed), as the equivocation's evidence, which
//! ends the space. Every refusal but `Open` alerts. A statement's outcome
//! is its code's ([`SubmitOutcome::judged`]); a transport failure, or a
//! package that never lands, leaves it unjudged.
//!
//! A `JamVenue` is made only for a service whose code is the one the node
//! expects: its code hash the deployed blob's, that blob's configuration
//! block the expected configuration, whose genesis hash is the chain's.
//! The service never calls `upgrade`, so its id, the chain and the
//! service's number, fixes its code and its pins for good.
//!
//! [`Jam`]'s own calls, which a run's tooling makes, wait for their items
//! to land, about three slots.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::live::statements::Statements;
use ed25519_dalek::{Signer, SigningKey};
use vos_anchor::venue::{self as rules, Held, Roots};
use vos_anchor::{Anchor, RootKind, RootRead, SpaceGenesis, SpaceId, VenueId, register_digest};
use vos_jam::Error;
use vos_statement::Statement;
use vos_statement_service::config::{Config, configure};
use vos_statement_service::item::{Control, Item, Op, Register, SignedControl, control_digest};
use vos_statement_service::state::{AnchorRecord, Outcome, SpaceRecord, keys};
use vos_statement_service::verdict::{AnchorCode, RegisterCode};

use vos_venue::queue::{AnchorQueue, AnchorSend, Fate};
use vos_venue::{AnchorOutcome, Held as Holding, Status, SubmitOutcome, UNJUDGED, VenueClient};

/// How long an item's outcome may take to land.
pub const LANDING: Duration = Duration::from_secs(120);

/// A JAM statements service, its calls waiting for their items to land.
pub struct Jam {
    pub statements: Statements,
    /// The deployment's constants, which its code holds.
    pub config: Config,
}

/// A JAM statements service, as a node's venue: [`Jam`]'s calls, its
/// reads on a thread of their own, its anchors through an [`AnchorQueue`].
pub struct JamVenue {
    shared: Arc<Shared>,
    queue: AnchorQueue,
}

impl std::ops::Deref for JamVenue {
    type Target = Jam;

    fn deref(&self) -> &Jam {
        &self.shared.service
    }
}

impl Drop for JamVenue {
    fn drop(&mut self) {
        self.shared.stopping.store(true, Ordering::SeqCst);
        self.shared.wake.notify_all();
    }
}

/// What the client last read of a space.
#[derive(Default)]
struct Known {
    /// Whether it has been read since the node asked of it.
    read: bool,
    record: Option<SpaceRecord>,
    /// The roots held at the windows read, or none.
    held: BTreeMap<u64, Option<[u8; 32]>>,
    /// The windows at or behind its last the leader asked of, to read.
    wanted: BTreeSet<u64>,
    /// The windows the service refused for good, each with its code.
    never: BTreeMap<u64, u32>,
    /// The windows at which the leader offered an anchor while the client
    /// held another root read there: sent as the equivocation's evidence.
    evidence: BTreeSet<u64>,
}

#[derive(Default)]
struct Reads {
    now: Option<u64>,
    spaces: BTreeMap<SpaceId, Known>,
}

/// The client's reads, shared by its reader, its queue's worker and the
/// node's calls.
struct Shared<S = Jam> {
    service: Arc<S>,
    read: Mutex<Reads>,
    wake: Condvar,
    stopping: AtomicBool,
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
        Ok(Self::over(Arc::new(Jam { statements, config })))
    }

    /// The client of `jam`, its reader and its queue started.
    fn over(jam: Arc<Jam>) -> Self {
        let shared = Arc::new(Shared::new(jam));
        let reader = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("jam-reads".into())
            .spawn(move || reader.read_on())
            .expect("the JAM reader starts");
        let queue = AnchorQueue::spawn("jam-anchors", JamSend(Arc::clone(&shared)));
        Self { shared, queue }
    }
}

/// What the anchors' sending reads of a statements service, as its
/// finalized block holds it, and lands on it.
trait Service: Send + Sync + 'static {
    fn space(&self, space: &SpaceId) -> Result<Option<SpaceRecord>, Error>;
    /// The space's root it holds at `window`.
    fn root(&self, space: &SpaceId, window: u64) -> Result<Option<[u8; 32]>, Error>;
    /// The venue's time.
    fn now(&self) -> Result<u64, Error>;
    /// Land `anchor`: the service's code (`AnchorCode`).
    fn land_anchor(&self, anchor: &Anchor) -> Result<u32, Error>;
}

impl Service for Jam {
    fn space(&self, space: &SpaceId) -> Result<Option<SpaceRecord>, Error> {
        Jam::space(self, space)
    }

    fn root(&self, space: &SpaceId, window: u64) -> Result<Option<[u8; 32]>, Error> {
        Ok(self
            .statements
            .value(&keys::anchor(space, RootKind::Space, window))?
            .and_then(|bytes| AnchorRecord::decode(&bytes).ok())
            .map(|record| record.root))
    }

    fn now(&self) -> Result<u64, Error> {
        self.statements.now()
    }

    fn land_anchor(&self, anchor: &Anchor) -> Result<u32, Error> {
        self.anchor_now(anchor)
    }
}

impl<S: Service> Shared<S> {
    fn new(service: Arc<S>) -> Self {
        Self {
            service,
            read: Mutex::default(),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
        }
    }

    fn read(&self) -> MutexGuard<'_, Reads> {
        self.read
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `space`, asked of: read at the reader's next turn.
    fn watch(&self, read: &mut Reads, space: SpaceId) {
        if let std::collections::btree_map::Entry::Vacant(entry) = read.spaces.entry(space) {
            entry.insert(Known::default());
            self.wake.notify_all();
        }
    }

    /// Read every slot, or when woken, until stopped.
    fn read_on(&self) {
        while !self.stopping.load(Ordering::SeqCst) {
            if let Err(error) = self.refresh() {
                tracing::warn!(%error, "the JAM service is not readable; reading again");
            }
            let read = self.read();
            let _ = self.wake.wait_timeout(read, SLOT);
        }
    }

    /// Read the venue's time, and each space asked of: its record and the
    /// roots at the windows wanted. What has aged is forgotten.
    fn refresh(&self) -> Result<(), Error> {
        let now = self.service.now()?;
        let asked: Vec<(SpaceId, Vec<u64>)> = self
            .read()
            .spaces
            .iter()
            .map(|(space, known)| (*space, known.wanted.iter().copied().collect()))
            .collect();
        let mut records = Vec::new();
        for (space, wanted) in asked {
            let record = self.service.space(&space)?;
            let mut held = Vec::new();
            for window in wanted {
                held.push((window, self.service.root(&space, window)?));
            }
            records.push((space, record, held));
        }
        let mut read = self.read();
        read.now = Some(now);
        for (space, record, held) in records {
            let known = read.spaces.entry(space).or_default();
            for (window, root) in held {
                known.wanted.remove(&window);
                known.held.entry(window).or_insert(root);
            }
            if let Some(record) = &record {
                let fresh = |window: &u64| !rules::aged(&record.clock, *window, now);
                known.held.retain(|window, _| fresh(window));
                known.never.retain(|window, _| fresh(window));
                known.evidence.retain(fresh);
                known.wanted.retain(fresh);
                if record.ended {
                    known.held.clear();
                }
            }
            known.record = record;
            known.read = true;
        }
        Ok(())
    }

    /// Send `anchor`, unless the last read, or the service's root at its
    /// window read now, says not to; the service's answer kept.
    fn send(&self, anchor: &Anchor) -> Fate {
        let (space, window) = (anchor.space, anchor.window);
        let Ok(now) = self.service.now() else {
            return Fate::Again(SLOT);
        };
        {
            let mut read = self.read();
            let Some(known) = read.spaces.get_mut(&space) else {
                return Fate::Again(SLOT);
            };
            let Some(record) = &known.record else {
                return Fate::Again(SLOT);
            };
            if record.ended || !record.keys.contains(&anchor.signer) {
                return Fate::Done;
            }
            if rules::aged(&record.clock, window, now) {
                known.never.insert(window, AnchorCode::Age as u32);
                return Fate::Done;
            }
        }
        let Ok(held) = self.service.root(&space, window) else {
            return Fate::Again(SLOT);
        };
        {
            let mut read = self.read();
            let Some(known) = read.spaces.get_mut(&space) else {
                return Fate::Again(SLOT);
            };
            let last = known.record.as_ref().and_then(|record| record.last);
            match held {
                Some(root) if root == anchor.root => {
                    known.held.insert(window, Some(root));
                    return Fate::Done;
                }
                Some(root) => {
                    known.held.insert(window, Some(root));
                    if !known.evidence.contains(&window) {
                        return Fate::Done;
                    }
                }
                None if rules::passed(last, window) => {
                    known.held.insert(window, None);
                    known.never.insert(window, AnchorCode::Window as u32);
                    return Fate::Done;
                }
                None => {}
            }
        }
        let code = match self.service.land_anchor(anchor) {
            Ok(code) => code,
            Err(error) => {
                tracing::warn!(window, %error, "an anchor not landed: again a slot later");
                return Fate::Again(SLOT);
            }
        };
        let outcome = outcome(code);
        let mut read = self.read();
        let known = read.spaces.entry(space).or_default();
        match outcome {
            AnchorOutcome::Taken => {
                known.held.insert(window, Some(anchor.root));
                return Fate::Done;
            }
            AnchorOutcome::NotYet if code == AnchorCode::Open as u32 => return Fate::Again(SLOT),
            AnchorOutcome::NotYet => {}
            AnchorOutcome::Never(code) => {
                known.never.insert(window, code);
            }
            AnchorOutcome::Unlisted(_) => {
                if let Some(record) = &mut known.record {
                    record.keys.retain(|key| *key != anchor.signer);
                }
            }
            AnchorOutcome::Stopped(_) => {
                if let Some(record) = &mut known.record {
                    record.ended = true;
                }
            }
        }
        if code == AnchorCode::Equivocation as u32 {
            tracing::error!(
                window,
                "an equivocation: the JAM service holds another root of the space at this \
                 window, signed by a listed anchor key, and this node's anchor is its evidence, \
                 which ends the space for good; it re-founds under a new genesis"
            );
        } else {
            tracing::error!(window, code, ?outcome, "the JAM service refused an anchor");
        }
        match outcome {
            AnchorOutcome::NotYet => Fate::Again(AWHILE),
            _ => Fate::Done,
        }
    }
}

/// The anchors' sending, as the queue's worker drives it.
struct JamSend<S = Jam>(Arc<Shared<S>>);

impl<S: Service> AnchorSend for JamSend<S> {
    fn send(&self, anchor: &Anchor) -> Fate {
        self.0.send(anchor)
    }
}

/// The leader's outcome of an anchor the service answered `code`, the code
/// kept: `New` and `Again` taken; `Signature`, `Window` and `Age` never;
/// `Key` unlisted; `Ended` and `Equivocation` (this anchor the evidence)
/// stopped; `Open`, `Unregistered`, `Item` and any other (refine failed)
/// not yet.
pub fn outcome(code: u32) -> AnchorOutcome {
    use AnchorCode::*;
    match AnchorCode::try_from(code).ok() {
        Some(New | Again) => AnchorOutcome::Taken,
        Some(Signature | Window | Age) => AnchorOutcome::Never(code),
        Some(Key) => AnchorOutcome::Unlisted(code),
        Some(Ended | Equivocation) => AnchorOutcome::Stopped(code),
        _ => AnchorOutcome::NotYet,
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
        self.shared.service.id()
    }

    /// Answered at once from the last read; what is taken is queued, and
    /// the queue's worker lands it.
    fn anchor(&self, anchor: &Anchor) -> AnchorOutcome {
        if !vos_venue::signed(anchor, &self.id()) {
            return AnchorOutcome::Never(AnchorCode::Signature as u32);
        }
        let window = anchor.window;
        {
            let mut read = self.shared.read();
            self.shared.watch(&mut read, anchor.space);
            let Some(known) = read.spaces.get_mut(&anchor.space) else {
                return AnchorOutcome::NotYet;
            };
            let Some(record) = known.record.as_ref().filter(|_| known.read) else {
                return AnchorOutcome::NotYet;
            };
            if record.ended {
                return AnchorOutcome::Stopped(AnchorCode::Ended as u32);
            }
            if !record.keys.contains(&anchor.signer) {
                return AnchorOutcome::Unlisted(AnchorCode::Key as u32);
            }
            let last = record.last;
            if let Some(code) = known.never.get(&window) {
                return AnchorOutcome::Never(*code);
            }
            match known.held.get(&window) {
                Some(Some(root)) if *root == anchor.root => return AnchorOutcome::Taken,
                Some(Some(_)) => {
                    known.evidence.insert(window);
                }
                Some(None) if rules::passed(last, window) => {
                    return AnchorOutcome::Never(AnchorCode::Window as u32);
                }
                _ => {}
            }
        }
        self.queue.push(anchor);
        AnchorOutcome::Taken
    }

    /// A statement the service holds seen is accepted unsent: a package
    /// refined again only to be refused a repeat costs a whole refine.
    fn submit(&self, statement: &Statement, proof: &[u8]) -> SubmitOutcome {
        let id = statement.id();
        if let Ok(Some(_)) = self.statements.value(&keys::seen(&id)) {
            return SubmitOutcome::Accepted;
        }
        match self.submit_code(statement, proof) {
            Ok(code) => SubmitOutcome::judged(code),
            Err(_) => SubmitOutcome::Retry(UNJUDGED),
        }
    }

    /// The space's standing as last read; unregistered while unread.
    fn status(&self, space: &SpaceId) -> Status {
        let mut read = self.shared.read();
        self.shared.watch(&mut read, *space);
        match read
            .spaces
            .get(space)
            .and_then(|known| known.record.as_ref())
        {
            Some(record) if record.ended => Status::Ended,
            Some(_) => Status::Active,
            None => Status::Unregistered,
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
        let mut read = self.shared.read();
        self.shared.watch(&mut read, *space);
        read.spaces
            .get(space)
            .and_then(|known| known.record.as_ref())
            .map(|record| record.keys.clone())
            .unwrap_or_default()
    }

    /// The root read at `window`: none past the space's last anchored;
    /// unread at or behind it until the reader reads it.
    fn held(&self, space: &SpaceId, window: u64) -> Holding {
        let mut read = self.shared.read();
        self.shared.watch(&mut read, *space);
        let Some(known) = read.spaces.get_mut(space).filter(|known| known.read) else {
            return Holding::Unread;
        };
        let last = known.record.as_ref().and_then(|record| record.last);
        match known.held.get(&window) {
            Some(Some(root)) => Holding::Root(*root),
            Some(None) => Holding::Nothing,
            None if !rules::passed(last, window) => Holding::Nothing,
            None => {
                if known.wanted.insert(window) {
                    self.shared.wake.notify_all();
                }
                Holding::Unread
            }
        }
    }

    /// The finalized block's slot time (slot × 6 s from JAM's genesis
    /// time) as last read; none before.
    fn time(&self) -> Option<u64> {
        self.shared.read().now
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
    match RegisterCode::try_from(code) {
        Ok(RegisterCode::Registered) => "registered",
        Ok(RegisterCode::Item) => "undecodable",
        Ok(RegisterCode::Genesis) => "genesis",
        Ok(RegisterCode::Founder) => "not a founder, or its signature",
        Ok(RegisterCode::Again) => "registered already",
        Err(_) => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every anchor code has its outcome, the code kept: a key refused
    /// unlisted; a signature refused never, since signing again with the
    /// same key makes the same signature; an unregistered space not yet; a
    /// window the service will never take never; an ended space, or this
    /// anchor the evidence that ends it, stopped.
    #[test]
    fn each_anchor_code_has_its_outcome() {
        use AnchorCode::*;
        for (code, expected) in [
            (New, AnchorOutcome::Taken),
            (Again, AnchorOutcome::Taken),
            (Item, AnchorOutcome::NotYet),
            (Signature, AnchorOutcome::Never(Signature as u32)),
            (Unregistered, AnchorOutcome::NotYet),
            (Ended, AnchorOutcome::Stopped(Ended as u32)),
            (Key, AnchorOutcome::Unlisted(Key as u32)),
            (Window, AnchorOutcome::Never(Window as u32)),
            (Open, AnchorOutcome::NotYet),
            (Age, AnchorOutcome::Never(Age as u32)),
            (Equivocation, AnchorOutcome::Stopped(Equivocation as u32)),
        ] {
            assert_eq!(outcome(code as u32), expected, "{code:?}");
        }
        assert_eq!(outcome(0x1001), AnchorOutcome::NotYet, "refine failed");
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
                ..Operand::new(output)
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

        fn root(&self, space: &SpaceId, window: u64) -> Result<Option<[u8; 32]>, Error> {
            Ok(self
                .read(&keys::anchor(space, RootKind::Space, window))
                .and_then(|bytes| AnchorRecord::decode(&bytes).ok())
                .map(|record| record.root))
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
    /// node's anchor of it is not sent over it, the root read; offered
    /// again once read, as the leader does once its divergence guard
    /// passed, it is sent, the equivocation's evidence, which ends the
    /// space.
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

        let shared = Shared::new(Arc::clone(&local));
        let ours = anchor(1, &honest);
        shared.watch(&mut shared.read(), space);
        shared.refresh().unwrap();
        assert_eq!(shared.send(&ours), Fate::Done, "not sent over another root");
        assert!(!local.space(&space).unwrap().unwrap().ended);
        assert_eq!(
            shared.read().spaces[&space].held.get(&window),
            Some(&Some([9; 32])),
            "the root read"
        );
        shared
            .read()
            .spaces
            .get_mut(&space)
            .unwrap()
            .evidence
            .insert(window);
        assert_eq!(shared.send(&ours), Fate::Done, "sent, the evidence");
        let record = local.space(&space).unwrap().unwrap();
        assert!(record.ended);
        let evidence = local
            .read(&keys::evidence(&space, RootKind::Space, window))
            .expect("the evidence");
        let evidence = Evidence::decode(&evidence).unwrap();
        assert_eq!(evidence.held.signer, stolen.verifying_key().to_bytes());
        assert_eq!(evidence.other.signer, honest.verifying_key().to_bytes());
        assert!(shared.read().spaces[&space].record.as_ref().unwrap().ended);
    }

    /// An anchor is answered at once, whatever the node: one of a node
    /// that never answers returns within 500 ms, a signature's check in a
    /// debug build on a loaded host and no wait on the node, whose calls
    /// time out in seconds; one not signed over this venue's digest is
    /// never taken.
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
        let venue = JamVenue::over(jam);
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut anchor = Anchor {
            space: SpaceId([1; 32]),
            window: 5,
            kind: RootKind::Space,
            root: [2; 32],
            signer: key.verifying_key().to_bytes(),
            signature: [0; 64],
        };
        assert_eq!(
            venue.anchor(&anchor),
            AnchorOutcome::Never(AnchorCode::Signature as u32)
        );
        anchor.signature = key.sign(&anchor.digest(&venue.id())).to_bytes();
        let start = Instant::now();
        assert_eq!(venue.anchor(&anchor), AnchorOutcome::NotYet, "unread");
        assert_eq!(venue.held(&anchor.space, 5), Holding::Unread);
        assert_eq!(venue.status(&anchor.space), Status::Unregistered);
        let took = start.elapsed();
        assert!(took < Duration::from_millis(500), "{took:?}");
    }
}
