//! The run's clients and prover, each wrapped to keep what the run
//! measures and audits: every judgement and when it came, the JAM
//! service's outcomes and the packages they landed in, the Kreivo mock's
//! signed envelopes, and each proof's time.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use vos_node_prover::masked::Disclosing;
use vos_node_prover::{Internals, ProveError, Prover};
use vos_statement_service::item::Item;
use vos_statement_service::state::{Outcome, keys};
use vos_venue::jam::JamVenue;
use vos_venue::kreivo::Transport;
use vos_venue::kreivo::calls::AccountId;
use vos_venue::kreivo::transport::{Included, Lost, SendError, Signed};
use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{AnchorRefusal, Anchored, NotAccepted, Status, Unjudged, VenueClient};
use vos_wire::result::Attest;
use vos_wire::vos_anchor::{Anchor, RootRead, SpaceId, VenueId};

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A proof made: its record, how long it took, and when it ended.
#[derive(Clone)]
pub struct Proved {
    pub attest: Attest,
    pub took: Duration,
    pub ended_ms: u64,
}

impl Proved {
    /// Whether it proved `statement`'s run.
    pub fn of(&self, statement: &Statement) -> bool {
        self.attest.public_args == statement.public_args
            && self.attest.output == statement.output
            && self.attest.roots == statement.roots
    }
}

/// The disclosing masked prover, one proof at a time across every node and
/// the run itself: a masked proof takes about 6 GiB.
#[derive(Default)]
pub struct Serial {
    masked: Disclosing,
    proved: Mutex<Vec<Proved>>,
}

impl Serial {
    /// Every statement proved: its record and its proof's internals.
    pub fn made(&self) -> Vec<(Attest, Internals)> {
        self.masked.made()
    }

    /// Every proof's time.
    pub fn proved(&self) -> Vec<Proved> {
        lock(&self.proved).clone()
    }
}

impl Prover for Serial {
    fn program(&self, kernel: &[u8]) -> Result<ProgramId, ProveError> {
        self.masked.program(kernel)
    }

    fn prove(&self, kernel: &[u8], attest: &Attest) -> Result<Vec<u8>, ProveError> {
        let mut proved = lock(&self.proved);
        let start = Instant::now();
        let proof = self.masked.prove(kernel, attest)?;
        proved.push(Proved {
            attest: attest.clone(),
            took: start.elapsed(),
            ended_ms: vos_node::wall_clock(),
        });
        Ok(proof)
    }
}

/// A venue's answer to a submission, and when it came.
#[derive(Clone, Debug)]
pub struct Judgement {
    pub statement: Statement,
    pub answer: Result<StatementId, NotAccepted>,
    pub at_ms: u64,
}

/// A venue's client, each submission's answer kept with its time.
pub struct Recorded {
    inner: Arc<dyn VenueClient>,
    judged: Mutex<Vec<Judgement>>,
}

impl Recorded {
    pub fn new(inner: Arc<dyn VenueClient>) -> Self {
        Self {
            inner,
            judged: Mutex::default(),
        }
    }

    pub fn judged(&self) -> Vec<Judgement> {
        lock(&self.judged).clone()
    }
}

impl VenueClient for Recorded {
    fn id(&self) -> VenueId {
        self.inner.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        self.inner.anchor(anchor)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        let answer = self.inner.submit(statement, proof);
        lock(&self.judged).push(Judgement {
            statement: statement.clone(),
            answer,
            at_ms: vos_node::wall_clock(),
        });
        answer
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.inner.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.inner.anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.inner.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.inner.time()
    }
}

/// An item the run landed at the JAM service: what it was, its outcome,
/// and the work report a guarantor made of its package, once read.
#[derive(Clone)]
pub struct Landed {
    pub what: String,
    pub outcome: Outcome,
    pub report: Arc<OnceLock<Vec<u8>>>,
}

impl Landed {
    /// Its package's work report, once read: none past `within`.
    pub fn report(&self, within: Duration) -> Option<Vec<u8>> {
        vos_checker::poll(within, || self.report.get().is_some());
        self.report.get().cloned()
    }
}

/// How long a landed package's report may take to show.
const REPORTED: Duration = Duration::from_secs(60);

/// The JAM statements service as a venue, as `JamVenue` is, each
/// submission landed by the run so its outcome, its refine gas and its
/// package's work report are kept.
pub struct Jam {
    pub venue: JamVenue,
    landed: Mutex<Vec<Landed>>,
}

impl Jam {
    pub fn new(venue: JamVenue) -> Self {
        Self {
            venue,
            landed: Mutex::default(),
        }
    }

    /// Land an item: its outcome, kept as `what`. Its package's work report
    /// is read apart, while the chain's status of the package names it, so
    /// the answer does not wait for it.
    pub fn land(
        &self,
        what: impl Into<String>,
        payload: Vec<u8>,
        extrinsics: Vec<Vec<u8>>,
    ) -> Result<Outcome, vos_jam::Error> {
        let (package, outcome) = self.venue.land_package(payload, extrinsics)?;
        let report = Arc::new(OnceLock::new());
        let (node, read) = (self.venue.statements.node.clone(), Arc::clone(&report));
        std::thread::spawn(move || {
            vos_checker::poll(REPORTED, || match node.work_report(&package) {
                Ok(Some(bytes)) => read.set(bytes).is_ok(),
                _ => false,
            });
        });
        lock(&self.landed).push(Landed {
            what: what.into(),
            outcome,
            report,
        });
        Ok(outcome)
    }

    /// Submit `statement` with its final proof as its item's extrinsic, a
    /// repeat sent too: its outcome.
    pub fn judge(&self, statement: &Statement, proof: &[u8]) -> Result<Outcome, vos_jam::Error> {
        let what = format!("statement {}", hex(&statement.id().0[..8]));
        let payload = Item::Submit(statement.encode()).encode();
        self.land(what, payload, vec![proof.to_vec()])
    }

    /// Every item the run landed.
    pub fn landed(&self) -> Vec<Landed> {
        lock(&self.landed).clone()
    }
}

/// The JAM venue's answers, as `JamVenue::submit` gives them: a statement
/// the service holds seen accepted unsent, a code of 0 or 6 accepted.
impl VenueClient for Jam {
    fn id(&self) -> VenueId {
        self.venue.id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        self.venue.anchor(anchor)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        let id = statement.id();
        if let Ok(Some(_)) = self.venue.statements.value(&keys::seen(&id)) {
            return Ok(id);
        }
        match self.judge(statement, proof) {
            Ok(outcome) if outcome.code == 0 || outcome.code == 6 => Ok(id),
            Ok(outcome) => Err(NotAccepted::Refused(outcome.code)),
            Err(_) => Err(NotAccepted::Unjudged(Unjudged::Unknown)),
        }
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.venue.anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.venue.anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.venue.status(space)
    }

    fn time(&self) -> Option<u64> {
        self.venue.time()
    }
}

/// A node's venue as its operator reconfigures it when the space migrates:
/// the old venue's client until `moved`, the new one's after.
pub struct Migrating {
    pub before: Arc<dyn VenueClient>,
    pub after: Arc<dyn VenueClient>,
    pub moved: Arc<AtomicBool>,
}

impl Migrating {
    fn current(&self) -> &Arc<dyn VenueClient> {
        if self.moved.load(Ordering::SeqCst) {
            &self.after
        } else {
            &self.before
        }
    }
}

impl VenueClient for Migrating {
    fn id(&self) -> VenueId {
        self.current().id()
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        self.current().anchor(anchor)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        self.current().submit(statement, proof)
    }

    fn anchored(&self, root: &RootRead) -> bool {
        self.current().anchored(root)
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.current().anchor_keys(space)
    }

    fn status(&self, space: &SpaceId) -> Status {
        self.current().status(space)
    }

    fn time(&self) -> Option<u64> {
        self.current().time()
    }
}

/// A signer's transport to the Kreivo mock, every extrinsic it signs kept:
/// the envelopes the chain is sent.
pub struct Enveloped {
    pub inner: Arc<dyn Transport>,
    pub envelopes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Transport for Enveloped {
    fn account(&self) -> AccountId {
        self.inner.account()
    }

    fn genesis(&self) -> Result<[u8; 32], Lost> {
        self.inner.genesis()
    }

    fn best(&self) -> Result<u64, Lost> {
        self.inner.best()
    }

    fn nonce(&self) -> Result<u64, Lost> {
        self.inner.nonce()
    }

    fn chain_nonce(&self) -> Result<u64, Lost> {
        self.inner.chain_nonce()
    }

    fn sign(&self, call: &[u8], nonce: u64) -> Result<Signed, SendError> {
        let signed = self.inner.sign(call, nonce)?;
        lock(&self.envelopes).push(signed.bytes.clone());
        Ok(signed)
    }

    fn send(&self, signed: &Signed) -> Result<Included, SendError> {
        self.inner.send(signed)
    }

    fn storage(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Lost> {
        self.inner.storage(key)
    }

    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Lost> {
        self.inner.keys(prefix)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
