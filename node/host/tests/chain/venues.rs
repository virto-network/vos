//! The run's clients and prover, each wrapped to keep what the run
//! measures and audits: every judgement and when it came, every work
//! package a JAM service's client sent and its work report, the Kreivo
//! mock's signed envelopes, and each proof's time.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use vos_jam_dev::JamVenue;
use vos_jam_dev::live::{PolkaJam, Watch};
use vos_node_prover::masked::Disclosing;
use vos_node_prover::{Internals, ProveError, Prover};
use vos_statement_service::state::Outcome;
use vos_venue::kreivo::Transport;
use vos_venue::kreivo::calls::AccountId;
use vos_venue::kreivo::transport::{Included, Lost, SendError, Signed};
use vos_venue::vos_statement::{ProgramId, Statement, StatementId};
use vos_venue::{NotAccepted, VenueClient};
use vos_wire::result::Attest;

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

vos_venue::forward_venue!(Recorded => inner; forward [id, anchor, anchored, anchor_keys, status, time, unsettled] {
    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, NotAccepted> {
        let answer = self.inner.submit(statement, proof);
        lock(&self.judged).push(Judgement {
            statement: statement.clone(),
            answer,
            at_ms: vos_node::wall_clock(),
        });
        answer
    }
});

/// A work package sent to a JAM service, as it went: its encoding, its
/// extrinsics, and the work report a guarantor made of it, once read.
#[derive(Clone)]
pub struct Sent {
    pub package: Vec<u8>,
    pub extrinsics: Vec<Vec<u8>>,
    pub report: Arc<OnceLock<Vec<u8>>>,
    /// Whether the node answered that it took it: none until it answered.
    pub taken: Arc<OnceLock<bool>>,
}

impl Sent {
    /// Its work report, once read: none past `within`.
    pub fn report(&self, within: Duration) -> Option<Vec<u8>> {
        vos_checker::poll(within, || self.report.get().is_some());
        self.report.get().cloned()
    }
}

/// How long a sent package's report may take to show.
pub const REPORTED: Duration = Duration::from_secs(90);

/// Every work package a JAM service's client sent, anchors, registrations
/// and statements alike (`vos_jam_dev::live::Watch`), each one's work report
/// read apart while the chain's status of the package names it.
#[derive(Default)]
pub struct Wire(Mutex<Vec<Sent>>);

impl Wire {
    /// The watch to set on `node`, the client that sends: each package
    /// kept as it goes, its report read apart, whether the node answers it
    /// took it or not (an answer lost, the package taken all the same).
    pub fn watch(self: &Arc<Self>, node: &PolkaJam) -> Watch {
        let (wire, node) = (Arc::clone(self), node.clone());
        Watch(Arc::new(
            move |package: &[u8], extrinsics: &[Vec<u8>], taken: Option<bool>| {
                if let Some(taken) = taken {
                    if let Some(sent) = lock(&wire.0)
                        .iter()
                        .rev()
                        .find(|sent| sent.package == package)
                    {
                        let _ = sent.taken.set(taken);
                    }
                    return;
                }
                let report = Arc::new(OnceLock::new());
                lock(&wire.0).push(Sent {
                    package: package.to_vec(),
                    extrinsics: extrinsics.to_vec(),
                    report: Arc::clone(&report),
                    taken: Arc::new(OnceLock::new()),
                });
                let (node, package) = (node.clone(), package.to_vec());
                std::thread::spawn(move || {
                    vos_checker::poll(REPORTED, || match node.work_report(&package) {
                        Ok(Some(bytes)) => report.set(bytes).is_ok(),
                        _ => false,
                    });
                });
            },
        ))
    }

    /// The packages sent so far.
    pub fn sent(&self) -> Vec<Sent> {
        lock(&self.0).clone()
    }

    /// The outcome the service keeps of the item `payload` in any package
    /// sent, as its finalized block holds it.
    pub fn outcome(&self, jam: &JamVenue, payload: &[u8]) -> Option<Outcome> {
        self.sent().iter().find_map(|sent| {
            jam.statements
                .outcome(&vos_wire::result::digest(&sent.package), payload)
                .ok()
                .flatten()
        })
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
