//! The builder: an agent's batches made packages that fit a work package,
//! submitted, and taken into its store once the chain holds their roots.
//!
//! **Fitting a package:**
//! - **The budget** a batch starts at is what the work package's refine gas
//!   leaves past a margin for the estimate ([`MARGIN`]) and past
//!   [`OWN_BOUND`], a bound on the package's own work: 900M of PolkaJam's
//!   1e9. That is above the least budget a VOS node refines with,
//!   `defaults::min_refine_gas(MAX_INPUTS)`, about 674M, the floor. A
//!   builder refuses a chain whose refine gas gives less, as a VOS node
//!   refuses such a config.
//! - **A package whose own work passes the bound** has its budget lowered
//!   to what the refine gas leaves past it ([`crate::gas`] estimates it),
//!   but never below the floor while the batch can lose an input, or a
//!   sweep a row: it shrinks first, so its other inputs' own work never
//!   fails a step a VOS node runs, but for a lone input past the usable
//!   gas, below. Only a batch that cannot shrink goes
//!   below the floor; one whose own work passes the usable gas is tried
//!   once more at the floor, or at the lowest budget the floor refused it
//!   while larger, where its step may fail `Cap` with fewer effects.
//! - **[`WORST_ENDING`] bounds the step that ends a workflow** in a package
//!   of its own, at the largest limit, restoring and dropping all of
//!   `cap::HELD_PAGES`, 576: its keep, its decoding, and the own work of
//!   its bookkeeping, the ending's ([`gas::ENDING`]) and each page's
//!   ([`gas::PAGE_READ`], about 123k, and [`gas::PAGE_DROP`], about 115k).
//!   That is about 913M of PolkaJam's 950M usable, asserted. It leaves out
//!   the step's own effects, which at the agent's caps take far more own
//!   work: `cap::STEP_WRITES` of writes about 105M in rows of 64 KiB, and up
//!   to about 450M as the 3,125 puts of a step's 200M; each of
//!   `cap::MESSAGES` messages about 26M; each of `cap::ATTESTS` attests
//!   about 28M. A step's gas trades puts against messages and attests, so
//!   its effects take about 1.15e9 at most, and the worst step with them
//!   about 2.06e9. So, for a step alone in its package:
//!   - **(a)** a workflow's step whose own effects fit the usable gas but
//!     pass what its keep leaves of it, about 37M at the page cap, fails
//!     `Cap` on JAM only, where a VOS node runs it;
//!   - **(b)** an input whose own work passes the usable gas even at the
//!     floor, its step's effects about 0.7e9 at the page cap or about 0.85e9
//!     with no page held, leaves no package to make: `prepare` answers
//!     `Error::Unfit`, and the builder stalls on it;
//!   - **(c)** a request's or a call's step never fails `Cap`: below its
//!     keep the batch leaves it undispatched, and it waits.
//!
//!   Open: closing (a) and (b) would take the per-step effect caps down,
//!   for an agent on JAM, about 31-fold, until their own work fits what
//!   the keep leaves.
//! - **Its exports and imports** are at most a package's segments, and its
//!   payload at most a package's input. A batch that does not fit loses its
//!   later inputs, and a sweep its later rows, which wait for the next; a
//!   batch holds at most [`MAX_INPUTS`].
//!
//! **Pages in DA:** a workflow whose snapshot holds a page DA no longer
//! has, by where the store says it was exported, has its rows left out of
//! the batch's sweeps before the batch is simulated, all such workflows at
//! once, so it stays due and the rest of the batch goes on. The check
//! takes the rows a sweep's step would: at most `defaults::SWEEP_LIMIT` of
//! them, due by the batch's time, each still in the due index, the
//! record due there and not ended. It cannot tell which the budget would
//! step: a lacking workflow's rows are left out even where the batch would
//! have stopped before them, so the rows after them may step where they
//! would have waited. A page is fetched once a prepare, whichever check or
//! simulation asks, and a place the store cannot read counts as one DA
//! lacks, for both. Nothing exports a workflow's pages again: one that
//! sleeps or awaits past DA's retention stays due and never resumes. Open:
//! pages exported again before retention ends, or a deterministic failure
//! for pages lost.
//!
//! **Taking a package:** once the chain holds the root its writes make,
//! the builder reads its work result back from its exports, which must be
//! the one it simulated, and commits it to its store.
//!
//! **Recovery:** a package the chain refused (its refine trapped or ran
//! out of gas, or accumulate refused its time or root) left the chain's
//! root where it was: the builder makes the batch again, at a new time, and
//! submits it. When the chain holds the root an earlier attempt's package
//! makes, that attempt landed late, and the builder takes it. When it holds
//! another, another package landed first: the builder takes that one from
//! its exports, when it leads from the store's root to the chain's, and
//! makes its own again from there; otherwise it stops, its store left as it
//! was.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, VerifyingKey};
use vos_wire::abi::cap;
use vos_wire::batch::{Batch, Input, Request, Work};
use vos_wire::ids::{Principal, ProgramHash, WorkflowId};
use vos_wire::ingress::{Call, call_message};
use vos_wire::keys::Due;
use vos_wire::package::{Exports, MAX_SEGMENTS, Package, SEGMENT, result_segments};
use vos_wire::records::{Workflow, WorkflowState, unstored};
use vos_wire::result::{PAGE, Page, Step, WorkResult, digest};
use vos_wire::{Decode, Encode, defaults, keys};

use crate::chain::{Chain, Landed};
use crate::da::Segments;
use crate::simulate::{Pages, Runner, Simulation, simulate};
use crate::store::{Exported, Pending, Store, View};
use crate::witness::witness;
use crate::{Error, gas};

/// The largest work package input the builder makes: PolkaJam's
/// `max_input` (`W_B`) is 13,791,360 bytes, imports and all.
pub const MAX_INPUT: usize = 12 << 20;
/// What a package's refine keeps past its estimate, in parts of a
/// thousand of its gas.
pub const MARGIN: u64 = 50;
/// A bound on a package's own work beyond its batch's budget: its refine's
/// start ([`defaults::refine_start`]) and what [`gas::own`] estimates. The
/// builder's estimates, PolkaJam reporting no refine gas: 3.3M to 13.5M in
/// the testnet run's packages, and at most 4.9M for a workflow's package
/// resumed across packages in the JAM-only host's comparison. So the bound
/// holds the packages that neither witness hundreds of rows nor write
/// them, with room; one that does lowers its budget by the excess.
pub const OWN_BOUND: u64 = 50_000_000;
/// The most inputs a batch the builder makes may hold: a VOS node's
/// default, by which its least budget is reckoned.
pub const MAX_INPUTS: usize = 256;
/// PolkaJam's refine gas for a work package, `G_R`.
pub const POLKAJAM_REFINE_GAS: u64 = 1_000_000_000;
/// The times the builder makes a batch again before it stops.
const ATTEMPTS: usize = 4;

/// What a work package of `refine_gas` leaves for its batch and its own
/// work, past the margin.
const fn usable(refine_gas: u64) -> u64 {
    refine_gas - refine_gas / 1000 * MARGIN
}

/// The budget a batch starts at in a work package of `refine_gas`: what it
/// leaves past the margin and [`OWN_BOUND`].
pub const fn budget(refine_gas: u64) -> u64 {
    usable(refine_gas).saturating_sub(OWN_BOUND)
}

// A package on PolkaJam whose own work stays within the bound gives its
// batch at least the budget a VOS node refines with.
const _: () = assert!(defaults::min_refine_gas(MAX_INPUTS) <= budget(POLKAJAM_REFINE_GAS));

/// The refine gas of a package holding only the worst step that ends a
/// workflow, bar its own effects: one at the largest limit a workflow may
/// declare, which restores every page a snapshot may hold and drops every
/// one's row. Its batch keeps what a VOS node refines with at the least,
/// which holds that step's keep; then its decoding, at the most inputs a
/// batch holds, and its own work, the ending's bookkeeping and each
/// page's. The step's own effects, and other inputs', are not in it (the
/// module's doc says what they leave).
pub const WORST_ENDING: u64 = defaults::min_refine_gas(MAX_INPUTS)
    + defaults::refine_start(
        MAX_INPUTS,
        gas::ENDING_PAYLOAD + cap::HELD_PAGES * gas::PAGE_PAYLOAD,
    )
    + gas::ENDING
    + cap::HELD_PAGES as u64 * (gas::PAGE_READ + gas::PAGE_DROP);

// On PolkaJam that package fits, its budget lowered by its own work: a
// workflow a VOS node runs to its end, a package runs to its end, but for
// its last step's own effects.
const _: () = assert!(WORST_ENDING <= usable(POLKAJAM_REFINE_GAS));

/// A batch made a package: its simulation, the package and its encoding,
/// where each of its imports was exported, in its order, the refine gas it
/// needs and the part of it the package's own work takes, the store once
/// it lands, the workflows whose due steps it leaves out, their pages gone
/// from DA, and the simulations making it took.
#[derive(Clone, Debug)]
pub struct Prepared {
    pub simulation: Simulation,
    pub package: Package,
    pub payload: Vec<u8>,
    pub segments: Vec<Exported>,
    pub gas: u64,
    pub own: u64,
    pub pending: Pending,
    pub skipped: Vec<WorkflowId>,
    pub simulations: u32,
}

impl Prepared {
    /// The segments the package exports: its pages, then its work result.
    pub fn exports(&self) -> u32 {
        (self.simulation.pages + result_segments(self.simulation.encoded.len())) as u32
    }
}

/// What became of an attempt to land a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fate {
    /// The chain took its package.
    Landed,
    /// The chain's root did not move within its package's window.
    Refused,
    /// Another package landed first, which the builder took.
    Overtaken,
    /// An earlier attempt's package landed after all, and was taken.
    Superseded,
}

/// An attempt: its batch's time, what the chain said of the submission,
/// and its fate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    pub time: u64,
    pub submitted: String,
    pub fate: Fate,
}

/// A batch landed: the package that did, the work result the chain holds,
/// as its exports encode it, where they are, and every attempt it took.
#[derive(Debug)]
pub struct Taken {
    pub prepared: Prepared,
    pub result: WorkResult,
    pub encoded: Vec<u8>,
    pub exports: Exports,
    pub attempts: Vec<Attempt>,
}

/// An agent's builder: its store, and the refine gas a work package has.
pub struct Builder {
    pub store: Store,
    refine_gas: u64,
}

impl Builder {
    /// A builder over `store` for a chain whose work packages each have
    /// `refine_gas`: refused, `Error::RefineGas`, when that gives a batch
    /// less than the least budget a VOS node refines with.
    pub fn new(store: Store, refine_gas: u64) -> Result<Self, Error> {
        let least = defaults::min_refine_gas(MAX_INPUTS);
        if budget(refine_gas) < least {
            return Err(Error::RefineGas { refine_gas, least });
        }
        Ok(Self { store, refine_gas })
    }

    /// The refine gas a work package has.
    pub fn refine_gas(&self) -> u64 {
        self.refine_gas
    }

    /// The agent's state version: the work results its store took.
    pub fn version(&self) -> Result<u64, Error> {
        record(&self.store.view(), &keys::version()).map(|version| version.unwrap_or(0))
    }

    /// `inputs` at `time` and `seed`, with `solicit`, made a package on the
    /// store as it stands, its pages read from `segments`. Inputs past
    /// [`MAX_INPUTS`], and later inputs and a sweep's later rows that do not
    /// fit, are left out to wait for a later package, as are the rows of
    /// workflows whose pages DA lacks.
    pub fn prepare(
        &self,
        runner: &Runner,
        segments: Arc<dyn Segments>,
        mut inputs: Vec<Input>,
        time: u64,
        seed: [u8; 32],
        solicit: &[(ProgramHash, u32)],
    ) -> Result<Prepared, Error> {
        let view = self.store.view();
        let version = self.version()?;
        let mut fitting = Fitting::new(self.refine_gas);
        inputs.truncate(MAX_INPUTS);
        let fetched = Arc::new(Fetched::new(view.clone(), segments));
        let mut skipped = lacking(&view, &fetched, &inputs, time);
        for workflow in &skipped {
            skip(&mut inputs, *workflow);
        }
        let pages: Pages = {
            let fetched = Arc::clone(&fetched);
            Arc::new(move |workflow, index| fetched.page(workflow, index))
        };
        let mut simulations = 0;
        loop {
            let batch = Batch {
                version,
                time,
                seed,
                budget: fitting.budget,
                inputs: inputs.clone(),
            };
            simulations += 1;
            let prepared = match self.package(runner, &view, Arc::clone(&pages), batch, solicit) {
                // A page DA lacks that `lacking` did not find: a sweep's
                // workflow is left out all the same, and any other input's
                // fails the batch.
                Err(Error::Page(workflow, index)) => {
                    if !skip(&mut inputs, workflow) {
                        return Err(Error::Page(workflow, index));
                    }
                    skipped.push(workflow);
                    continue;
                }
                prepared => prepared?,
            };
            let start = defaults::refine_start(inputs.len(), prepared.payload.len() + 64);
            let own = gas::own(&prepared.package, &prepared.simulation);
            let fits = prepared.exports() as usize <= MAX_SEGMENTS
                && prepared.segments.len() <= MAX_SEGMENTS
                && prepared.payload.len() + prepared.segments.len() * SEGMENT <= MAX_INPUT;
            match fitting.next(fits, own + start, shrinks(&inputs)) {
                Next::Take => {
                    return Ok(Prepared {
                        gas: fitting.budget + start + own,
                        own,
                        skipped,
                        simulations,
                        ..prepared
                    });
                }
                Next::Again => {}
                Next::Shrink => {
                    shrink(&mut inputs);
                }
                Next::Unfit => return Err(Error::Unfit),
            }
        }
    }

    /// `batch` made a package on `view`, the pages its workflows hold from
    /// `pages`.
    fn package(
        &self,
        runner: &Runner,
        view: &View,
        pages: Pages,
        batch: Batch,
        solicit: &[(ProgramHash, u32)],
    ) -> Result<Prepared, Error> {
        let simulation = simulate(runner, view, pages, &batch)?;
        let witness = witness(view, &simulation)?;
        let segments = simulation
            .imports
            .iter()
            .map(|&(workflow, index)| {
                view.page(workflow, index)?
                    .ok_or(Error::Page(workflow, index))
            })
            .collect::<Result<_, _>>()?;
        let pending = view.stage(simulation.writes.clone(), &batch.seed)?;
        let package = Package {
            batch,
            root: view.root()?,
            witness,
            imports: simulation.imports.clone(),
            solicit: solicit.to_vec(),
        };
        Ok(Prepared {
            payload: Work::Package(package.clone()).encode(),
            simulation,
            package,
            segments,
            gas: 0,
            own: 0,
            pending,
            skipped: Vec::new(),
            simulations: 0,
        })
    }

    /// The segments `prepared`'s package imports, from `segments`.
    pub fn imports(
        &self,
        prepared: &Prepared,
        segments: &dyn Segments,
    ) -> Result<Vec<Vec<u8>>, Error> {
        prepared
            .package
            .imports
            .iter()
            .zip(&prepared.segments)
            .map(|(&(workflow, index), (root, at))| {
                segments
                    .segment(root, *at)
                    .ok_or(Error::Page(workflow, index))
            })
            .collect()
    }

    /// Take `prepared`'s package once the chain holds `landed`: the work
    /// result its exports hold, read from `segments`, which must be the one
    /// simulated, as it encodes it; its rows; and its pages, where `landed`
    /// says they were exported. Refused, `Error::Unaccumulated`, when the
    /// chain holds the root the package was built on; `Error::Root` when it
    /// holds another; on any error the store is left as it was.
    pub fn accept(
        &mut self,
        prepared: &Prepared,
        landed: &Landed,
        segments: &dyn Segments,
    ) -> Result<(WorkResult, Vec<u8>), Error> {
        if self.store.root()? != prepared.package.root {
            return Err(Error::Root);
        }
        if landed.root != prepared.pending.root {
            return Err(match landed.root == prepared.package.root {
                true => Error::Unaccumulated,
                false => Error::Root,
            });
        }
        let exports = landed.exports.ok_or(Error::Exports)?;
        let (result, encoded) = exported_result(segments, &exports)?;
        if encoded != prepared.simulation.encoded {
            return Err(Error::Result);
        }
        let mut pending = prepared.pending.clone();
        record_pages(&mut pending, &result, &exports)?;
        self.store.commit(pending)?;
        Ok((result, encoded))
    }

    /// Run `inputs` on `chain` until a package of them lands. Each attempt
    /// takes its time and seed from `clock`. A package the chain refused is
    /// made again; one that lost the root to another is made again on that
    /// other's result, once taken.
    pub fn run(
        &mut self,
        chain: &mut dyn Chain,
        runner: &Runner,
        inputs: &[Input],
        clock: &mut dyn FnMut() -> (u64, [u8; 32]),
        solicit: &[(ProgramHash, u32)],
    ) -> Result<Taken, Error> {
        let mut tried: Vec<Prepared> = Vec::new();
        let mut attempts = Vec::new();
        for _ in 0..ATTEMPTS {
            let (time, seed) = clock();
            let segments = chain.segments();
            let prepared = self.prepare(
                runner,
                Arc::clone(&segments),
                inputs.to_vec(),
                time,
                seed,
                solicit,
            )?;
            let submitted = chain.submit(runner, &prepared)?;
            let landed = chain.wait(&prepared)?;
            let segments = chain.segments();
            tried.push(prepared);
            let root = self.store.root()?;
            let landing = tried.iter().rposition(|prepared| {
                prepared.package.root == root && prepared.pending.root == landed.root
            });
            if let Some(at) = landing {
                let fate = match at + 1 == tried.len() {
                    true => Fate::Landed,
                    false => Fate::Superseded,
                };
                attempts.push(Attempt {
                    time,
                    submitted,
                    fate,
                });
                let prepared = tried.swap_remove(at);
                let (result, encoded) = self.accept(&prepared, &landed, segments.as_ref())?;
                return Ok(Taken {
                    prepared,
                    result,
                    encoded,
                    exports: landed.exports.ok_or(Error::Exports)?,
                    attempts,
                });
            }
            let fate = if landed.root == root {
                Fate::Refused
            } else {
                self.resync(chain, &landed)?;
                tried.clear();
                Fate::Overtaken
            };
            attempts.push(Attempt {
                time,
                submitted,
                fate,
            });
        }
        Err(Error::Attempts(attempts))
    }

    /// Take the package that landed instead of the builder's, from its
    /// exports: when its work result leads from the store's root to the
    /// chain's. Otherwise the store has fallen behind by more than one
    /// package, or holds another history: `Error::Diverged`.
    pub fn resync(&mut self, chain: &dyn Chain, landed: &Landed) -> Result<WorkResult, Error> {
        let exports = landed.exports.ok_or(Error::Diverged)?;
        let (result, _) =
            exported_result(chain.segments().as_ref(), &exports).map_err(|_| Error::Diverged)?;
        let view = self.store.view();
        let writes = view
            .writes(&result, &mut Default::default())?
            .ok_or(Error::Diverged)?;
        let mut pending = view.stage(writes, &result.seed)?;
        if pending.root != landed.root {
            return Err(Error::Diverged);
        }
        record_pages(&mut pending, &result, &exports)?;
        self.store.commit(pending)?;
        Ok(result)
    }

    /// The sweep a batch at `time` starts with: the rows of the due index
    /// due by then, the earliest first, at most a sweep's, as a VOS leader
    /// lists them; `None` when none is due.
    pub fn sweep(&self, time: u64) -> Result<Option<Input>, Error> {
        let prefix = keys::due_prefix();
        let mut due = Vec::new();
        for row in self.store.view().rows_from(&prefix) {
            let (key, _) = row?;
            if !key.starts_with(&prefix) {
                break;
            }
            // A key that names no row of the index is passed over, as a VOS
            // leader passes it.
            match keys::due_entry(&key) {
                Some((at, entry)) if at <= time && due.len() < defaults::SWEEP_LIMIT => {
                    due.push((at, entry));
                }
                Some(_) => break,
                None => {}
            }
        }
        Ok((!due.is_empty()).then_some(Input::Sweep { due }))
    }

    /// Workflow `id`, read for `owner`: its record, `None` when there is no
    /// such workflow or it is another's, as a VOS node answers its owner.
    pub fn workflow(&self, owner: &Principal, id: WorkflowId) -> Result<Option<Workflow>, Error> {
        let record: Option<Workflow> = record(&self.store.view(), &keys::workflow(id))?;
        Ok(record.filter(|workflow| workflow.owner == *owner))
    }
}

/// A client's call to the agent of JAM service `service`, as its builder
/// takes it: signed by its session's key, as a VOS node's ingress checks
/// it, else `Error::Signature`.
pub fn admit(service: u64, call: Call) -> Result<Input, Error> {
    let message = call_message(
        &vos_wire::package::identity(service),
        &call.session,
        call.sequence,
        call.instance,
        call.method,
        &call.arguments,
    );
    let signed = VerifyingKey::from_bytes(&call.session.key).is_ok_and(|key| {
        key.verify_strict(&message, &Signature::from_bytes(&call.signature))
            .is_ok()
    });
    if !signed {
        return Err(Error::Signature);
    }
    Ok(Input::Request(Request {
        session: call.session,
        sequence: call.sequence,
        caller: Principal::Client(call.session.key),
        instance: call.instance,
        method: call.method,
        arguments: call.arguments,
    }))
}

/// The work result a package's exports hold, after its pages, and its
/// encoding: the segments decode to it, then zeros.
fn exported_result(
    segments: &dyn Segments,
    exports: &Exports,
) -> Result<(WorkResult, Vec<u8>), Error> {
    let mut bytes = Vec::new();
    for index in exports.pages..exports.segments {
        bytes.extend(
            segments
                .segment(&exports.root, index)
                .ok_or(Error::Exports)?,
        );
    }
    let (result, used) = WorkResult::decode(&bytes).map_err(|_| Error::Exports)?;
    if bytes[used..].iter().any(|byte| *byte != 0) {
        return Err(Error::Exports);
    }
    bytes.truncate(used);
    Ok((result, bytes))
}

/// Leave `inputs` smaller: their later half, or, when one is left, a
/// sweep's later rows. False when nothing is left to drop.
fn shrink(inputs: &mut Vec<Input>) -> bool {
    if inputs.len() > 1 {
        inputs.truncate(inputs.len() / 2);
        return true;
    }
    match inputs.as_mut_slice() {
        [Input::Sweep { due }] if due.len() > 1 => {
            due.truncate(due.len() / 2);
            true
        }
        _ => false,
    }
}

/// A prepare's budget between its simulations: the usable gas, the floor,
/// the budget, the lowest budget the floor refused a larger batch, and
/// whether a lone input was tried again at the floor.
struct Fitting {
    usable: u64,
    floor: u64,
    budget: u64,
    refused: Option<u64>,
    retried: bool,
}

/// What a prepare does after a simulation.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    /// The package fits: take it.
    Take,
    /// Simulate again at the budget now set.
    Again,
    /// Leave the batch smaller and simulate again.
    Shrink,
    /// Even the batch at its smallest does not fit.
    Unfit,
}

impl Fitting {
    fn new(refine_gas: u64) -> Self {
        Self {
            usable: usable(refine_gas),
            floor: defaults::min_refine_gas(MAX_INPUTS),
            budget: budget(refine_gas),
            refused: None,
            retried: false,
        }
    }

    /// After a package whose segments and input `fits` and whose own work
    /// and start take `beyond` past its budget, of a batch that `shrinks`
    /// or not:
    /// - it fits within the usable gas: take it;
    /// - else the budget the estimate leaves, which a smaller batch's own
    ///   work leaves at least, below the floor only for a batch that cannot
    ///   shrink;
    /// - else a smaller batch;
    /// - and a lone input whose own work passes the usable gas once again
    ///   at the floor, or at the lowest budget the floor refused a larger
    ///   batch: a step capped there has fewer effects, and fails `Cap` as
    ///   lowering past the floor failed it before the batch shrank.
    fn next(&mut self, fits: bool, beyond: u64, shrinks: bool) -> Next {
        if fits && self.budget + beyond <= self.usable {
            return Next::Take;
        }
        if fits && beyond < self.usable {
            let lowered = self.usable - beyond;
            if lowered >= self.floor || !shrinks {
                self.budget = lowered;
                return Next::Again;
            }
            self.refused = Some(self.refused.map_or(lowered, |refused| refused.min(lowered)));
        }
        if shrinks {
            return Next::Shrink;
        }
        let retry = self
            .refused
            .map_or(self.floor, |refused| refused.min(self.floor));
        if fits && !self.retried && self.budget > retry {
            self.retried = true;
            self.budget = retry;
            return Next::Again;
        }
        Next::Unfit
    }
}

/// Whether [`shrink`] can leave `inputs` smaller.
fn shrinks(inputs: &[Input]) -> bool {
    inputs.len() > 1 || matches!(inputs, [Input::Sweep { due }] if due.len() > 1)
}

/// The pages a prepare reads from DA, each fetched once, whichever check or
/// simulation asks: from where the store says each was exported, a place
/// the store cannot read counting as a page DA lacks.
struct Fetched {
    view: View,
    segments: Arc<dyn Segments>,
    pages: Mutex<BTreeMap<(WorkflowId, u32), Fetch>>,
}

/// A page as DA gave it, `None` when it lacks it.
type Fetch = Option<Vec<u8>>;

impl Fetched {
    fn new(view: View, segments: Arc<dyn Segments>) -> Self {
        Self {
            view,
            segments,
            pages: Mutex::default(),
        }
    }

    /// Workflow `workflow`'s page `index`, `None` when DA lacks it.
    fn page(&self, workflow: WorkflowId, index: u32) -> Option<Vec<u8>> {
        let mut pages = self.pages.lock().expect("the fetched pages");
        pages
            .entry((workflow, index))
            .or_insert_with(|| {
                let (root, at) = self.view.page(workflow, index).ok()??;
                Some(self.segments.segment(&root, at)?.get(..PAGE)?.to_vec())
            })
            .clone()
    }
}

/// The workflows a batch at `time` of `inputs` would step from their
/// snapshots, by the rows its sweeps list, whose snapshots hold a page
/// `fetched` lacks. A sweep's step takes the rows a sweep's step does: at
/// most `defaults::SWEEP_LIMIT`, due by `time` and still in the due index,
/// the workflow's record due there and not ended. A row whose record does
/// not read is passed over, for the simulation to find.
fn lacking(view: &View, fetched: &Fetched, inputs: &[Input], time: u64) -> Vec<WorkflowId> {
    let mut lacking = Vec::new();
    let sweeps = inputs.iter().filter_map(|input| match input {
        Input::Sweep { due } => Some(due),
        _ => None,
    });
    for due in sweeps {
        for &(at, entry) in due.iter().take(defaults::SWEEP_LIMIT) {
            let Due::Workflow(id) = entry else {
                continue;
            };
            if at > time || lacking.contains(&id) {
                continue;
            }
            if !matches!(view.get(&keys::due(at, entry)), Ok(Some(_))) {
                continue;
            }
            let Ok(Some(workflow)) = record::<Workflow>(view, &keys::workflow(id)) else {
                continue;
            };
            let resumes = workflow.due == at && !matches!(workflow.state, WorkflowState::Ended(_));
            let Some(snapshot) = workflow.snapshot.filter(|_| resumes) else {
                continue;
            };
            let held = |&(index, hash): &(u32, [u8; 32])| {
                fetched
                    .page(id, index)
                    .is_some_and(|page| digest(&page) == hash)
            };
            if !snapshot.pages.iter().all(held) {
                lacking.push(id);
            }
        }
    }
    lacking
}

/// Leave `workflow`'s rows out of the sweeps among `inputs`, a sweep left
/// with none dropped: whether any was.
fn skip(inputs: &mut Vec<Input>, workflow: WorkflowId) -> bool {
    let mut skipped = false;
    inputs.retain_mut(|input| match input {
        Input::Sweep { due } => {
            let before = due.len();
            due.retain(|(_, entry)| *entry != Due::Workflow(workflow));
            skipped |= due.len() < before;
            !due.is_empty()
        }
        _ => true,
    });
    skipped
}

/// Record where `result`'s stored pages lie among `exports`, in the order
/// its runs list them, and forget those it dropped.
fn record_pages(
    pending: &mut Pending,
    result: &WorkResult,
    exports: &Exports,
) -> Result<(), Error> {
    let listed = result.steps.iter().flat_map(|step| match step {
        Step::Ran(run) => run.pages.as_slice(),
        _ => &[],
    });
    let mut at = 0;
    for Page {
        workflow,
        index,
        hash,
    } in listed
    {
        match hash {
            Some(_) => {
                pending.page(*workflow, *index, Some((exports.root, at)));
                at += 1;
            }
            None => pending.page(*workflow, *index, None),
        }
    }
    if at != exports.pages {
        return Err(Error::Exports);
    }
    Ok(())
}

/// An agent record of `view`.
fn record<T: Decode>(view: &View, key: &[u8]) -> Result<Option<T>, Error> {
    let Some(bytes) = view.get(key)? else {
        return Ok(None);
    };
    let value = unstored(&bytes).ok_or(Error::Corrupt("a record"))?;
    T::decode(value)
        .map(|(value, _)| Some(value))
        .map_err(|_| Error::Corrupt("a record"))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, SessionId};

    use super::*;

    fn sweep(workflows: &[u64]) -> Input {
        let due = workflows
            .iter()
            .map(|&id| (id, Due::Workflow(WorkflowId(id))))
            .collect();
        Input::Sweep { due }
    }

    /// A batch that does not fit loses its later inputs, then, a sweep
    /// left alone, its later rows; one row, or one other input, is as
    /// small as it gets.
    #[test]
    fn a_batch_shrinks_by_its_inputs_then_a_sweeps_rows() {
        let ack = Input::Ack {
            to: AgentId(1),
            sequence: 1,
        };
        let mut inputs = vec![sweep(&[1, 2, 3, 4]), ack.clone(), ack.clone()];
        assert!(shrink(&mut inputs));
        assert_eq!(inputs, [sweep(&[1, 2, 3, 4])]);
        assert!(shrink(&mut inputs));
        assert_eq!(inputs, [sweep(&[1, 2])]);
        assert!(shrink(&mut inputs));
        assert_eq!(inputs, [sweep(&[1])]);
        assert!(!shrink(&mut inputs));
        assert!(!shrink(&mut vec![ack]));
    }

    /// The budget: taken when the package fits; lowered to what the
    /// estimate leaves, but below the floor only for a batch that cannot
    /// shrink, which shrinks first; and a lone input past the usable gas
    /// tried once more at the lowest budget the floor refused, then unfit.
    #[test]
    fn a_budget_keeps_its_floor_while_the_batch_can_shrink() {
        let start = budget(POLKAJAM_REFINE_GAS);
        let usable = usable(POLKAJAM_REFINE_GAS);
        let floor = defaults::min_refine_gas(MAX_INPUTS);
        let mut fitting = Fitting::new(POLKAJAM_REFINE_GAS);
        assert_eq!(fitting.next(true, OWN_BOUND, true), Next::Take);
        assert_eq!(fitting.next(true, 100_000_000, true), Next::Again);
        assert_eq!(fitting.budget, usable - 100_000_000);
        // Past the floor: a batch that can shrink does, keeping the budget.
        let below = usable - floor + 1;
        assert_eq!(fitting.next(true, below, true), Next::Shrink);
        assert_eq!(fitting.budget, usable - 100_000_000);
        // Alone, it lowers past the floor.
        assert_eq!(fitting.next(true, below, false), Next::Again);
        assert_eq!(fitting.budget, floor - 1);
        assert_eq!(fitting.next(true, below, false), Next::Take);
        // A lone input past the usable gas: once more at the lowest budget
        // the floor refused, then unfit.
        let mut fitting = Fitting::new(POLKAJAM_REFINE_GAS);
        assert_eq!(fitting.next(true, usable - floor + 10, true), Next::Shrink);
        assert_eq!(fitting.next(true, usable, false), Next::Again);
        assert_eq!(fitting.budget, floor - 10);
        assert_eq!(fitting.next(true, usable, false), Next::Unfit);
        // With no budget refused, at the floor; a package past a work
        // package's segments is never tried again.
        let mut fitting = Fitting::new(POLKAJAM_REFINE_GAS);
        assert_eq!(fitting.next(true, usable + 1, false), Next::Again);
        assert_eq!(fitting.budget, floor);
        assert_eq!(fitting.next(true, usable + 1, false), Next::Unfit);
        let mut fitting = Fitting::new(POLKAJAM_REFINE_GAS);
        assert_eq!(fitting.budget, start);
        assert_eq!(fitting.next(false, OWN_BOUND, false), Next::Unfit);
    }

    /// A workflow whose pages are gone leaves the sweeps, which drop
    /// when emptied; the other inputs and rows stay.
    #[test]
    fn a_workflow_without_its_pages_leaves_the_sweep() {
        let session = (9, Due::Session(SessionId(9)));
        let mut inputs = vec![sweep(&[1, 2]), Input::Sweep { due: vec![session] }];
        assert!(skip(&mut inputs, WorkflowId(1)));
        assert_eq!(inputs[0], sweep(&[2]));
        assert!(skip(&mut inputs, WorkflowId(2)));
        assert_eq!(inputs, [Input::Sweep { due: vec![session] }]);
        assert!(!skip(&mut inputs, WorkflowId(3)));
    }

    /// A call signed by its session's key for the agent's service is a
    /// request of that key's; signed for another service, or by another
    /// key, it is refused.
    #[test]
    fn a_call_is_admitted_signed_by_its_sessions_key() {
        let key = SigningKey::from_bytes(&[3; 32]);
        let session = Session {
            key: key.verifying_key().to_bytes(),
            name: [4; 16],
            t0: 5,
        };
        let signed = |service: u64, key: &SigningKey| {
            let message = call_message(
                &vos_wire::package::identity(service),
                &session,
                6,
                InstanceId(7),
                MethodId(8),
                &[9],
            );
            Call {
                session,
                sequence: 6,
                instance: InstanceId(7),
                method: MethodId(8),
                arguments: vec![9],
                signature: key.sign(&message).to_bytes(),
            }
        };
        let Ok(Input::Request(request)) = admit(1, signed(1, &key)) else {
            panic!("admitted");
        };
        assert_eq!(request.caller, Principal::Client(session.key));
        assert_eq!((request.sequence, request.arguments), (6, vec![9]));
        assert_eq!(admit(2, signed(1, &key)), Err(Error::Signature));
        let other = SigningKey::from_bytes(&[4; 32]);
        assert_eq!(admit(1, signed(1, &other)), Err(Error::Signature));
    }
}
