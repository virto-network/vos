//! Fitting a batch to a work package: its budget, its size, and the pages
//! its workflows hold.
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
//! - **[`WORST_JAM_STEP`] bounds a step** in a package of its own. A JAM
//!   service's agent takes installs for JAM alone (`prepare` refuses any
//!   other, `Error::Target`), so its instances run within [`cap::JAM`]'s
//!   limits: the worst step, at the largest limit, restores, stores and
//!   drops every page a workflow may hold, ends it, and makes its effects at
//!   their limits ([`gas::effects`]), about 839M of PolkaJam's 950M usable,
//!   asserted. So no step fails `Cap` on JAM alone, and no input leaves no
//!   package to make; a request's or a call's step below its keep is left
//!   undispatched, and waits.
//! - **At VOS's caps it would not hold.** [`WORST_ENDING`], the ending
//!   that restores and drops all of `cap::HELD_PAGES`, 576, is about 913M
//!   bar its effects ([`gas::ENDING`], [`gas::PAGE_READ`], about 123k a
//!   page, [`gas::PAGE_DROP`], about 115k); its effects at those caps take
//!   up to about 1.15e9 more (`cap::STEP_WRITES` of writes about 105M in
//!   rows of 64 KiB, up to about 450M as the 3,125 puts of a step's 200M,
//!   each of `cap::MESSAGES` messages about 26M, each of `cap::ATTESTS`
//!   attests about 28M, traded against each other by the step's gas).
//!   [`cap::JAM`]'s are about 35 times fewer.
//! - **Its exports and imports** are at most a package's segments, and its
//!   payload at most a package's input; the package itself, its payload and
//!   its imports' references with its framing, within JAM-NP's CE 133 bound
//!   on a work package a guarantor takes ([`MAX_PACKAGE`]), which a package
//!   past it fails at submission. A batch that does not fit loses its later
//!   inputs, and a sweep its later rows, which wait for the next; a batch
//!   holds at most [`MAX_INPUTS`].
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
//! lacks, for both. Nothing exports a workflow's pages again: a workflow
//! whose step comes past what JAM keeps of its pages
//! (`cap::Limits::pages_kept`, 27 days, a day within the imports DA's
//! retention) ends at that step, `Expired`, without them, so it is never
//! left out for good.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vos_wire::abi::cap::{self, Target};
use vos_wire::batch::{Admin, Batch, Input, Work};
use vos_wire::ids::{ProgramHash, WorkflowId};
use vos_wire::keys::Due;
use vos_wire::package::{MAX_SEGMENTS, Package, SEGMENT, result_segments};
use vos_wire::records::{Workflow, WorkflowState};
use vos_wire::result::{PAGE, digest};
use vos_wire::{defaults, keys};

use super::{Builder, record};
use crate::da::Segments;
use crate::simulate::{Pages, Runner, Simulation, simulate};
use crate::store::{Exported, Pending, View};
use crate::witness::witness;
use crate::{Error, gas};

/// The largest work package input the builder makes: PolkaJam's
/// `max_input` (`W_B`) is 13,791,360 bytes, imports and all.
pub const MAX_INPUT: usize = 12 << 20;
/// JAM-NP's CE 133 bound on a work package: its first message, the core's
/// index (2 bytes) and the package, at most 204,802 bytes, so a guarantor
/// downloads no huge package before it checks its authorization. PolkaJam
/// enforces it; extrinsics travel apart, under `W_B` alone.
pub const MAX_PACKAGE: usize = 204_800;
/// A package's bytes beyond its payload and its imports' references, at
/// most, as `jamt` encodes it (the dev tooling's
/// `vos_jam_dev::live::package::encode_package`, the same bytes): its
/// authorization by PolkaJam's bootstrap authorizer, its context and its
/// item's fixed fields, 262 bytes, with its payload's length (3 bytes to
/// 2 MiB), its imports' count (3 bytes to 2 MiB of them) and its
/// extrinsics' (1).
pub const PACKAGE_FRAMING: usize = 262 + 3 + 3 + 1;
/// An import's reference in a work item: a segment root and its index.
pub(crate) const IMPORT_REF: usize = 32 + 2;

/// What a package's refine keeps past its estimate, in parts of a
/// thousand of its gas.
pub const MARGIN: u64 = 50;
/// A bound on a package's own work beyond its batch's budget: its refine's
/// start ([`defaults::batch_start`]) and what the [`gas`] module
/// estimates. The builder's estimates, PolkaJam reporting no refine gas:
/// 3.3M to 13.5M in the testnet run's packages, and at most 4.9M for a
/// workflow's package resumed across packages in the JAM-only host's
/// comparison. So the bound holds the packages that neither witness
/// hundreds of rows nor write them, with room; one that does lowers its
/// budget by the excess.
pub const OWN_BOUND: u64 = 50_000_000;
/// The most inputs a batch the builder makes may hold: a VOS node's
/// default, by which its least budget is reckoned.
pub const MAX_INPUTS: usize = 256;
/// PolkaJam's refine gas for a work package, `G_R`.
pub const POLKAJAM_REFINE_GAS: u64 = 1_000_000_000;

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
/// page's. The step's own effects, and other inputs', are not in it: at
/// VOS's caps they would pass what is left, which [`WORST_JAM_STEP`] does
/// not at JAM's.
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

/// The refine gas of a package holding only the worst step of a JAM
/// service's agent, whose instances run within [`cap::JAM`]: at the largest
/// limit, restoring every
/// page its workflow may hold, storing or dropping each, ending it, and its
/// effects at their limits ([`gas::effects`]). Its batch keeps what a VOS
/// node refines with at the least, as [`WORST_ENDING`]'s does.
pub const WORST_JAM_STEP: u64 = defaults::min_refine_gas(MAX_INPUTS)
    + defaults::refine_start(
        MAX_INPUTS,
        gas::ENDING_PAYLOAD + cap::JAM.held_pages * gas::PAGE_PAYLOAD,
    )
    + gas::ENDING
    + cap::JAM.held_pages as u64 * (gas::PAGE_READ + gas::PAGE_DROP + gas::PAGE_STORE)
    + gas::effects(&cap::JAM);

// On PolkaJam it fits: a step of a JAM service's agent never fails `Cap` on
// JAM alone, nor leaves no package to make.
const _: () = assert!(WORST_JAM_STEP <= usable(POLKAJAM_REFINE_GAS));

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

    /// The package's bytes as CE 133 bounds them, at most: its payload, its
    /// imports' references and [`PACKAGE_FRAMING`].
    pub fn package_bytes(&self) -> usize {
        self.payload.len() + self.segments.len() * IMPORT_REF + PACKAGE_FRAMING
    }

    /// The segments the package imports, from `segments`.
    pub fn imports(&self, segments: &dyn Segments) -> Result<Vec<Vec<u8>>, Error> {
        self.package
            .imports
            .iter()
            .zip(&self.segments)
            .map(|(&(workflow, index), (root, at))| {
                segments
                    .segment(root, *at)
                    .ok_or(Error::Page(workflow, index))
            })
            .collect()
    }
}

impl Builder {
    /// `inputs` at `time` and `seed`, with `solicit`, made a package on the
    /// store as it stands, its pages read from `segments`. Inputs past
    /// [`MAX_INPUTS`], and later inputs and a sweep's later rows that do not
    /// fit, are left out to wait for a later package, as are the rows of
    /// workflows whose pages DA lacks. An install for another target than
    /// JAM is refused, `Error::Target`.
    pub fn prepare(
        &self,
        runner: &Runner,
        segments: Arc<dyn Segments>,
        mut inputs: Vec<Input>,
        time: u64,
        seed: [u8; 32],
        solicit: &[(ProgramHash, u32)],
    ) -> Result<Prepared, Error> {
        for input in &inputs {
            if let Input::Admin(Admin::Install { target, .. }) = input
                && *target != Target::Jam
            {
                return Err(Error::Target(*target));
            }
        }
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
            let fits = prepared.exports() as usize <= MAX_SEGMENTS
                && prepared.segments.len() <= MAX_SEGMENTS
                && prepared.payload.len() + prepared.segments.len() * SEGMENT <= MAX_INPUT
                && prepared.package_bytes() <= MAX_PACKAGE;
            let beyond = prepared.gas - fitting.budget;
            match fitting.next(fits, beyond, shrinks(&inputs)) {
                Next::Take => {
                    return Ok(Prepared {
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
        let payload = Work::encode_package(&package);
        let start = defaults::batch_start(&package.batch, payload.len() + 64);
        let own = gas::own(&package, &simulation);
        Ok(Prepared {
            gas: package.batch.budget + start + own,
            own,
            payload,
            simulation,
            package,
            segments,
            pending,
            skipped: Vec::new(),
            simulations: 0,
        })
    }
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
            // Past what its target keeps of its pages, its step ends it
            // without them.
            let resumes = workflow.due == at
                && !matches!(workflow.state, WorkflowState::Ended(_))
                && workflow.pages_expire().is_none_or(|expire| time < expire);
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

#[cfg(test)]
mod tests {
    use vos_wire::ids::{AgentId, SessionId};

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

    /// A step's effects at JAM's limits take about a twenty-fourth of
    /// their own work at VOS's, and its worst step fits a package where
    /// VOS's, at its caps, would not.
    #[test]
    fn the_jam_limits_fit_a_package() {
        let (vos, jam) = (gas::effects(&cap::VOS), gas::effects(&cap::JAM));
        let usable = usable(POLKAJAM_REFINE_GAS);
        println!(
            "effects at most: VOS {vos}, JAM {jam}, {:.1} times fewer; the worst JAM step \
             {WORST_JAM_STEP} of {usable} usable; the worst VOS ending with its effects {}",
            vos as f64 / jam as f64,
            WORST_ENDING + vos,
        );
        assert!(vos / jam >= 24, "{vos} against {jam}");
        assert!(WORST_ENDING + vos > usable);
        assert!(WORST_JAM_STEP <= usable);
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
}
