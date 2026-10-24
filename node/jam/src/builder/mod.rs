//! The builder: an agent's batches made packages that fit a work package,
//! submitted, and taken into its store once the chain holds their roots.
//! How a batch is fitted, and left without the workflows whose pages DA
//! lacks, is the `fit` module's.
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

mod fit;

use std::sync::Arc;

use vos_wire::batch::Input;
use vos_wire::ids::{Principal, ProgramHash, WorkflowId};
use vos_wire::package::Exports;
use vos_wire::records::{Workflow, unstored};
use vos_wire::result::{Page, Step, WorkResult};
use vos_wire::{Decode, defaults, keys};

use crate::Error;
use crate::chain::{Chain, Landed};
use crate::da::Segments;
use crate::simulate::Runner;
use crate::store::{Pending, Store, View};

pub use fit::MAX_INPUT;
pub use fit::{
    MARGIN, MAX_INPUTS, MAX_PACKAGE, OWN_BOUND, PACKAGE_FRAMING, POLKAJAM_REFINE_GAS, Prepared,
    WORST_ENDING, WORST_JAM_STEP, budget,
};

/// The times the builder makes a batch again before it stops.
const ATTEMPTS: usize = 4;

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
    pub(crate) fn version(&self) -> Result<u64, Error> {
        record(&self.store.view(), &keys::version()).map(|version| version.unwrap_or(0))
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
                self.resync(segments.as_ref(), &landed)?;
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
    pub fn resync(
        &mut self,
        segments: &dyn Segments,
        landed: &Landed,
    ) -> Result<WorkResult, Error> {
        let exports = landed.exports.ok_or(Error::Diverged)?;
        let (result, _) = exported_result(segments, &exports).map_err(|_| Error::Diverged)?;
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
        let view = self.store.view();
        let rows = view
            .rows_from(&keys::due_prefix())
            .map(|row| row.map(|(key, _)| key));
        let due = keys::due_rows(rows, time, defaults::SWEEP_LIMIT)?;
        Ok((!due.is_empty()).then_some(Input::Sweep { due }))
    }

    /// Workflow `id`, read for `owner`: its record, `None` when there is no
    /// such workflow or it is another's, as a VOS node answers its owner.
    pub fn workflow(&self, owner: &Principal, id: WorkflowId) -> Result<Option<Workflow>, Error> {
        let record: Option<Workflow> = record(&self.store.view(), &keys::workflow(id))?;
        Ok(record.filter(|workflow| workflow.owner == *owner))
    }
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
