//! An agent on JAM, from its builder's side.
//!
//! The builder holds the agent's whole keyspace under one tree ([`Store`]).
//! For each batch it simulates refine against the store, recording every
//! row it touches ([`simulate`]), builds the package's witness from them
//! ([`witness`]), and names, as imports, the pages the batch's workflows
//! restore, by where earlier packages exported them. Once the package is
//! accumulated, it applies the work result, which it reads back from the
//! package's exports, to its store, whose root must be the root after.
//!
//! [`Chain`] emulates the JAM node's side in process, DA included, so the
//! whole loop runs without one.

pub mod chain;
pub mod da;
pub mod simulate;
pub mod store;
pub mod witness;

use std::collections::BTreeMap;
use std::sync::Arc;

use vos_pvm::ExitReason;
use vos_pvm::refine::RefineError;
use vos_tree::Hash;
use vos_wire::Decode;
use vos_wire::batch::Batch;
use vos_wire::ids::WorkflowId;
use vos_wire::package::{MAX_SEGMENTS, Package, result_segments};
use vos_wire::result::{PAGE, Step, WorkResult, digest};

pub use chain::{Chain, Refined};
pub use da::{Da, segment_root};
pub use simulate::{Runner, Simulation, simulate};
pub use store::Store;
pub use witness::witness;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The program could not be loaded or run.
    Load(RefineError),
    /// Refine did not halt.
    Refine(ExitReason),
    /// Accumulate did not halt.
    Accumulate(ExitReason),
    /// Refine's output is not what it returns.
    Output,
    /// The work result does not apply to the store.
    Refused,
    /// The package was refined on another root, or its result does not
    /// lead to its root after.
    Root,
    /// The chain does not hold the package's root after: accumulate
    /// refused it.
    Unaccumulated,
    /// The package's exports are not its pages and its work result.
    Exports,
    /// The package would import or export more segments than one may.
    Segments,
    /// DA lacks a page a workflow of the batch holds.
    Page(WorkflowId, u32),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Load(error) => write!(f, "the agent's program: {error:?}"),
            Error::Refine(exit) => write!(f, "refine stopped: {exit:?}"),
            Error::Accumulate(exit) => write!(f, "accumulate stopped: {exit:?}"),
            Error::Output => f.write_str("refine's output is not a package's"),
            Error::Refused => f.write_str("the work result does not apply to the store"),
            Error::Root => f.write_str("the roots do not continue the store's"),
            Error::Unaccumulated => f.write_str("the chain does not hold the root after"),
            Error::Exports => f.write_str("the exports are not the result and its pages"),
            Error::Segments => f.write_str("more segments than a package imports or exports"),
            Error::Page(workflow, index) => {
                write!(f, "DA lacks workflow {}'s page {index}", workflow.0)
            }
        }
    }
}

impl std::error::Error for Error {}

/// Where a page was exported: its package's segment root, and its index
/// among the package's exports.
pub type Exported = (Hash, u32);

/// An agent's builder: its store, and where each page its workflows hold
/// was exported.
#[derive(Clone, Debug, Default)]
pub struct Builder {
    pub store: Store,
    pages: BTreeMap<(WorkflowId, u32), Exported>,
}

/// A batch made a package: its simulation, the package, and where each of
/// the package's imports was exported, in its order.
#[derive(Clone, Debug)]
pub struct Prepared {
    pub simulation: Simulation,
    pub package: Package,
    pub segments: Vec<Exported>,
}

/// Whether `simulation`'s package fits a package's segments: the pages
/// and the work result it exports, and the pages it imports.
fn fits(simulation: &Simulation) -> Result<(), Error> {
    let exports = simulation.pages + result_segments(simulation.encoded.len());
    if exports > MAX_SEGMENTS || simulation.imports.len() > MAX_SEGMENTS {
        return Err(Error::Segments);
    }
    Ok(())
}

impl Builder {
    /// Make `batch` a package on the store as it stands, its pages read
    /// from `da`; refused when it would import or export more segments
    /// than a package may.
    pub fn prepare(&self, runner: &Runner, da: &Da, batch: Batch) -> Result<Prepared, Error> {
        let (index, da) = (self.pages.clone(), da.clone());
        let pages = Arc::new(move |workflow, page| {
            let (root, at) = index.get(&(workflow, page))?;
            Some(da.segment(root, *at)?.get(..PAGE)?.to_vec())
        });
        let simulation = simulate(runner, &self.store, pages, &batch)?;
        fits(&simulation)?;
        let witness = witness(&self.store, &simulation);
        let segments = simulation
            .imports
            .iter()
            .map(|page| self.pages[page])
            .collect();
        let package = Package {
            batch,
            root: self.store.root(),
            witness,
            imports: simulation.imports.clone(),
        };
        Ok(Prepared {
            simulation,
            package,
            segments,
        })
    }

    /// The segments `prepared`'s package imports, from `da`.
    pub fn imports(&self, prepared: &Prepared, da: &Da) -> Result<Vec<Vec<u8>>, Error> {
        prepared
            .package
            .imports
            .iter()
            .zip(&prepared.segments)
            .map(|(&(workflow, index), (root, at))| {
                da.segment(root, *at)
                    .map(<[u8]>::to_vec)
                    .ok_or(Error::Page(workflow, index))
            })
            .collect()
    }

    /// Take a package refined and accumulated, the chain holding `stored`
    /// after: its work result, read back from its exports in `da` and
    /// checked against its hash, applied to the store, whose root must
    /// become the root after, which the chain must hold; and its pages,
    /// indexed where they were exported. Its work result. On any error the
    /// store is left as it was.
    pub fn accept(
        &mut self,
        refined: &Refined,
        stored: Option<Hash>,
        da: &Da,
    ) -> Result<WorkResult, Error> {
        let output = &refined.output;
        if output.root_before != self.store.root() {
            return Err(Error::Root);
        }
        if stored != Some(output.root_after) {
            return Err(Error::Unaccumulated);
        }
        let exports = da.exports(&refined.segment_root).ok_or(Error::Exports)?;
        let pages = output.pages as usize;
        let bytes: Vec<u8> = exports.get(pages..).ok_or(Error::Exports)?.concat();
        let (result, used) = WorkResult::decode(&bytes).map_err(|_| Error::Exports)?;
        if digest(&bytes[..used]) != output.work_result_hash {
            return Err(Error::Exports);
        }
        let listed = result.steps.iter().flat_map(|step| match step {
            Step::Ran(run) => run.pages.as_slice(),
            _ => &[],
        });
        let mut at = 0;
        let mut index = Vec::new();
        for page in listed {
            let place = (page.workflow, page.index);
            match page.hash {
                Some(hash) => {
                    let segment = exports.get(at).ok_or(Error::Exports)?;
                    if digest(&segment[..PAGE]) != hash {
                        return Err(Error::Exports);
                    }
                    index.push((place, Some((refined.segment_root, at as u32))));
                    at += 1;
                }
                None => index.push((place, None)),
            }
        }
        if at != pages {
            return Err(Error::Exports);
        }
        let mut store = self.store.clone();
        if store.apply(&result) != Some(output.root_after) {
            return Err(Error::Root);
        }
        self.store = store;
        for (place, exported) in index {
            match exported {
                Some(exported) => self.pages.insert(place, exported),
                None => self.pages.remove(&place),
            };
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A package fits as long as its exports and its imports each take at
    /// most a package's segments.
    #[test]
    fn a_package_past_its_segments_is_refused() {
        let result = WorkResult {
            version: 0,
            time: 0,
            seed: [0; 32],
            steps: Vec::new(),
        };
        let simulation = |pages: usize, imports: usize| Simulation {
            encoded: vos_wire::Encode::encode(&result),
            result: result.clone(),
            reads: Default::default(),
            ranges: Vec::new(),
            writes: Default::default(),
            imports: vec![(WorkflowId(0), 0); imports],
            pages,
            gas_used: 0,
        };
        assert_eq!(fits(&simulation(MAX_SEGMENTS - 1, MAX_SEGMENTS)), Ok(()));
        assert_eq!(fits(&simulation(MAX_SEGMENTS, 0)), Err(Error::Segments));
        assert_eq!(fits(&simulation(0, MAX_SEGMENTS + 1)), Err(Error::Segments));
    }
}
