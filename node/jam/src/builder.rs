//! The builder: an agent's batches made packages that fit a work package,
//! submitted, and taken into its store once the chain holds their roots.
//!
//! **Fitting a package:** the batch's budget is what the work package's
//! refine gas leaves past the package's own work ([`crate::gas`]), with a
//! margin; its exports and imports at most a package's segments, and its
//! payload at most a package's input. A batch that does not fit loses its
//! later inputs, and a sweep its later rows, which wait for the next. A
//! workflow whose pages DA no longer holds has its rows left out of the
//! sweep, so it stays due and the rest of the batch goes on: with no
//! re-export of its pages, it waits for good.
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

use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use vos_wire::batch::{Batch, Input, Request, Work};
use vos_wire::ids::{Principal, ProgramHash, WorkflowId};
use vos_wire::ingress::{Call, call_message};
use vos_wire::keys::Due;
use vos_wire::package::{Exports, MAX_SEGMENTS, Package, SEGMENT, result_segments};
use vos_wire::records::{Workflow, unstored};
use vos_wire::result::{PAGE, Page, Step, WorkResult};
use vos_wire::{Decode, Encode, defaults, keys};

use crate::chain::{Chain, Landed};
use crate::da::Segments;
use crate::simulate::{Runner, Simulation, simulate};
use crate::store::{Exported, Pending, Store, View};
use crate::witness::witness;
use crate::{Error, gas};

/// The largest work package input the builder makes: PolkaJam's
/// `max_input` (`W_B`) is 13,791,360 bytes, imports and all.
pub const MAX_INPUT: usize = 12 << 20;
/// What a package's refine keeps past its estimate, in parts of a
/// thousand of its gas.
const MARGIN: u64 = 50;
/// The times the builder makes a batch again before it stops.
const ATTEMPTS: usize = 4;

/// A batch made a package: its simulation, the package and its encoding,
/// where each of its imports was exported, in its order, the refine gas it
/// needs and the part of it the package's own work takes, the store once
/// it lands, and the workflows whose due steps it leaves out, their pages
/// gone from DA.
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
    pub refine_gas: u64,
}

impl Builder {
    pub fn new(store: Store, refine_gas: u64) -> Self {
        Self { store, refine_gas }
    }

    /// The agent's state version: the work results its store took.
    pub fn version(&self) -> Result<u64, Error> {
        record(&self.store.view(), &keys::version()).map(|version| version.unwrap_or(0))
    }

    /// `inputs` at `time` and `seed`, with `solicit`, made a package on the
    /// store as it stands, its pages read from `segments`. Later inputs,
    /// and a sweep's later rows, that do not fit are left out, as are the
    /// rows of workflows whose pages DA lacks.
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
        let usable = self.refine_gas - self.refine_gas / 1000 * MARGIN;
        let mut budget = usable / 5 * 4;
        let mut skipped = Vec::new();
        loop {
            let batch = Batch {
                version,
                time,
                seed,
                budget,
                inputs: inputs.clone(),
            };
            let segments = Arc::clone(&segments);
            let prepared = match self.package(runner, &view, segments, batch, solicit) {
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
            let needed = budget + start + own;
            if fits && needed <= usable {
                return Ok(Prepared {
                    gas: needed,
                    own,
                    skipped,
                    ..prepared
                });
            }
            if fits && own + start < usable && budget > usable - own - start {
                // The budget the estimate leaves, which a smaller batch's
                // own work leaves at least.
                budget = usable - own - start;
                continue;
            }
            if !shrink(&mut inputs) {
                return Err(Error::Unfit);
            }
        }
    }

    /// `batch` made a package on `view`.
    fn package(
        &self,
        runner: &Runner,
        view: &View,
        segments: Arc<dyn Segments>,
        batch: Batch,
        solicit: &[(ProgramHash, u32)],
    ) -> Result<Prepared, Error> {
        let places = view.clone();
        let pages = Arc::new(move |workflow, index| {
            let (root, at) = places.page(workflow, index).ok()??;
            Some(segments.segment(&root, at)?.get(..PAGE)?.to_vec())
        });
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
