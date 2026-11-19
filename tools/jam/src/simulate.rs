//! The recording simulation: a batch refined as a VOS node refines it, on
//! the JAM-only host's state stand-in, with its state served from the
//! builder's store and every row it reads and every range it scans
//! recorded; then its work result applied to the store's rows, recording
//! what that reads and writes. A JAM refine of the same batch touches
//! exactly these rows, or traps, so a package whose witness covers them
//! refines to the same work result.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use vos_abi::abi::cap;
use vos_abi::ids::WorkflowId;
use vos_abi::jam::RefineArgs;
use vos_abi::records::{stored, unstored};
use vos_abi::result::{PAGE, WorkResult, digest, split_output};
use vos_abi::{Encode, keys};
use vos_pvm::ExitReason;
use vos_pvm::refine::{MemoryModel, PreparedProgram};
use vos_pvm::refine_host::{
    JamItem, JamRefine, Preimages, RefineContext, StateReader, value_window,
};
use vos_tree::keys::{after, prefix_end};
use vos_wire::batch::{Batch, Work};
use vos_wire::defaults;

use crate::Error;
use crate::store::{RowsFrom, View, Writes};

/// What refines an agent's work: its program, its service and its
/// preimages.
#[derive(Clone)]
pub struct Runner {
    pub program: Arc<PreparedProgram>,
    pub service: u64,
    pub preimages: Arc<dyn Preimages>,
    /// Whether the service's code, the blob JAM looks up, is within `W_C`
    /// (`vos_pvm::spi::service_fits`): refine and accumulate of one past
    /// it answer [`Error::Big`].
    pub fits: bool,
}

/// A service's own preimages, by their hashes: a lookup naming another
/// service finds none.
struct Own {
    service: u64,
    programs: BTreeMap<[u8; 32], Vec<u8>>,
}

impl Preimages for Own {
    fn preimage(&self, service: u64, hash: &[u8; 32]) -> Option<Vec<u8>> {
        (service == self.service)
            .then(|| self.programs.get(hash).cloned())
            .flatten()
    }
}

impl Runner {
    /// `program` as service `service`'s, whose code JAM looks up is
    /// `code`, its preimages `programs`.
    pub fn new(
        program: Arc<PreparedProgram>,
        code: &[u8],
        service: u64,
        programs: impl IntoIterator<Item = Vec<u8>>,
    ) -> Self {
        let programs = programs
            .into_iter()
            .map(|program| (digest(&program), program))
            .collect();
        Self {
            program,
            service,
            preimages: Arc::new(Own { service, programs }),
            fits: vos_pvm::spi::service_fits(code),
        }
    }

    /// [`Error::Big`] for a service past `W_C`, before any run.
    pub fn admitted(&self) -> Result<(), Error> {
        if self.fits { Ok(()) } else { Err(Error::Big) }
    }

    /// What a JAM node gives a refine of `payload`, which imports
    /// `imports`.
    pub(crate) fn jam(&self, payload: Vec<u8>, imports: Vec<Vec<u8>>) -> JamRefine {
        JamRefine {
            service: self.service,
            items: vec![JamItem {
                payload,
                imports,
                service: u32::try_from(self.service).expect("a JAM service id is 32 bits"),
                ..JamItem::default()
            }],
            preimages: Some(Arc::clone(&self.preimages)),
            ..JamRefine::default()
        }
    }

    /// Refine arguments for `payload`, as a JAM node passes them.
    pub fn arguments(&self, payload: &[u8], package_hash: [u8; 32]) -> Vec<u8> {
        RefineArgs::new(self.service, payload.to_vec(), package_hash).encode()
    }
}

/// Where a workflow's page is, by its workflow and index: its bytes.
pub(crate) type Pages = Arc<dyn Fn(WorkflowId, u32) -> Option<Vec<u8>> + Send + Sync>;

/// A batch as the simulation found it.
#[derive(Clone, Debug)]
pub struct Simulation {
    /// The work result's encoding, and the result.
    pub encoded: Vec<u8>,
    pub result: WorkResult,
    /// Every row refine or the apply reads, outside what refine scans.
    pub reads: BTreeSet<Vec<u8>>,
    /// Every range refine scans, `[from, to)`, `to` `None` for the
    /// keyspace's end, as it scanned them.
    pub ranges: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    /// The rows the apply writes.
    pub writes: Writes,
    /// The pages refine restores from their rows, which a package imports.
    pub imports: Vec<(WorkflowId, u32)>,
    /// The pages its steps store, which a package exports.
    pub pages: usize,
    /// The refine's gas.
    pub gas_used: u64,
}

/// Simulate `batch` on `view`, the pages its workflows hold from `pages`.
pub(crate) fn simulate(
    runner: &Runner,
    view: &View,
    pages: Pages,
    batch: &Batch,
) -> Result<Simulation, Error> {
    runner.admitted()?;
    let payload = Work::encode_batch(batch);
    let arguments = runner.arguments(&payload, [0; 32]);
    let gas = batch.budget + defaults::batch_start(batch, arguments.len());
    let recorder = Arc::new(Recorder {
        view: view.clone(),
        pages,
        log: Mutex::default(),
    });
    let reader: Arc<dyn StateReader> = recorder.clone();
    let run = RefineContext::load_prepared(&runner.program, &arguments, gas, MemoryModel::Auto)
        .map_err(Error::Load)?
        .with_state(reader)
        .try_run_jam_with_state_stand_in(runner.jam(payload, Vec::new()))
        .map_err(Error::Load)?;
    let invocation = run.invocation;
    let log = std::mem::take(&mut *recorder.log.lock().expect("the log"));
    if let Some(error) = log.error {
        return Err(error);
    }
    if let Some(&(workflow, index)) = log.missing.first() {
        return Err(Error::Page(workflow, index));
    }
    if invocation.exit != ExitReason::Halt {
        return Err(Error::Refine(invocation.exit));
    }
    let output = invocation
        .output_bounded(cap::OUTPUT)
        .ok_or(Error::Output)?;
    let (result, section) = split_output(&output).ok_or(Error::Output)?;
    let mut reads = log.reads;
    let writes = view.writes(&result, &mut reads)?.ok_or(Error::Refused)?;
    Ok(Simulation {
        encoded: result.encode(),
        result,
        reads,
        ranges: log.ranges,
        writes,
        imports: log.imports.into_iter().collect(),
        pages: section.len(),
        gas_used: invocation.gas_used,
    })
}

/// The store as a refine reads it, recording what it reads.
struct Recorder {
    view: View,
    pages: Pages,
    log: Mutex<Log>,
}

#[derive(Default)]
struct Log {
    reads: BTreeSet<Vec<u8>>,
    ranges: Vec<(Vec<u8>, Option<Vec<u8>>)>,
    imports: BTreeSet<(WorkflowId, u32)>,
    /// Pages whose rows refine read that the source lacks.
    missing: Vec<(WorkflowId, u32)>,
    /// A read the store failed, which spoils the simulation.
    error: Option<Error>,
    /// The row a scan pulled last, whose value the scan's read takes as
    /// stored and unrecorded, as the scanned range covers it.
    scanned: Option<(Vec<u8>, Vec<u8>)>,
}

impl Log {
    fn ok<T>(&mut self, result: Result<T, Error>) -> Option<T> {
        result
            .map_err(|error| {
                self.error.get_or_insert(error);
            })
            .ok()
    }
}

impl StateReader for Recorder {
    /// A row as stored. A page row holds the page's hash on JAM, where the
    /// page is imported; the VOS refine simulated reads the page itself,
    /// LZ4-compressed. A page the source lacks is recorded missing. A
    /// scan's read of the row it pulled gives the row as stored.
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
        let mut log = self.log.lock().expect("the log");
        if let Some((_, value)) = log
            .scanned
            .take_if(|(scanned, _)| scanned.as_slice() == key)
        {
            return Some(value_window(&value, offset, max));
        }
        log.reads.insert(key.to_vec());
        let value = log.ok(self.view.get(key))??;
        let Some(place) = keys::page_entry(key) else {
            return Some(value_window(&value, offset, max));
        };
        let page = (self.pages)(place.0, place.1)
            .filter(|page| page.len() == PAGE && unstored(&value) == Some(&digest(page)[..]));
        let value = match page {
            Some(page) => {
                log.imports.insert(place);
                stored(&lz4_flex::block::compress(&page))
            }
            None => {
                log.missing.push(place);
                value
            }
        };
        Some(value_window(&value, offset, max))
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, usize)> + 'a> {
        let mut from = prefix.to_vec();
        if let Some(cursor) = after {
            from = from.max(self::after(cursor));
        }
        Box::new(Scan {
            log: &self.log,
            rows: self.view.rows_from(&from),
            prefix,
            from,
            last: None,
            exhausted: false,
        })
    }
}

/// A scan as refine pulls its rows: on its end, the range it read is
/// recorded, from its start to past the last row pulled, or to the
/// prefix's end once the rows under it ran out.
struct Scan<'a> {
    log: &'a Mutex<Log>,
    rows: RowsFrom,
    prefix: &'a [u8],
    from: Vec<u8>,
    last: Option<Vec<u8>>,
    exhausted: bool,
}

impl Iterator for Scan<'_> {
    type Item = (Vec<u8>, usize);

    fn next(&mut self) -> Option<Self::Item> {
        let mut log = self.log.lock().expect("the log");
        log.scanned = None;
        match self.rows.next() {
            Some(Ok((key, value))) if key.starts_with(self.prefix) => {
                self.last = Some(key.clone());
                let len = value.len();
                log.scanned = Some((key.clone(), value));
                Some((key, len))
            }
            Some(Err(error)) => {
                log.ok::<()>(Err(error));
                None
            }
            _ => {
                self.exhausted = true;
                None
            }
        }
    }
}

impl Drop for Scan<'_> {
    fn drop(&mut self) {
        self.log.lock().expect("the log").scanned = None;
        let to = match (&self.last, self.exhausted) {
            (_, true) => prefix_end(self.prefix),
            (Some(last), false) => Some(after(last)),
            (None, false) => return,
        };
        if to.as_ref().is_some_and(|to| *to <= self.from) {
            return;
        }
        let from = std::mem::take(&mut self.from);
        self.log.lock().expect("the log").ranges.push((from, to));
    }
}
