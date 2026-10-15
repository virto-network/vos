//! What a refine reads and keeps: its meter, applied state through the
//! node or a package's witness, and what its earlier steps committed.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ops::Range;

use vos_wire::abi::{Failure, cap};
use vos_wire::batch::Batch;
use vos_wire::ids::{AgentId, InstanceId, Principal, WorkflowId};
use vos_wire::records::{Installed, unstored, unversioned};
use vos_wire::result::{PAGE, PageSection};
use vos_wire::{Decode, defaults, keys};

use super::Overlay;
use super::jam::Witnessed;
use super::snapshots::Format;
use crate::host::{SCAN_PAGE, StateRows, scan_page, state_read, state_read_into};

/// The refine's gas as the agent accounts for it, from the batch and state
/// alone, never from `gas`, whose readings differ between hosts: what the
/// batch's budget leaves once the dispatched steps are taken. So every host
/// dispatches the same steps.
pub(crate) struct Meter {
    pub(crate) left: Cell<u64>,
    /// What the running step keeps of `left`: its reserve, its handler's
    /// limit and the finish. The installed records it reads first and its
    /// served precompiles take from above it.
    pub(crate) kept: Cell<u64>,
    /// A charge found nothing above `kept`.
    pub(crate) overrun: Cell<bool>,
}

impl Meter {
    pub(crate) fn new(left: u64) -> Self {
        Self {
            left: Cell::new(left),
            kept: Cell::new(0),
            overrun: Cell::new(false),
        }
    }

    /// Take `gas` before the agent spends it; false, the step overrun, when
    /// what lies above what the step keeps cannot pay it.
    pub(crate) fn take(&self, gas: u64) -> bool {
        match self.left.get().checked_sub(gas) {
            Some(left) if left >= self.kept.get() => {
                self.left.set(left);
                true
            }
            _ => {
                self.overrun.set(true);
                false
            }
        }
    }
}

/// A stored value without its format byte, or an agent record that does
/// not decode: state the agent did not write. It fails the step that reads
/// it, so one bad row cannot stop the agent.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Corrupt;

impl From<Corrupt> for Failure {
    fn from(_: Corrupt) -> Failure {
        Failure::Trapped
    }
}

/// The value stored under `key`: without its format byte, and, in a
/// committed map's value row, without the version that wrote it.
fn stored_value<'a>(key: &[u8], bytes: &'a [u8]) -> Result<&'a [u8], Corrupt> {
    let value = unstored(bytes).ok_or(Corrupt)?;
    if keys::is_committed(key) {
        unversioned(value).map(|(_, value)| value).ok_or(Corrupt)
    } else {
        Ok(value)
    }
}

/// Where a refine reads applied state.
pub(crate) enum Source {
    /// The node, through `state_read` and `state_scan`.
    Node,
    /// A JAM package's witness, verified against its root.
    Witness(Witnessed),
}

/// What one refine has committed so far, above applied state.
pub(crate) struct Base {
    pub(crate) agent: AgentId,
    pub(crate) source: Source,
    pub(crate) time: u64,
    pub(crate) seed: [u8; 32],
    /// The batch's whole budget, which the meter takes from.
    pub(crate) budget: u64,
    pub(crate) meter: Meter,
    /// Writes of the steps already committed in this refine, in order.
    pub(crate) earlier: Overlay,
    /// Installed records read in this refine. Only admin steps change
    /// them, and they clear it.
    pub(crate) installed: RefCell<BTreeMap<InstanceId, Option<Rc<Installed>>>>,
    /// The output's page section, and where in it lies each page the
    /// steps taken stored, or that they dropped: a later step of the
    /// workflow restores from there.
    pub(crate) section: RefCell<PageSection>,
    pub(crate) pages: BTreeMap<(WorkflowId, u32), Option<Range<usize>>>,
}

impl Base {
    pub(crate) fn new(agent: AgentId, batch: &Batch, source: Source) -> Self {
        Self {
            agent,
            source,
            time: batch.time,
            seed: batch.seed,
            budget: batch.budget,
            meter: Meter::new(batch.budget),
            earlier: BTreeMap::new(),
            installed: RefCell::new(BTreeMap::new()),
            section: RefCell::new(PageSection::new()),
            pages: BTreeMap::new(),
        }
    }

    /// How this refine's page section, and the node's page rows, hold a
    /// page: whole on JAM, which exports them as they are.
    pub(crate) fn format(&self) -> Format {
        match self.source {
            Source::Node => Format::Compressed,
            Source::Witness(_) => Format::Whole,
        }
    }

    /// A row of applied state as stored, by agent-relative key; `None`
    /// when absent.
    fn stored(&self, key: &[u8]) -> Option<Vec<u8>> {
        match &self.source {
            Source::Node => state_read(key),
            Source::Witness(witnessed) => witnessed.read(key).map(<[u8]>::to_vec),
        }
    }

    /// The length of a row of applied state as stored, without reading it.
    pub(crate) fn stored_len(&self, key: &[u8]) -> Option<usize> {
        match &self.source {
            Source::Node => state_read_into(key, &mut []),
            Source::Witness(witnessed) => witnessed.read(key).map(<[u8]>::len),
        }
    }

    /// A value of applied state, by agent-relative key.
    fn applied(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        self.stored(key)
            .map(|bytes| stored_value(key, &bytes).map(<[u8]>::to_vec))
            .transpose()
    }

    /// An agent record of applied state. A small one, as marks and ids
    /// are, is read and decoded on the stack.
    pub(crate) fn record<T: Decode>(&self, key: &[u8]) -> Result<Option<T>, Corrupt> {
        let decode = |bytes: &[u8]| {
            let value = unstored(bytes).ok_or(Corrupt)?;
            T::decode(value)
                .map(|(value, _)| Some(value))
                .map_err(|_| Corrupt)
        };
        if let Source::Witness(witnessed) = &self.source {
            return witnessed.read(key).map_or(Ok(None), decode);
        }
        // Every record refine reads fits, the stored byte included (a
        // session mark takes 17 bytes); a larger one is read again whole.
        let mut small = [0u8; 32];
        match state_read_into(key, &mut small) {
            None => Ok(None),
            Some(len) if len <= small.len() => decode(&small[..len]),
            Some(_) => state_read(key).map_or(Ok(None), |bytes| decode(&bytes)),
        }
    }

    /// Applied rows under `prefix` after `after`, a page at a time.
    pub(crate) fn applied_rows(&self, prefix: &[u8], after: &[u8]) -> Result<StateRows, Corrupt> {
        self.scan_page(prefix, after)
            .into_iter()
            .map(|(key, value)| {
                let value = stored_value(&key, &value)?.to_vec();
                Ok((key, value))
            })
            .collect()
    }

    /// A page of rows under `prefix` after `after`, their values as
    /// stored: at most [`SCAN_PAGE`] bytes of them, or room for the first
    /// alone.
    fn scan_page(&self, prefix: &[u8], after: &[u8]) -> StateRows {
        if let Source::Witness(witnessed) = &self.source {
            return witnessed
                .scan(prefix, after, SCAN_PAGE)
                .or_else(|| witnessed.scan(prefix, after, cap::STORED_ROW))
                .expect("a stored row past its cap");
        }
        scan_page(prefix, after)
    }

    /// A value through this refine's earlier steps and applied state.
    pub(crate) fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Corrupt> {
        match self.earlier.get(key) {
            Some(value) => Ok(value.clone()),
            None => self.applied(key),
        }
    }

    /// An instance's installed record. Read the first time in a refine, it
    /// is paid first, by its length ([`defaults::RECORD_BYTE`]): out of gas
    /// when the meter cannot pay it.
    pub(crate) fn installed(&self, instance: InstanceId) -> Result<Option<Rc<Installed>>, Failure> {
        if let Some(cached) = self.installed.borrow().get(&instance) {
            return Ok(cached.clone());
        }
        let key = keys::installed(instance);
        let len = match self.earlier.get(&key) {
            Some(value) => value.as_ref().map_or(0, Vec::len),
            None => self.stored_len(&key).unwrap_or(0),
        };
        if !self.meter.take(defaults::RECORD_BYTE * len as u64) {
            return Err(Failure::OutOfGas);
        }
        let installed = match self.read(&key)? {
            Some(bytes) => Some(Rc::new(Installed::decode(&bytes).map_err(|_| Corrupt)?.0)),
            None => None,
        };
        self.installed
            .borrow_mut()
            .insert(instance, installed.clone());
        Ok(installed)
    }

    /// Workflow `id`'s page `index`, whose snapshot names it by `hash`,
    /// read into `page`: from the section when a step of this refine
    /// stored it, else from its row, which on JAM holds the page's hash,
    /// `hash` itself, and the package an import of the page. False when a
    /// step dropped it, no row holds it, or what holds it is not a page.
    pub(crate) fn page(
        &self,
        id: WorkflowId,
        index: u32,
        hash: &[u8; 32],
        page: &mut [u8; PAGE],
    ) -> Result<bool, Corrupt> {
        let format = self.format();
        match self.pages.get(&(id, index)) {
            Some(Some(range)) => Ok(format.unpack(self.section.borrow().page(range.clone()), page)),
            Some(None) => Ok(false),
            None => Ok(
                match (self.applied(&keys::page(id, index))?, &self.source) {
                    (None, _) => false,
                    (Some(row), Source::Node) => format.unpack(&row, page),
                    (Some(row), Source::Witness(witnessed)) => {
                        row == hash && witnessed.import(id, index, page)
                    }
                },
            ),
        }
    }

    /// Whether a row is there, through this refine's earlier steps,
    /// whatever its value.
    pub(crate) fn holds(&self, key: &[u8]) -> bool {
        match self.earlier.get(key) {
            Some(value) => value.is_some(),
            None => self.stored_len(key).is_some(),
        }
    }

    /// A principal's role byte, through this refine's earlier steps.
    pub(crate) fn role(&self, principal: &Principal) -> Result<Option<u8>, Corrupt> {
        Ok(self
            .read(&keys::member(principal))?
            .and_then(|bytes| bytes.first().copied()))
    }
}
