//! Inner machines: an actor's program or a kernel, from the node's pool
//! (`instantiate`) or built here from its blob (the loader), which a JAM
//! node's preimages supply.
//!
//! A machine can track the pages written in it ([`Machine::track`]): its
//! writable pages are armed read-only, a guest's first store to one exits
//! `Fault` at the page, and the agent marks the page written, sets it
//! read-write and resumes. Every write the agent makes into the machine goes
//! through [`Machine::write`], which marks and opens its pages first, since
//! `poke` into a read-only page fails. So the agent knows the pages a run
//! wrote with Gray Paper calls alone, the same on every host.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use vos_pvm_program::{
    HALT_ADDRESS, INPUT_SIZE, PAGE_SIZE, REGISTER_COUNT, Region, StandardHeader, ZONE_SIZE,
};
use vos_wire::abi::{Failure, code, precompile};

use crate::host::{
    EXPUNGE, INSTANTIATE, INVOKE, MACHINE, PAGES, PEEK, POKE, ecalli, historical_lookup,
    historical_lookup_from, lost, ptr, ptr_mut,
};

const ZONE: u64 = ZONE_SIZE as u64;
const PAGE: u64 = PAGE_SIZE as u64;
const INPUT: u64 = INPUT_SIZE as u64;
/// The top of the standard stack.
const STACK_TOP: u64 = (1 << 32) - 2 * ZONE - INPUT;
/// The standard argument window.
pub const ARGUMENTS: u64 = (1 << 32) - ZONE - INPUT;

const ALLOCATE_READ_WRITE: u64 = 2;
const SET_READ_ONLY: u64 = 3;
const SET_READ_WRITE: u64 = 4;

/// Why no machine could be had.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// Every inner machine is in use.
    Full,
    /// The preimages do not hold the program: on JAM, where `instantiate`
    /// is not served and the agent loads the program itself.
    Missing,
    /// The node, which serves `instantiate`, does not hold the program: on
    /// VOS, where every program the agent runs is pinned, data it lost.
    Unknown,
    /// The counter starts no instruction of the program.
    Counter,
}

impl From<Unavailable> for Failure {
    fn from(unavailable: Unavailable) -> Failure {
        match unavailable {
            Unavailable::Full => Failure::Depth,
            Unavailable::Missing | Unavailable::Unknown => Failure::Unloadable,
            Unavailable::Counter => Failure::Trapped,
        }
    }
}

/// A machine of a program the agent's state pins, an installed instance's
/// or a workflow's, at `counter`. A node that does not hold it lost it: the
/// refine stops ([`lost`]), rather than fail the step for the node's fault.
/// On JAM, a program the preimages lack fails the step, `Unloadable`.
pub fn pinned(program: &[u8; 32], counter: u32) -> Result<Machine, Unavailable> {
    match Machine::acquire_at(program, counter) {
        Err(Unavailable::Unknown) => lost("a pinned program"),
        acquired => acquired,
    }
}

/// The header of a program the agent's state pins, held lost, as
/// [`pinned`] holds it, on a node that lacks it.
pub fn pinned_header(program: &[u8; 32]) -> Option<StandardHeader> {
    header(program).or_else(|| {
        let _ = pinned(program, 0);
        None
    })
}

/// How an invocation stopped. A tracked machine's fault on a page it may
/// write never stops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Halt,
    Panic,
    /// At this address's page.
    Fault(u64),
    Host(u64),
    OutOfGas,
}

/// The header of `program`'s blob, which places its regions, read alone.
pub fn header(program: &[u8; 32]) -> Option<StandardHeader> {
    header_and_len(program).map(|(header, _)| header)
}

/// [`header`], and the blob's length.
pub fn header_and_len(program: &[u8; 32]) -> Option<(StandardHeader, usize)> {
    let mut header = [0u8; StandardHeader::LEN];
    let len = historical_lookup_from(program, 0, &mut header)?;
    (len >= StandardHeader::LEN)
        .then(|| StandardHeader::read(&header))
        .flatten()
        .map(|header| (header, len))
}

/// The pages a program may write: its read-write data and heap, and its
/// stack.
pub fn writable_pages(header: &StandardHeader) -> Option<u64> {
    let [_, rw, stack] = header.regions()?;
    Some((rw.size + stack.size) / PAGE)
}

/// A tracked machine's writable pages and those written since it was armed.
struct Tracking {
    runs: [(u64, u64); 2],
    written: BTreeSet<u64>,
}

impl Tracking {
    fn tracks(&self, page: u64) -> bool {
        self.runs
            .iter()
            .any(|&(first, count)| (first..first + count).contains(&page))
    }
}

/// An inner machine: gas and registers between invocations, as `invoke`
/// reads and writes them.
pub struct Machine {
    id: u64,
    frame: [u64; 14],
    /// Boxed: a step's nested machines sit on the agent's stack, a frame a
    /// level, sixty-three levels deep.
    tracking: Option<alloc::boxed::Box<Tracking>>,
}

impl Machine {
    /// A machine for `program`, laid out with no arguments, its registers
    /// ready for the halt and stack conventions.
    ///
    /// On JAM every acquisition runs the loader, at a cost that grows with
    /// the blob, which neither a step's reserve nor a nested call's price
    /// covers past a program of about 512 KiB: JAM mode prices it by the
    /// blob.
    pub fn acquire(program: &[u8; 32]) -> Result<Self, Unavailable> {
        Self::acquire_at(program, 0)
    }

    /// [`Machine::acquire`], its program counter at `counter`: a machine
    /// entered mid-block is charged the whole block, on every host.
    pub fn acquire_at(program: &[u8; 32], counter: u32) -> Result<Self, Unavailable> {
        let (id, _) = ecalli!(INSTANTIATE, [ptr(program), u64::from(counter), 0, 0, 0, 0]);
        let id = match id {
            code::FULL => return Err(Unavailable::Full),
            code::HUH => return Err(Unavailable::Counter),
            // The node looked in every program it holds.
            code::WHO => return Err(Unavailable::Unknown),
            code::WHAT => {
                let blob = historical_lookup(program).ok_or(Unavailable::Missing)?;
                load(&blob, counter)?
            }
            id => id,
        };
        let mut frame = [0u64; 14];
        frame[1] = HALT_ADDRESS;
        frame[2] = STACK_TOP;
        Ok(Self {
            id,
            frame,
            tracking: None,
        })
    }

    /// Track the pages written in the machine from here on: arm its
    /// writable pages, as `header` places them, read-only. False when
    /// `pages` refuses them. A workflow's step takes the arming and each
    /// page's repair from the batch's budget, by the pages
    /// (`defaults::ARM_PAGE`, `defaults::WRITTEN_PAGE`).
    pub fn track(&mut self, header: &StandardHeader) -> bool {
        let Some([_, rw, stack]) = header.regions() else {
            return false;
        };
        let runs = [rw, stack].map(|region| (region.base / PAGE, region.size / PAGE));
        for (first, count) in runs {
            if count > 0 && !self.pages(first, count, SET_READ_ONLY) {
                return false;
            }
        }
        self.tracking = Some(alloc::boxed::Box::new(Tracking {
            runs,
            written: BTreeSet::new(),
        }));
        true
    }

    /// The pages written since the machine was armed, in order; `None`
    /// when it is not tracked.
    pub fn written(&self) -> Option<&BTreeSet<u64>> {
        self.tracking.as_ref().map(|tracking| &tracking.written)
    }

    /// End the machine, as dropping it does: its program counter, where
    /// a host call's exit left it after the call.
    pub fn expunge(self) -> u64 {
        let machine = core::mem::ManuallyDrop::new(self);
        ecalli!(EXPUNGE, [machine.id, 0, 0, 0, 0, 0]).0
    }

    #[inline]
    pub fn gas(&self) -> u64 {
        self.frame[0]
    }

    #[inline]
    pub fn set_gas(&mut self, gas: u64) {
        self.frame[0] = gas;
    }

    /// Charge `gas`; false when the machine has less.
    #[inline]
    pub fn charge(&mut self, gas: u64) -> bool {
        match self.frame[0].checked_sub(gas) {
            Some(left) => {
                self.frame[0] = left;
                true
            }
            None => {
                self.frame[0] = 0;
                false
            }
        }
    }

    #[inline]
    pub fn register(&self, index: usize) -> u64 {
        self.frame[1 + index]
    }

    /// Its registers, φ0 to φ12.
    #[inline]
    pub fn registers(&self) -> [u64; REGISTER_COUNT] {
        core::array::from_fn(|index| self.register(index))
    }

    #[inline]
    pub fn set_register(&mut self, index: usize, value: u64) {
        self.frame[1 + index] = value;
    }

    /// Run an untracked machine until it stops: a tracked one runs with
    /// [`Machine::invoke_paying`].
    #[inline]
    pub fn invoke(&mut self) -> Exit {
        debug_assert!(self.tracking.is_none(), "a tracked machine pays its pages");
        self.invoke_once()
    }

    /// Run a tracked machine until it stops. Its first store to a page it
    /// may write asks `pay` first, then marks the page written, opens it and
    /// resumes; refused, the run stops at the fault with the page unopened,
    /// which [`Machine::unwritten`] tells from a trap.
    pub fn invoke_paying(&mut self, pay: &mut dyn FnMut() -> bool) -> Exit {
        match self.invoke_once() {
            Exit::Fault(address) if self.tracking.is_some() => self.resume(address, pay),
            exit => exit,
        }
    }

    #[inline]
    fn invoke_once(&mut self) -> Exit {
        let (status, detail) = ecalli!(
            INVOKE,
            [self.id, ptr_mut(as_bytes(&mut self.frame)), 0, 0, 0, 0]
        );
        match status {
            0 => Exit::Halt,
            1 => Exit::Panic,
            2 => Exit::Fault(detail),
            3 => Exit::Host(detail),
            4 => Exit::OutOfGas,
            _ => Exit::Panic,
        }
    }

    /// A tracked machine's run from a fault at `address`: while the fault
    /// is a first store to a page it may write, and `pay` pays it, open the
    /// page and resume.
    #[cold]
    #[inline(never)]
    fn resume(&mut self, mut address: u64, pay: &mut dyn FnMut() -> bool) -> Exit {
        loop {
            if !self.unwritten(address) || !pay() {
                return Exit::Fault(address);
            }
            let page = address / PAGE;
            self.open(page, page + 1);
            match self.invoke_once() {
                Exit::Fault(next) => address = next,
                exit => return exit,
            }
        }
    }

    /// Whether `address` lies in a page the tracked machine may write and
    /// has not written since it was armed: a fault there is a first store.
    pub fn unwritten(&self, address: u64) -> bool {
        self.unwritten_page(address / PAGE)
    }

    fn unwritten_page(&self, page: u64) -> bool {
        self.tracking
            .as_ref()
            .is_some_and(|tracking| tracking.tracks(page) && !tracking.written.contains(&page))
    }

    /// The pages of `len` bytes at `address` a write would mark written.
    pub fn unwritten_in(&self, address: u64, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        let end = address.saturating_add(len).div_ceil(PAGE);
        (address / PAGE..end)
            .filter(|&page| self.unwritten_page(page))
            .count() as u64
    }

    /// Mark the tracked pages from `first` to `end` that are not yet
    /// written, and set them read-write, a run at a time. True when it
    /// opened `first`.
    fn open(&mut self, first: u64, end: u64) -> bool {
        let Some(tracking) = &mut self.tracking else {
            return false;
        };
        let opens = |page: u64| tracking.tracks(page) && !tracking.written.contains(&page);
        let opened = opens(first);
        let mut runs: Vec<(u64, u64)> = Vec::new();
        for page in (first..end).filter(|&page| opens(page)) {
            match runs.last_mut() {
                Some((start, count)) if *start + *count == page => *count += 1,
                _ => runs.push((page, 1)),
            }
        }
        tracking
            .written
            .extend(runs.iter().flat_map(|&(start, count)| start..start + count));
        for (start, count) in runs {
            assert!(
                self.pages(start, count, SET_READ_WRITE),
                "a tracked page is mapped"
            );
        }
        opened
    }

    fn pages(&self, first: u64, count: u64, mode: u64) -> bool {
        ecalli!(PAGES, [self.id, first, count, mode, 0, 0]).0 == code::OK
    }

    /// Read the machine's bytes at `address` into `out`; false when
    /// unreadable.
    pub fn peek_into(&self, address: u64, out: &mut [u8]) -> bool {
        let (status, _) = ecalli!(
            PEEK,
            [self.id, ptr_mut(out), address, out.len() as u64, 0, 0]
        );
        status == code::OK
    }

    /// The machine's bytes at `address`, or `None` when unreadable.
    #[inline]
    pub fn peek(&self, address: u64, len: usize) -> Option<Vec<u8>> {
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        if len == 0 {
            return Some(bytes);
        }
        let (status, _) = ecalli!(
            PEEK,
            [
                self.id,
                bytes.as_mut_ptr() as u64,
                address,
                len as u64,
                0,
                0
            ]
        );
        if status != code::OK {
            return None;
        }
        // SAFETY: the host wrote all `len` bytes.
        unsafe { bytes.set_len(len) };
        Some(bytes)
    }

    /// Write `bytes` into the machine at `address`, as a guest's store
    /// would: a tracked machine's pages are marked and opened first.
    /// `Trapped` when unwritable.
    #[inline]
    pub fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), Failure> {
        if self.tracking.is_some() {
            self.open_written(address, bytes.len() as u64);
        }
        self.poke(address, bytes)
            .then_some(())
            .ok_or(Failure::Trapped)
    }

    /// Mark and open the tracked pages a write of `len` bytes at `address`
    /// reaches.
    #[cold]
    #[inline(never)]
    fn open_written(&mut self, address: u64, len: u64) {
        if len > 0 {
            let end = address.saturating_add(len);
            self.open(address / PAGE, end.div_ceil(PAGE));
        }
    }

    #[inline]
    fn poke(&self, address: u64, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return true;
        }
        let (status, _) = ecalli!(
            POKE,
            [self.id, ptr(bytes), address, bytes.len() as u64, 0, 0]
        );
        status == code::OK
    }

    /// Map `len` bytes at `address` read-write, and write `bytes` there:
    /// for laying a machine out, before [`Machine::track`], whose pages it
    /// would neither mark nor arm again.
    pub fn map(&self, address: u64, len: u64, bytes: &[u8]) -> bool {
        debug_assert!(self.tracking.is_none(), "a tracked machine maps nothing");
        let pages = len.div_ceil(PAGE);
        if pages == 0 {
            return true;
        }
        self.pages(address / PAGE, pages, ALLOCATE_READ_WRITE) && self.poke(address, bytes)
    }

    /// Map `len` bytes at `address`, write `bytes` there and make them
    /// read-only, as [`Machine::map`] does, before any tracking.
    pub fn map_read_only(&self, address: u64, len: u64, bytes: &[u8]) -> bool {
        let pages = len.div_ceil(PAGE);
        if pages == 0 {
            return true;
        }
        self.map(address, len, bytes) && self.pages(address / PAGE, pages, SET_READ_ONLY)
    }

    /// Serve the machine's call of precompile `id`, one
    /// [`precompile::price`] names, as a node serves its own machine's, at
    /// the same price: charged first, then computed through this program's
    /// own call, natively on a VOS node and in software on JAM, its output
    /// written through [`Machine::write`], and every register left as it
    /// was.
    pub fn precompile(&mut self, id: u64) -> Result<(), Failure> {
        let price = precompile::price(id).ok_or(Failure::Trapped)?;
        if !self.charge(price) {
            return Err(Failure::OutOfGas);
        }
        self.blake2b_compress()
    }

    fn blake2b_compress(&mut self) -> Result<(), Failure> {
        let (address, block) = (self.register(7), self.register(8));
        let mut h = [0u8; 64];
        let mut m = [0u8; 128];
        if !self.peek_into(address, &mut h) || !self.peek_into(block, &mut m) {
            return Err(Failure::Trapped);
        }
        let last = self.register(10) != 0;
        vos_pvm_precompiles::blake2b_compress(&mut h, &m, u128::from(self.register(9)), last);
        self.write(address, &h)
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        ecalli!(EXPUNGE, [self.id, 0, 0, 0, 0, 0]);
    }
}

fn as_bytes(frame: &mut [u64; 14]) -> &mut [u8] {
    // SAFETY: fourteen little-endian words, the layout `invoke` reads.
    unsafe { core::slice::from_raw_parts_mut(frame.as_mut_ptr().cast::<u8>(), 14 * 8) }
}

/// Build a machine from a standard program: its code through `machine` at
/// `counter`, then each region through `pages` and `poke`, at the Gray
/// Paper's standard layout with no arguments.
fn load(blob: &[u8], counter: u32) -> Result<u64, Unavailable> {
    let header = StandardHeader::read(blob).ok_or(Unavailable::Missing)?;
    let [ro, rw, stack] = header.regions().ok_or(Unavailable::Missing)?;
    let (ro_len, rw_len) = (header.ro_size as usize, header.rw_size as usize);
    let at = StandardHeader::LEN;
    let ro_data = blob.get(at..at + ro_len).ok_or(Unavailable::Missing)?;
    let rw_data = blob
        .get(at + ro_len..at + ro_len + rw_len)
        .ok_or(Unavailable::Missing)?;
    let at = at + ro_len + rw_len;
    let code_len = blob
        .get(at..at + 4)
        .and_then(|len| len.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(Unavailable::Missing)? as usize;
    let code = blob
        .get(at + 4..at + 4 + code_len)
        .ok_or(Unavailable::Missing)?;

    let (id, _) = ecalli!(
        MACHINE,
        [ptr(code), code.len() as u64, u64::from(counter), 0, 0, 0]
    );
    match id {
        code::FULL => return Err(Unavailable::Full),
        code::HUH if counter != 0 => return Err(Unavailable::Counter),
        code::HUH | code::WHAT => return Err(Unavailable::Missing),
        _ => {}
    }
    let machine = Machine {
        id,
        frame: [0; 14],
        tracking: None,
    };
    let laid_out = |region: Region, bytes: &[u8]| {
        if region.writable {
            machine.map(region.base, region.size, bytes)
        } else {
            machine.map_read_only(region.base, region.size, bytes)
        }
    };
    if !laid_out(ro, ro_data) || !laid_out(rw, rw_data) || !laid_out(stack, &[]) {
        return Err(Unavailable::Missing);
    }
    let machine = core::mem::ManuallyDrop::new(machine);
    Ok(machine.id)
}
