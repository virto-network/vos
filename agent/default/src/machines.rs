//! Inner machines: an actor, attestable or workflow program, from the
//! node's pool (`instantiate`) or built here from its blob (the loader),
//! which a JAM node's preimages supply.
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

use vos_pvm_program::{Region, StandardHeader};
use vos_wire::abi::{Failure, code, precompile};

use crate::host::{
    EXPUNGE, INSTANTIATE, INVOKE, MACHINE, PAGES, PEEK, POKE, ecalli, historical_lookup,
    historical_lookup_into, ptr, ptr_mut,
};

const ZONE: u64 = 1 << 16;
const PAGE: u64 = 4096;
const INPUT: u64 = 1 << 24;
/// Where a machine returns to halt.
pub const HALT: u64 = (1 << 32) - ZONE;
/// The top of the standard stack.
pub const STACK_TOP: u64 = (1 << 32) - 2 * ZONE - INPUT;
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
    /// Neither the pool nor the preimages know the program.
    Missing,
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
    let mut header = [0u8; StandardHeader::LEN];
    let len = historical_lookup_into(program, &mut header)?;
    (len >= StandardHeader::LEN)
        .then(|| StandardHeader::read(&header))
        .flatten()
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
    pub id: u64,
    pub frame: [u64; 14],
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
        let (id, _) = ecalli!(INSTANTIATE, [ptr(program), 0, 0, 0, 0, 0]);
        let id = match id {
            code::FULL => return Err(Unavailable::Full),
            code::WHAT | code::WHO => {
                let blob = historical_lookup(program).ok_or(Unavailable::Missing)?;
                load(&blob)?
            }
            id => id,
        };
        let mut frame = [0u64; 14];
        frame[1] = HALT;
        frame[2] = STACK_TOP;
        Ok(Self {
            id,
            frame,
            tracking: None,
        })
    }

    /// Track the pages written in the machine from here on: arm its
    /// writable pages, as `header` places them, read-only. False when
    /// `pages` refuses them.
    ///
    /// Neither the arming nor a page's repair is metered yet: workflows
    /// will take both from the batch's budget, the arming by its pages and
    /// each repair at a measured bounce, as a served precompile is taken.
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

    #[inline]
    pub fn set_register(&mut self, index: usize, value: u64) {
        self.frame[1 + index] = value;
    }

    /// Run until the machine stops. A tracked machine's first store to a
    /// page it may write marks the page and resumes.
    #[inline]
    pub fn invoke(&mut self) -> Exit {
        match self.invoke_once() {
            Exit::Fault(address) if self.tracking.is_some() => self.resume(address),
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
    /// is a first store to a page it may write, open the page and resume.
    #[cold]
    #[inline(never)]
    fn resume(&mut self, mut address: u64) -> Exit {
        while self.open(address / PAGE, address / PAGE + 1) {
            match self.invoke_once() {
                Exit::Fault(next) => address = next,
                exit => return exit,
            }
        }
        Exit::Fault(address)
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
    fn peek_into(&self, address: u64, out: &mut [u8]) -> bool {
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
            return self.write_tracked(address, bytes);
        }
        self.poke(address, bytes)
            .then_some(())
            .ok_or(Failure::Trapped)
    }

    #[cold]
    #[inline(never)]
    fn write_tracked(&mut self, address: u64, bytes: &[u8]) -> Result<(), Failure> {
        if !bytes.is_empty() {
            let end = address.saturating_add(bytes.len() as u64);
            self.open(address / PAGE, end.div_ceil(PAGE));
        }
        self.poke(address, bytes)
            .then_some(())
            .ok_or(Failure::Trapped)
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

fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| value << 8 | u64::from(*byte))
}

/// Build a machine from a standard program: its code through `machine`,
/// then each region through `pages` and `poke`, at the Gray Paper's
/// standard layout with no arguments.
fn load(blob: &[u8]) -> Result<u64, Unavailable> {
    let header = StandardHeader::read(blob).ok_or(Unavailable::Missing)?;
    let [ro, rw, stack] = header.regions().ok_or(Unavailable::Missing)?;
    let (ro_len, rw_len) = (header.ro_size as usize, header.rw_size as usize);
    let at = StandardHeader::LEN;
    let ro_data = blob.get(at..at + ro_len).ok_or(Unavailable::Missing)?;
    let rw_data = blob
        .get(at + ro_len..at + ro_len + rw_len)
        .ok_or(Unavailable::Missing)?;
    let at = at + ro_len + rw_len;
    let code_len = blob.get(at..at + 4).map(le).ok_or(Unavailable::Missing)? as usize;
    let code = blob
        .get(at + 4..at + 4 + code_len)
        .ok_or(Unavailable::Missing)?;

    let (id, _) = ecalli!(MACHINE, [ptr(code), code.len() as u64, 0, 0, 0, 0]);
    match id {
        code::FULL => return Err(Unavailable::Full),
        code::HUH | code::WHAT => return Err(Unavailable::Missing),
        _ => {}
    }
    let machine = Machine {
        id,
        frame: [0; 14],
        tracking: None,
    };
    let laid_out = |region: Region, bytes: &[u8]| match region.writable {
        true => machine.map(region.base, region.size, bytes),
        false => machine.map_read_only(region.base, region.size, bytes),
    };
    if !laid_out(ro, ro_data) || !laid_out(rw, rw_data) || !laid_out(stack, &[]) {
        return Err(Unavailable::Missing);
    }
    let machine = core::mem::ManuallyDrop::new(machine);
    Ok(machine.id)
}
