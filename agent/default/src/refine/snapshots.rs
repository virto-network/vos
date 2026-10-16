//! A workflow's snapshot, captured and restored with Gray Paper calls
//! alone.
//!
//! **Restore:** the program's machine at the snapshot's counter, each page
//! it holds written back from its row, or on JAM from its import, and
//! checked against its hash, the registers set, then its writable pages
//! armed read-only, so the step's first store to each exits to the agent,
//! which marks it written.
//!
//! **Capture,** when the step pauses: each page it wrote is stored, by its
//! hash, when it differs from its base, the program's image or zeros, and
//! from what was held; it is dropped when written back to its base, so a
//! restore gives the base again. The page section holds a stored page
//! LZ4-compressed for a VOS node's row, and whole on JAM, where it is
//! exported as it is.
//!
//! Both are kept out of the step's frame, which the workflow's nested calls
//! sit on: each holds a page's buffer.

use alloc::vec::Vec;
use core::cell::RefCell;
use core::ops::Range;

use vos_pvm_program::{REGISTER_COUNT, StandardHeader};
use vos_wire::abi::Failure;
use vos_wire::abi::cap::Limits;
use vos_wire::ids::{ProgramHash, WorkflowId};
use vos_wire::records::Workflow;
use vos_wire::result::{PAGE, Page, PageSection, digest};

use super::base::Base;
use crate::host::{historical_lookup_from, lost};
use crate::machines::{self, Machine, Unavailable};

const PAGE_BYTES: u64 = PAGE as u64;
/// The most bytes a page takes, LZ4-compressed.
const MAX_STORED: usize = lz4_flex::block::get_maximum_output_size(PAGE);

/// How the page section, and a VOS node's page rows, hold a page.
#[derive(Clone, Copy)]
pub(crate) enum Format {
    /// LZ4-compressed, as a VOS node's rows keep it.
    Compressed,
    /// Whole, as JAM exports it.
    Whole,
}

impl Format {
    /// A page held in this format, read into `page`: false when it is not
    /// a whole page.
    pub(crate) fn unpack(self, held: &[u8], page: &mut [u8; PAGE]) -> bool {
        match self {
            Format::Compressed => {
                matches!(lz4_flex::block::decompress_into(held, page), Ok(PAGE))
            }
            Format::Whole => {
                let whole = held.len() == PAGE;
                if whole {
                    page.copy_from_slice(held);
                }
                whole
            }
        }
    }

    /// The most bytes a page takes, and `page` put into `out` in this
    /// format: the bytes it took.
    fn pack(self, page: &[u8; PAGE], out: &mut [u8]) -> usize {
        match self {
            Format::Compressed => {
                lz4_flex::block::compress_into(page, out).expect("room for a page")
            }
            Format::Whole => {
                out[..PAGE].copy_from_slice(page);
                PAGE
            }
        }
    }

    fn room(self) -> usize {
        match self {
            Format::Compressed => MAX_STORED,
            Format::Whole => PAGE,
        }
    }
}

/// Workflow `id`'s machine for its next step: at its program's start for
/// its first, else at its snapshot's counter with its pages and registers.
/// Then its writable pages are armed, so the step's writes are tracked. A
/// page row gone or not matching its hash is data the agent lost: the
/// refine stops ([`lost`]).
#[inline(never)]
pub(crate) fn restore(
    base: &Base,
    id: WorkflowId,
    workflow: &Workflow,
) -> Result<(Machine, StandardHeader), Failure> {
    let program = &workflow.program.0;
    let mut machine = match &workflow.snapshot {
        None => machines::pinned(program, 0)?,
        Some(snapshot) => {
            if snapshot.registers.len() != REGISTER_COUNT {
                lost("a workflow's registers");
            }
            let mut machine = match machines::pinned(program, snapshot.counter) {
                Err(Unavailable::Counter) => lost("a workflow's counter"),
                acquired => acquired?,
            };
            let mut page = [0u8; PAGE];
            for &(index, hash) in &snapshot.pages {
                let Ok(true) = base.page(id, index, &hash, &mut page) else {
                    lost("a workflow's page row");
                };
                if digest(&page) != hash {
                    lost("a workflow's page");
                }
                machine.write(u64::from(index) * PAGE_BYTES, &page)?;
            }
            for (index, value) in snapshot.registers.iter().enumerate() {
                machine.set_register(index, *value);
            }
            machine
        }
    };
    let header = machines::header(program).ok_or(Failure::Unloadable)?;
    if !machine.track(&header) {
        return Err(Failure::Trapped);
    }
    Ok((machine, header))
}

/// A paused step's pages: the entries its run lists, where in the section
/// lie the LZ4 bytes of those it stores, and the pages the workflow holds
/// now.
pub(crate) struct Captured {
    pub(crate) pages: Vec<Page>,
    pub(crate) stored: Vec<Range<usize>>,
    pub(crate) held: Vec<(u32, [u8; 32])>,
}

/// The pages a paused step wrote, against those the workflow held, each it
/// stores put into `base`'s section in its format as the running step's.
/// Past `limits`' step pages written, or its held pages held after, the
/// step fails, its pages dropped from the section; past the section's cap,
/// the batch cannot take the step, which waits.
#[inline(never)]
pub(crate) fn capture(
    base: &Base,
    machine: &Machine,
    limits: &Limits,
    program: &ProgramHash,
    header: &StandardHeader,
    id: WorkflowId,
    held: &[(u32, [u8; 32])],
) -> Result<Captured, Failure> {
    let captured = pages(
        base.format(),
        machine,
        limits,
        program,
        header,
        id,
        held,
        &base.section,
    );
    if captured.is_err() {
        base.section.borrow_mut().drop_running();
    }
    captured
}

#[allow(clippy::too_many_arguments)]
fn pages(
    format: Format,
    machine: &Machine,
    limits: &Limits,
    program: &ProgramHash,
    header: &StandardHeader,
    id: WorkflowId,
    held: &[(u32, [u8; 32])],
    section: &RefCell<PageSection>,
) -> Result<Captured, Failure> {
    let written = machine.written().expect("a workflow's machine is tracked");
    if written.len() * PAGE > limits.step_pages {
        return Err(Failure::Cap);
    }
    let image = Image::of(header).ok_or(Failure::Trapped)?;
    let mut section = section.borrow_mut();
    let mut pages = Vec::new();
    let mut stored = Vec::new();
    let mut now = Vec::with_capacity(held.len() + written.len());
    let mut before = held.iter().copied().peekable();
    let mut bytes = [0u8; PAGE];
    for &page in written {
        let index = page as u32;
        while let Some(&(kept, _)) = before.peek()
            && kept < index
        {
            now.extend(before.next());
        }
        let previous = before
            .next_if(|&(kept, _)| kept == index)
            .map(|(_, hash)| hash);
        if !machine.peek_into(page * PAGE_BYTES, &mut bytes) {
            return Err(Failure::Trapped);
        }
        if image.holds(program, page, &bytes) {
            if previous.is_some() {
                pages.push(Page {
                    workflow: id,
                    index,
                    hash: None,
                });
            }
            continue;
        }
        let hash = digest(&bytes);
        now.push((index, hash));
        if previous != Some(hash) {
            pages.push(Page {
                workflow: id,
                index,
                hash: Some(hash),
            });
            // Past the section's cap the batch will not take the step.
            stored.extend(section.store(format.room(), |out| format.pack(&bytes, out)));
        }
    }
    now.extend(before);
    if now.len() > limits.held_pages {
        return Err(Failure::Cap);
    }
    Ok(Captured {
        pages,
        stored,
        held: now,
    })
}

/// Where a program's read-write data lies in its blob and its memory: a
/// page's base is that data where it lies, and zeros elsewhere.
struct Image {
    /// The data's offset in the blob.
    offset: u64,
    /// Its address, and its length.
    address: u64,
    len: u64,
}

impl Image {
    fn of(header: &StandardHeader) -> Option<Self> {
        let [_, rw, _] = header.regions()?;
        Some(Self {
            offset: (StandardHeader::LEN as u64) + u64::from(header.ro_size),
            address: rw.base,
            len: u64::from(header.rw_size),
        })
    }

    /// Whether `bytes`, page `page`'s, are its base.
    fn holds(&self, program: &ProgramHash, page: u64, bytes: &[u8; PAGE]) -> bool {
        let address = page * PAGE_BYTES;
        let start = address.saturating_sub(self.address);
        let data = if address >= self.address && start < self.len {
            (self.len - start).min(PAGE_BYTES) as usize
        } else {
            0
        };
        let (head, tail) = bytes.split_at(data);
        if !zeros(tail) {
            return false;
        }
        if data == 0 {
            return true;
        }
        let mut image = [0u8; PAGE];
        historical_lookup_from(&program.0, self.offset + start, &mut image[..data]).is_some()
            && image[..data] == *head
    }
}

/// Whether `bytes` are all zeros, a word at a time.
fn zeros(bytes: &[u8]) -> bool {
    let (words, rest) = bytes.as_chunks::<8>();
    words.iter().all(|word| *word == [0; 8]) && rest.iter().all(|byte| *byte == 0)
}
