use alloc::vec::Vec;

use scale::{Decode, Encode};

use super::price;
use crate::defaults::MAX_HANDLER_GAS;

pub const REQUEST: usize = 64 << 10;
pub const REPLY: usize = 64 << 10;
pub const KEY: usize = 1 << 10;
/// An ordered table's key: a tree path through it is then at most
/// about 1,040 levels deep.
pub const ORDERED_KEY: usize = 64;
pub const VALUE: usize = 64 << 10;
pub const STEP_WRITES: usize = 256 << 10;
/// One scan's output: room for a row at the key and value caps with
/// both length prefixes.
pub const SCAN: usize = KEY + VALUE + 16;
/// The largest row the agent stores in a table or committed map, framed
/// as a state scan returns it: both length prefixes, the table's prefix,
/// a hashed key of `KEY` zero bytes escaped and terminated, and a value
/// at its cap after the format byte and a committed map's version.
pub const STORED_ROW: usize = 8 + crate::keys::TABLE_PREFIX + 16 + 2 * KEY + 2 + 1 + 8 + VALUE;
pub const MESSAGES: usize = 16;
pub const MESSAGE: usize = 64 << 10;
pub const ATTESTS: usize = 16;
pub const WORK_RESULT: usize = 4 << 20;
/// The pages a workflow's program, its actor's, may write, its data,
/// heap and stack: a start of a workflow of a larger one fails.
pub const WORKFLOW_PAGES: usize = 4096;
/// The raw bytes of the pages one workflow step may write: past it, the
/// step fails.
///
/// **The budget binds first.** A step takes from its batch's budget,
/// whatever host it runs on:
/// - before it runs, and every step: [`crate::defaults::WORKFLOW_RESERVE`],
///   [`crate::defaults::ARM_PAGE`] for each page its program may write,
///   [`crate::defaults::RESTORED_PAGE`] for each page its workflow holds,
///   and its gas limit;
/// - its machine's gas: its effect-free code's share, the limit, and the
///   limit again for each unit from its first effect, when the refine has
///   it beyond what the step used, or the step ends at that effect;
/// - [`crate::defaults::WRITTEN_PAGE`] for each page it writes, before the
///   page opens, again in every step that writes it.
///
/// So the pages a step restores and writes satisfy `restored ×
/// RESTORED_PAGE + written × WRITTEN_PAGE + limit + reserves ≤ budget`:
/// in a refine of the default budget (`REFINE_GAS`), a step that restores
/// no page writes about 800, whatever its host, and one that restores
/// [`HELD_PAGES`] about 310. Effect-free code that would pass it ends the
/// step at the first page it cannot pay, once its machine has moved, so a
/// computation larger than a step moves on, a step a batch; once a unit
/// has made an effect, the step waits for the next batch behind a step
/// that ran a handler, or fails alone, out of gas.
pub const STEP_PAGES: usize = 8 << 20;
/// The pages a workflow's snapshot may hold, 2.25 MiB: a step that
/// would leave it more fails, so the least budget a node refines with
/// ([`crate::defaults::min_refine_gas`]) restores any snapshot. On JAM,
/// the step that ends a workflow holding them all, at the largest
/// limit, restores every page and drops every page's row, and a
/// package of that step alone, bar its own effects, fits a work
/// package's refine gas: an agent's builder asserts it.
pub const HELD_PAGES: usize = 576;
/// The raw bytes of the pages one work result's page section may hold:
/// a step that would pass it waits for the next batch.
pub const RESULT_PAGES: usize = 16 << 20;
/// A refine's whole output: the work result, then its page section, in
/// which a page, LZ4-compressed and framed, may outgrow its 4 KiB by a
/// few dozen bytes.
pub const OUTPUT: usize = WORK_RESULT + RESULT_PAGES + RESULT_PAGES / 64;

/// The most a step of `gas` adds to a work result: its input, a new
/// session's whole, its reply, writes, messages and attests at their
/// caps, a request's reply to its sender, with the framing of as many
/// writes (committed ones, with their map, the larger) and instances as
/// `gas` can pay for.
pub const fn step_result(gas: u64) -> usize {
    128 + REPLY
        + STEP_WRITES
        + (gas / price::PUT) as usize * 18
        + (1 + (gas / price::MACHINE) as usize) * 12
        + MESSAGES * (MESSAGE + 40)
        + (REPLY + 40)
        + ATTESTS * (REQUEST + REPLY + 40)
}

/// The most a handler's step adds to a work result. An install's record
/// is under [`STEP_WRITES`] too.
pub const STEP_RESULT: usize = step_result(MAX_HANDLER_GAS);

/// What a workflow's step adds beyond its calls' effects: its record,
/// with its arguments, last input or result and the hash of each page
/// it holds, the rows beside it, and an entry for each page it stores,
/// at most those it holds after, and drops, at most those it held
/// before.
pub const WORKFLOW_ROWS: usize = 1024 + REQUEST + HELD_PAGES * 36 + 2 * HELD_PAGES * 48;

/// The most a workflow's step adds to a work result: its calls' effects
/// at the gas it may use, its limit for its effect-free code and its
/// limit again from a unit's first effect, and its rows.
pub const WORKFLOW_STEP_RESULT: usize = step_result(2 * MAX_HANDLER_GAS) + WORKFLOW_ROWS;

// Every step fits an empty result, so a batch always makes progress.
const _: () = assert!(STEP_RESULT + 64 <= WORK_RESULT);
const _: () = assert!(WORKFLOW_STEP_RESULT + 64 <= WORK_RESULT);

/// Where an instance is installed to run, which sets the [`Limits`] it runs
/// within: its install record names it. The agent holds an instance to its
/// target's limits on every host, so a JAM builder's simulation, the JAM
/// refine and a VOS node running the same batch agree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Target {
    /// A VOS node.
    #[default]
    #[codec(index = 0)]
    Vos = 0,
    /// A JAM service, whose work package pays, in software and beyond its
    /// batch's budget, for hashing, applying and exporting what each step
    /// leaves in the work result.
    #[codec(index = 1)]
    Jam = 1,
}

impl Target {
    pub const fn limits(self) -> &'static Limits {
        match self {
            Target::Vos => &VOS,
            Target::Jam => &JAM,
        }
    }
}

/// What an instance may do and be on its [`Target`]. A step past an effect
/// or memory limit fails, [`super::Failure::Cap`]; a program past a static
/// one is refused at install, likewise. Every target pays the same prices,
/// a page's included ([`crate::defaults::WRITTEN_PAGE`] and its kin): the
/// limits cap what a step does, and never price it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The bytes of state a step writes, keys and values, its nested
    /// calls' included.
    pub step_writes: usize,
    /// The rows a step writes or deletes.
    pub step_rows: usize,
    /// The messages a step sends, a workflow's request or wait included.
    pub messages: usize,
    /// A message's arguments.
    pub message: usize,
    /// The attests a step makes.
    pub attests: usize,
    /// An attest's arguments, and its output.
    pub attest: usize,
    /// The pages a workflow's program may write, its data, heap and stack:
    /// a start of a workflow of a larger one fails.
    pub workflow_pages: usize,
    /// The bytes of the pages one workflow step may write.
    pub step_pages: usize,
    /// The pages a workflow's snapshot may hold.
    pub held_pages: usize,
    /// How long, in milliseconds of batch time, a workflow's stored page
    /// stays where its next step finds it: a step due later, its snapshot
    /// holding a page stored that long before, fails
    /// [`super::Failure::Expired`] instead of restoring it. `None`: kept
    /// until the workflow ends.
    pub pages_kept: Option<u64>,
    /// The pages an actor's program may write, checked at install; `None`
    /// where only a workflow's start checks them.
    pub program_pages: Option<usize>,
    /// The bytes of an actor's program, checked at install.
    pub program: usize,
    /// The kernels an install binds.
    pub kernels: usize,
    /// The BLAKE2b compressions one kernel's run may make, each served by
    /// the agent ([`crate::defaults::PRECOMPILE_SERVING`]): its method's
    /// gas limit over the precompile's price bounds them, checked at
    /// install, and a kernel runs within that limit. `None`: the calling
    /// handler's gas alone bounds a kernel.
    pub kernel_compressions: Option<u64>,
}

/// A VOS node's limits: the caps above.
pub const VOS: Limits = Limits {
    step_writes: STEP_WRITES,
    step_rows: usize::MAX,
    messages: MESSAGES,
    message: MESSAGE,
    attests: ATTESTS,
    attest: REQUEST,
    workflow_pages: WORKFLOW_PAGES,
    step_pages: STEP_PAGES,
    held_pages: HELD_PAGES,
    pages_kept: None,
    program_pages: None,
    program: 64 << 20,
    kernels: 1024,
    kernel_compressions: None,
};

/// A JAM service's limits. What a step leaves in its work result its
/// package pays for beyond its batch's budget, in software: at VOS's caps a
/// step's effects take up to about 1.4e9 gas of that own work, past a work
/// package's refine gas; at these about 39M, a 35th, which an agent's
/// builder asserts leaves its worst step a package, every page it may hold
/// restored, stored and dropped. Its messages and attests carry a 32nd of
/// the bytes, half as many; its writes a 16th of the bytes, in at most 128
/// rows. A workflow holds a ninth of the pages, and writes a 32nd of them
/// in a step; an actor's program writes at most a 16th of them, and loads
/// within a step's reserve. A workflow's pages travel as exported segments,
/// which JAM's data availability keeps for a limited time, so a workflow
/// that waits a day past storing a page it holds ends: well within that
/// time, and deterministically, rather than waiting for good on pages
/// gone. A kernel hashes about a 40th of what the most
/// gas a handler may request pays for.
pub const JAM: Limits = Limits {
    step_writes: 16 << 10,
    step_rows: 128,
    messages: 8,
    message: 2 << 10,
    attests: 8,
    attest: 2 << 10,
    workflow_pages: 256,
    step_pages: 256 << 10,
    held_pages: 64,
    pages_kept: Some(24 * 60 * 60 * 1000),
    program_pages: Some(256),
    program: 512 << 10,
    kernels: 32,
    kernel_compressions: Some(4096),
};

impl Limits {
    /// Whether each of its limits is at most `other`'s, so what `other`
    /// sizes holds it too.
    pub const fn within(&self, other: &Limits) -> bool {
        let pages = match (self.program_pages, other.program_pages) {
            (_, None) => true,
            (Some(mine), Some(theirs)) => mine <= theirs,
            (None, Some(_)) => false,
        };
        let compressions = match (self.kernel_compressions, other.kernel_compressions) {
            (_, None) => true,
            (Some(mine), Some(theirs)) => mine <= theirs,
            (None, Some(_)) => false,
        };
        let kept = match (self.pages_kept, other.pages_kept) {
            (_, None) => true,
            (Some(mine), Some(theirs)) => mine <= theirs,
            (None, Some(_)) => false,
        };
        self.step_writes <= other.step_writes
            && self.step_rows <= other.step_rows
            && self.messages <= other.messages
            && self.message <= other.message
            && self.attests <= other.attests
            && self.attest <= other.attest
            && self.workflow_pages <= other.workflow_pages
            && self.step_pages <= other.step_pages
            && self.held_pages <= other.held_pages
            && self.program <= other.program
            && self.kernels <= other.kernels
            && pages
            && compressions
            && kept
    }
}

// The caps above size every step's result and every batch's floor, so each
// target's limits stay within them.
const _: () = assert!(JAM.within(&VOS));
const _: () = assert!(VOS.attest <= REQUEST && VOS.attest <= REPLY);
