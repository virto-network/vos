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
/// **The budget binds first.** A step is taken its pages from the
/// batch's budget, whatever host it runs on: it restores the pages its
/// workflow holds at [`crate::defaults::RESTORED_PAGE`] each, and
/// writes others at [`crate::defaults::WRITTEN_PAGE`] each, beside its
/// gas limit and the agent's reserves. So the pages a step restores and
/// writes satisfy `restored × RESTORED_PAGE + written × WRITTEN_PAGE +
/// limit + reserves ≤ budget`: in a refine of the default budget
/// (`REFINE_GAS`), a step that restores no page writes about 800, and
/// one that restores [`HELD_PAGES`] about 310. Effect-free code that
/// would pass it ends the step at the first page it cannot pay; once a
/// unit has made an effect, the step waits for the next batch behind a
/// step that ran a handler, or fails alone, out of gas.
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
