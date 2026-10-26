/// Replies kept per (session, agent), so a pipelining client can recover
/// any lost reply.
pub const REPLY_WINDOW: u64 = 64;
/// A session expires after this much work-result time without a
/// request, in milliseconds.
pub const SESSION_EXPIRY_MS: u64 = 60 * 60 * 1000;
/// A new session's creation time must be this close to the work
/// result's time, in milliseconds.
pub const SESSION_SKEW_MS: u64 = 60 * 1000;
/// The expiry index files sessions by their time divided by this, in
/// milliseconds: a session is collected at most this long after it
/// expires.
pub const SESSION_BUCKET_MS: u64 = 5 * 60 * 1000;
/// The most rows of the due index one sweep lists.
pub const SWEEP_LIMIT: usize = 32;
/// The most sessions an agent holds: more are refused until some are
/// collected.
pub const MAX_SESSIONS: u64 = 1 << 16;
/// The most sessions one key holds at an agent.
pub const MAX_KEY_SESSIONS: u64 = 64;
/// The most window cuts one work result records: a result whose time
/// crosses more boundaries cuts the newest this many windows, and the
/// older ones are never cut. A consensus constant, on every host.
pub const MAX_CUTS: u64 = 32;
/// The most rows one read at a window's cut names
/// ([`crate::abi::Op::AttestAt`]): about what [`crate::abi::cap::SERVED`]
/// holds, each row's share of the proof included.
pub const MAX_READS: usize = 256;
/// How many windows a read at a window's cut waits to be served: one asked
/// in window `w` that no [`crate::batch::Input::Resume`] has served by the
/// boundary `B_{w + READ_WINDOWS}` ends
/// [`crate::abi::AttestError::NotClosed`]. It is served at its own window's
/// cut alone, once the representative's `Closed` of that window comes; the
/// caller asks again.
pub const READ_WINDOWS: u64 = 2;
/// How many windows behind the latest recorded cut the agent keeps its cut
/// and close rows: a cut recording window `w` deletes those of every window
/// before `w − CUT_KEEP`. It covers a read's whole life, to its deadline. A
/// consensus constant, on every host.
pub const CUT_KEEP: u64 = READ_WINDOWS;
/// The most paths one of the representative's closes sends, a message
/// each, within every target's messages a step
/// ([`crate::abi::cap::Limits::messages`]): a window whose agents asked for
/// more goes in several.
pub const CLOSE_PATHS: usize = 8;

// An expired session's batch time is past its t0 plus the skew: it was
// created within the skew of t0, so a collected session can never be
// created again.
const _: () = assert!(SESSION_EXPIRY_MS >= 2 * SESSION_SKEW_MS);
/// A handler's gas limit when its schema declares none: about 330
/// gets, 150 puts or 5,000 register-only operations, or about 16,000
/// BLAKE2b compressions.
pub const HANDLER_GAS: u64 = 10_000_000;
/// The most gas a handler's schema may request: node policy, which
/// the agent and the testkit read here.
pub const MAX_HANDLER_GAS: u64 = 100_000_000;
/// A refine's gas budget: a hundred handlers at their default limit.
pub const REFINE_GAS: u64 = 1_000_000_000;
/// The agent's own work on an input that may run a handler, a request
/// or a message's call, beyond its handler's gas and the installed
/// records it reads ([`RECORD_BYTE`]): admitting it, acquiring its top
/// machine, through the loader on JAM, and framing its step. About
/// 50,000 for the test actors; the rest is for larger programs, up to
/// about 512 KiB, whose loading grows with the blob. Measured by the
/// testkit's `the_reserves_cover_the_agents_own_work`.
///
/// The agent dispatches by its own accounting of the batch's budget
/// ([`crate::batch::Batch::budget`]), never by the `gas` host call,
/// whose readings differ between hosts: an input goes only if what the
/// earlier steps left covers its reserve, its handler's limit and the
/// finish, and it takes its reserve, the gas its handler used, the
/// installed records it read first, and its served precompiles'
/// [`PRECOMPILE_SERVING`]. So every host dispatches the same steps.
pub const STEP_RESERVE: u64 = 300_000;
/// The same for an input that runs no handler: an acknowledgement, a
/// reply, a message that failed in refine.
pub const INPUT_RESERVE: u64 = 50_000;
/// The same for a sweep: reading the rows of the due index it lists.
pub const SWEEP_RESERVE: u64 = 1_000_000;
/// The same for an install: reading, validating and encoding a schema
/// of `schema::MAX_LEN` bytes from its program's machine, about 6.8M.
pub const INSTALL_RESERVE: u64 = 9_000_000;
/// Gas the agent takes per byte of an installed record it reads for the
/// first time in a refine, before it reads it: reading and decoding the
/// record, about 3.4M for a schema of `schema::MAX_LEN` bytes. The
/// refine keeps it after, and so pays a record once whatever reads it.
pub const RECORD_BYTE: u64 = 64;
/// Gas a refine keeps to finish its result once its steps are written.
pub const FINISH_RESERVE: u64 = 100_000;
/// Gas a refine keeps to start: the program's entry and the batch's
/// fixed fields. Decoding its inputs takes [`DECODE_INPUT`] more for
/// each, and [`DECODE_BYTE`] for every byte of the refine's arguments.
/// Measured by the testkit's `the_start_reserves_cover_decoding_a_batch`.
pub const START_RESERVE: u64 = 100_000;
/// Gas a refine keeps per input of its batch, for decoding it.
pub const DECODE_INPUT: u64 = 6_000;
/// Gas a refine keeps per byte of its arguments, for decoding them.
pub const DECODE_BYTE: u64 = 20;

/// Gas a refine keeps per kernel an install of its batch names, for
/// decoding the kernel's record, its shape among it, past its bytes'
/// [`DECODE_BYTE`]. Measured by the testkit's
/// `the_start_reserves_cover_decoding_a_batch`.
pub const DECODE_KERNEL: u64 = 8_000;

/// What decoding a batch of `inputs` may take, from refine arguments of
/// `len` bytes, when its installs name no kernel, and so a bound for a
/// batch without installs: the gas a node gives a refine beyond its
/// batch's budget, which its steps alone take from, is [`batch_start`].
pub const fn refine_start(inputs: usize, len: usize) -> u64 {
    START_RESERVE + DECODE_INPUT * inputs as u64 + DECODE_BYTE * len as u64
}

/// What decoding `batch` may take, from refine arguments of `len` bytes:
/// [`refine_start`], and [`DECODE_KERNEL`] for each kernel its installs
/// name. The gas a node gives a refine beyond its batch's budget, which
/// its steps alone take from. The agent checks that the budget is left
/// once it has decoded the batch, and traps otherwise.
pub fn batch_start(batch: &crate::batch::Batch, len: usize) -> u64 {
    use crate::batch::{Admin, Input};
    let kernels: usize = batch
        .inputs
        .iter()
        .map(|input| match input {
            Input::Admin(Admin::Install { derivation, .. }) => derivation.kernels.len(),
            _ => 0,
        })
        .sum();
    refine_start(batch.inputs.len(), len) + DECODE_KERNEL * kernels as u64
}

/// The least budget of a batch of at most `max_inputs` that dispatches
/// any input that runs a handler, whatever runs before it: a sweep and
/// the rest of the batch's plain inputs, then the input's own reserve,
/// its record at the most an install writes, and the most a handler may
/// request; or an install; or a workflow's step, restoring the most
/// pages a snapshot holds, its record at its largest, with room for a
/// page past what a sweep leaves inputs; and the finish. A node refines
/// with no less, so every batch makes progress, and every workflow's
/// step can run.
pub const fn min_refine_gas(max_inputs: usize) -> u64 {
    use crate::abi::cap;
    let handler = STEP_RESERVE + RECORD_BYTE * cap::STEP_WRITES as u64;
    let workflow = WORKFLOW_RESERVE
        + ARM_PAGE * cap::WORKFLOW_PAGES as u64
        + RESTORED_PAGE * cap::HELD_PAGES as u64
        + RECORD_BYTE * cap::WORKFLOW_ROWS as u64
        + 2 * WRITTEN_PAGE;
    let mut first = INSTALL_RESERVE;
    if handler > first {
        first = handler;
    }
    if workflow > first {
        first = workflow;
    }
    SWEEP_RESERVE
        + INPUT_RESERVE * max_inputs.saturating_sub(1) as u64
        + first
        + MAX_HANDLER_GAS
        + FINISH_RESERVE
}

/// Gas the agent accounts for serving one precompile call of an inner
/// machine, beyond the price the machine pays: the exit, the copies in
/// and out, and the computation, natively on a VOS node (about 5,000 in
/// all for a BLAKE2b compression) and in software on JAM (about
/// 20,000). Measured by the testkit's
/// `serving_a_precompile_costs_the_agent_its_bounce`.
///
/// It is the batch's, not the machine's: a compression costs a handler
/// 600 of its gas and the batch's budget this much, so one step hashes
/// at most about 4 MiB in a refine of the default budget, on any host.
pub const PRECOMPILE_SERVING: u64 = 27_000;
/// The agent's own work on each byte of the rows a read at a window's cut
/// is served ([`crate::batch::Input::Resume`]), beyond decoding its batch:
/// decoding and checking them against its request, and handing them to
/// the kernel. It is the batch's, taken from its budget as a precompile's
/// serving is, never the workflow's gas. Measured by the testkit's
/// `serving_a_read_pays_for_itself`.
pub const SERVED_BYTE: u64 = 64;
/// The most outbox entries one acknowledgement clears, bounding an ack
/// step's accumulate work, far inside its gas; the node acks again for
/// the rest.
pub const ACK_LIMIT: u64 = 1024;

/// An await's deadline when its call sets none: after the batch time
/// of the step that awaits, in milliseconds.
pub const AWAIT_MS: u64 = 60 * 1000;
/// The most workflows an agent holds that have not ended: a start past
/// it fails. An ended one, kept for its result until collected, is not
/// among them.
pub const MAX_WORKFLOWS: u64 = 1 << 16;
/// How long an ended workflow's result is kept for its owner to read,
/// in milliseconds of batch time: as long as an idle session lives.
pub const WORKFLOW_KEPT_MS: u64 = SESSION_EXPIRY_MS;
// A node's default batch restores any workflow's snapshot.
const _: () = assert!(min_refine_gas(256) <= REFINE_GAS);

/// The agent's own work on a workflow's step beyond its handler's
/// gas and its pages: reading its record and its program's header,
/// acquiring its machine at its counter, and writing its record and
/// rows back. Measured by the testkit's
/// `the_workflow_reserves_cover_the_agents_own_work`. What a step takes
/// of its batch's budget in all: [`crate::abi::cap::STEP_PAGES`].
pub const WORKFLOW_RESERVE: u64 = 400_000;
/// The same per page its program may write, which every step arms
/// read-only and a pool prices a machine by.
pub const ARM_PAGE: u64 = 200;
/// The same per page a step writes, taken before it opens: the exit
/// and repair of its first store, then its capture, compared with its
/// base, hashed, in software on JAM, and compressed. About 340,000 on
/// a VOS node and 830,000 on JAM for a page of random bytes, which
/// compress the slowest. How many a step writes:
/// [`crate::abi::cap::STEP_PAGES`].
pub const WRITTEN_PAGE: u64 = 1_100_000;
/// The same per page a step restores: read, decompressed, hashed, in
/// software on JAM, and written back. About 230,000 on a VOS node and
/// 710,000 on JAM for a page of random bytes.
pub const RESTORED_PAGE: u64 = 950_000;
