/// The most binding digests one sweep forgets, beside them
/// ([`crate::keys::SweepBudget`]): a backlog drains this many a sweep, a
/// sweep every batch while rows are due. Bindings keep an index of their
/// own ([`crate::keys::due`]), so a backlog of them never holds a
/// session's or a workflow's row back.
pub const SWEEP_BINDINGS: usize = 64;
/// The most paths one of the representative's closes sends, a message
/// each, within every target's messages a step
/// ([`crate::abi::cap::Limits::messages`]): a window whose agents asked for
/// more goes in several.
pub const CLOSE_PATHS: usize = 8;
/// A handler's gas limit when its schema declares none: about 330
/// gets, 150 puts or 5,000 register-only operations, or about 16,000
/// BLAKE2b compressions.
pub const HANDLER_GAS: u64 = 10_000_000;
/// The most gas a handler's schema may request: node policy, which
/// the agent and the testkit read here.
pub const MAX_HANDLER_GAS: u64 = 100_000_000;
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
/// [`PRECOMPILE_SERVING`] for a Poseidon2 compression: about 5,800 natively
/// on a VOS node and about 38,600 in software on JAM, its permutation's
/// arithmetic dearer in the guest than a BLAKE2b compression's. Measured by
/// the same test.
pub const POSEIDON2_SERVING: u64 = 60_000;
