//! Tunable constants: domain tags, cadence, and retention bounds.

/// Domain tag separating chronos beacon hashes from every other blake2b use in
/// VOS. The `/v2` suffix pins the current derivation input layout
/// ([`crate::derive_beacon`], which folds the per-round `slot`), so an external
/// re-implementer of a different layout is not silently accepted.
pub const BEACON_DOMAIN_TAG: &[u8] = b"vos-beacon/v2";

/// Domain tag for a round's VRF input `α` ([`crate::derive_alpha`]) — kept
/// distinct from the beacon hash so the two derivations can never collide.
pub const ALPHA_DOMAIN_TAG: &[u8] = b"vos-chronos-alpha/v1";

/// Domain tag for the committee combine ([`crate::combine_betas`]) — the hash
/// that folds the XOR of the voters' VRF outputs down to the 32-byte round
/// entropy.
pub const COMBINE_DOMAIN_TAG: &[u8] = b"vos-chronos-combine/v1";

/// Bound on the operator-chosen per-space domain label. Replicated to every
/// node, so cap it.
pub const MAX_DOMAIN_BYTES: usize = 128;

/// Each round's contributed entropy is exactly 32 bytes.
pub const ENTROPY_LEN: usize = 32;

/// Slots per epoch — entropy is folded at most once per epoch, so this sets the
/// randomness cadence relative to the clock. Default 4 ≈ 1 s at the feeder's
/// default 250 ms slot. The clock advances every slot regardless; only beacon
/// rounds are gated to epoch boundaries.
pub const SLOTS_PER_EPOCH: u64 = 4;

/// How many folded epochs behind the live head a value must be before it is
/// considered **finalized** (the JAM η₂ lesson: the live head η₀ is biasable by
/// a last-revealer, so grinding-sensitive consumers read a lagged buffer). A lag
/// of 2 matches JAM's η₂. [`crate::Chronos::latest_final`] /
/// [`crate::Chronos::randomness_at`] never return a round newer than this;
/// [`crate::Chronos::current`] is the un-lagged head, documented low-stakes-only.
pub const FINALIZED_LAG: usize = 2;

/// How many epochs a committee round stays open for reveals before it folds. A
/// round opened at epoch `N` folds at epoch `N + REVEAL_WINDOW_EPOCHS`,
/// combining whatever committee reveals were committed by then — the fold is at
/// a deterministic clock boundary, so the leader cannot pick the moment. A round
/// opened with an **empty** committee (no enrolled voters to wait for) folds
/// immediately, so an unconfigured space folds the leader entropy at the epoch
/// boundary. This is the reveal-window half of the head-lag; consumers read a
/// value `REVEAL_WINDOW_EPOCHS + FINALIZED_LAG` epochs behind the clock.
pub const REVEAL_WINDOW_EPOCHS: u64 = 2;

// `MAX_SLOT_JUMP` (the future-drift cap) moved to `vos::chronos` — the feeder
// pre-clamps to it and this actor enforces it, so it lives with the shared
// protocol. Re-exported from the crate root.

/// Most-recent rounds retained for `round_at`/`randomness_at` lookups. Older
/// rounds are pruned from the front; the chain head ([`crate::Chronos::current`])
/// is always available. Bounds the replicated state regardless of how long the
/// service runs. One entry per folded epoch, so this is ~1024 epochs of history,
/// not 1024 slots.
pub const MAX_HISTORY: usize = 1024;

/// Cap on rounds returned by one `range` call — a soft response-size budget so
/// one reply stays modest (~14 KiB at ~112 bytes per [`crate::BeaconRound`]). The
/// reply payload is heap-grown host-side, not bounded by the incoming-fetch
/// buffer, so this is a courtesy cap, not a correctness limit.
pub const MAX_RANGE: u32 = 128;
