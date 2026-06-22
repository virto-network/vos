//! JAR/JAM protocol capability numbering.
//!
//! IDs match the canonical slot numbers in `spec/Jar/JAVM/Capability.lean`
//! (`protocolGas = 1`, `protocolFetch = 2`, ... `protocolQuota = 28`).
//! When a guest executes `ecalli N` the javm kernel looks up cap slot `N`
//! in the active VM's cap table; for slots 1..=28 the kernel pre-populates
//! `Cap::Protocol(ProtocolCap { id: N })` which exits to the host as
//! `KernelResult::ProtocolCall { slot: N }`. The host is responsible for
//! enforcing phase discipline: e.g. `STORAGE_W` is refused in refine, while
//! `STORAGE_R` is legal in both phases.
//!
//! Per spec `Capability.lean:119-126`:
//!
//! ```text
//! [0]       IPC / REPLY
//! [1..=28]  Protocol caps (gaps at 10..=14 reserved)
//! [29..=63] Program caps (inherited via CREATE bitmask)
//! [64..]    Program caps (inherited via MOVE)
//! [254]     UNTYPED
//! [255]     free
//! ```
//!
//! Slots 10..=14 are reserved by the spec for future protocol caps. VOS
//! provisionally squats on three of them for its own debug/allocator/invoke
//! hooks; these must migrate to VOS-owned program caps (slots 29..=63) in a
//! follow-up that teaches `grey-transpiler` to emit them.

// --- Spec-canonical protocol caps (slots 1..=28) ---

pub const GAS: u32 = 1;
pub const FETCH: u32 = 2;
pub const PREIMAGE_LOOKUP: u32 = 3;
pub const STORAGE_R: u32 = 4;
pub const STORAGE_W: u32 = 5;
pub const INFO: u32 = 6;
pub const HISTORICAL: u32 = 7;
pub const EXPORT: u32 = 8;
pub const COMPILE: u32 = 9;

// Spec-reserved range 10..=14 — provisional VOS squatters.
pub const GROW_HEAP: u32 = 10;
pub const DEBUG_WRITE: u32 = 11;
pub const INVOKE: u32 = 12;

pub const BLESS: u32 = 15;
pub const ASSIGN: u32 = 16;
pub const DESIGNATE: u32 = 17;
pub const CHECKPOINT: u32 = 18;
pub const SERVICE_NEW: u32 = 19;
pub const SERVICE_UPGRADE: u32 = 20;
pub const TRANSFER: u32 = 21;
pub const SERVICE_EJECT: u32 = 22;
pub const PREIMAGE_QUERY: u32 = 23;
pub const PREIMAGE_SOLICIT: u32 = 24;
pub const PREIMAGE_FORGET: u32 = 25;
pub const OUTPUT: u32 = 26;
pub const PREIMAGE_PROVIDE: u32 = 27;
pub const QUOTA: u32 = 28;

// --- VOS-specific high-range hostcalls (slots 29..=127, cap-installed by the
// host via `install_vos_precompile_caps`, NOT spec protocol caps) ---
//
// These share the program-cap range the blake2b/ristretto precompiles squat
// (`vos::crypto` IDs 100/110..=114). The host installs a cap for each slot so a
// guest `ecalli N` resolves to a `ProtocolCall { slot: N }` the runtime handles
// rather than `RESULT_WHAT`. All fit javm's `imm <= 127` budget.

/// Boot-context seam. Mints a
/// **fresh** 32-byte `boot_token` on every (re)instantiation (cold AND warm
/// restart), a host-local `device_id`, and a monotonic `boot_epoch`, written as
/// `boot_token(32) ‖ device_id(32) ‖ boot_epoch(u64 LE)` into the guest buffer.
/// The deterministic PVM has no OS entropy, so a forward-ratcheting CSPRNG (the
/// messenger's `HostRand`) re-boots from this each refine entry to keep used MLS
/// randomness from being re-emitted on a warm restart / snapshot fork. Sound
/// only for non-replicated (`Local`) actors — the token is intentionally
/// non-deterministic, so it must never feed a replicated state transition.
pub const BOOT_CONTEXT: u32 = 120;

/// Host wall-clock in Unix-epoch milliseconds. The deterministic PVM has no
/// clock and there is no time precompile; a `Local` actor that needs real time
/// (e.g. the messenger, for MLS KeyPackage/commit `Lifetime` validity that
/// remote peers check against their own clock) reads it here. Like
/// [`BOOT_CONTEXT`] the value is intentionally non-deterministic, so it is sound
/// ONLY for non-replicated (`Local`) actors and must never feed a replicated
/// state transition — replicated actors take time from the `chronos` beacon
/// (sampled once at the raft leader and committed), never from this hostcall.
pub const NOW_MS: u32 = 121;
