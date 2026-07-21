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
//! Slots 10..=14 are reserved by the spec for future protocol caps and VOS
//! never assigns them. Scheduler-supplied VOS capabilities use explicit high
//! slots below the JAVM immediate limit.

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
// VOS service/scheduler, NOT spec protocol caps) ---
//
// These share the program-cap range the blake2b/ristretto precompiles squat
// (`vos::crypto` IDs 100/110..=114). The host installs a cap for each slot so a
// guest `ecalli N` resolves to a `ProtocolCall { slot: N }` the runtime handles
// rather than `RESULT_WHAT`. All fit javm's `imm <= 127` budget.

/// Request additional guest heap pages.
pub const GROW_HEAP: u32 = 117;

/// Best-effort guest diagnostic output.
pub const DEBUG_WRITE: u32 = 118;

/// Invoke a nested actor PVM through the owning VOS scheduler.
pub const INVOKE: u32 = 119;

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

/// Durable actor suspension boundary supplied by the VOS scheduler.
///
/// Refine captures the complete nested JAVM kernel before this call observes
/// a result. A result of `0` drives the transition-finalization branch; after
/// that transition commits, restoring the snapshot injects `1` and execution
/// continues immediately after the source-level `.await`.
pub const SUSPEND: u32 = 122;

/// Validate an attestation proof against guest-derived public inputs.
/// Installed only on the generic service's Accumulate entry; actor PVMs and
/// Refine never receive this capability.
pub const PROOF_VERIFY: u32 = 123;

/// Authenticate the exact canonical physical install request before an empty
/// account is initialized. Installed only on the service Accumulate entry.
pub const INSTALL_AUTH_VERIFY: u32 = 124;

/// Validate an external service's exact accumulation receipt before a
/// committed reply is admitted as continuation input. Accumulate-only.
pub const RECEIPT_VERIFY: u32 = 125;

/// Authenticate one exact canonical physical idle-actor upgrade request
/// against package authority. Accumulate-only; the host must also have the
/// replacement program bytes available.
pub const UPGRADE_AUTH_VERIFY: u32 = 126;

/// Query or stage one canonical actor PVM by `ProgramId` inside the current
/// Accumulate transaction. A zero-length PVM is a read-only availability
/// probe; non-empty bytes are committed only if the service entry succeeds.
pub const PROGRAM_IMPORT: u32 = 127;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vos_capabilities_never_use_jam_protocol_slots() {
        let supplied = [
            GROW_HEAP,
            DEBUG_WRITE,
            INVOKE,
            BOOT_CONTEXT,
            NOW_MS,
            SUSPEND,
            PROOF_VERIFY,
            INSTALL_AUTH_VERIFY,
            RECEIPT_VERIFY,
            UPGRADE_AUTH_VERIFY,
            PROGRAM_IMPORT,
        ];
        assert!(supplied.iter().all(|slot| !(1..=28).contains(slot)));
        for (index, slot) in supplied.iter().enumerate() {
            assert!(!supplied[..index].contains(slot));
            assert!(*slot <= 127, "JAVM ecall immediate overflow");
        }
    }

    #[test]
    fn proof_tracer_uses_the_same_scheduler_capability_ids() {
        assert_eq!(GROW_HEAP, zkpvm::core::ecall::ECALL_VOS_GROW_HEAP);
        assert_eq!(DEBUG_WRITE, zkpvm::core::ecall::ECALL_VOS_DEBUG_WRITE);
        assert_eq!(INVOKE, zkpvm::core::ecall::ECALL_VOS_INVOKE);
    }

    #[test]
    fn v2_actor_handles_do_not_shadow_supplied_capabilities() {
        let actor_handles = crate::v2::TARGET_ACTOR_HANDLE_SLOT
            ..crate::v2::TARGET_ACTOR_HANDLE_SLOT + crate::v2::MAX_ROOT_TREE_ACTORS as u8;
        let occupied = [
            crate::crypto::ECALL_BLAKE2B_COMPRESS as u8,
            GROW_HEAP as u8,
            DEBUG_WRITE as u8,
            INVOKE as u8,
            BOOT_CONTEXT as u8,
            NOW_MS as u8,
            SUSPEND as u8,
            PROOF_VERIFY as u8,
            INSTALL_AUTH_VERIFY as u8,
            RECEIPT_VERIFY as u8,
            UPGRADE_AUTH_VERIFY as u8,
            PROGRAM_IMPORT as u8,
            crate::v2::ACTOR_IPC_CAP_SLOT,
        ];
        assert!(
            occupied
                .into_iter()
                .all(|slot| !actor_handles.contains(&slot))
        );
        assert_eq!(actor_handles.end - actor_handles.start, 63);
        assert!(
            crate::v2::ACTOR_CALLABLE_BASE_SLOT
                .checked_add(crate::v2::MAX_ROOT_TREE_ACTORS as u8 - 1)
                .is_some_and(|last| last < crate::v2::ACTOR_IPC_CAP_SLOT)
        );
        assert!(crate::v2::ACTOR_IPC_CAP_SLOT < crate::v2::ACTOR_SAVED_ARGS_CAP_SLOT);
    }
}
