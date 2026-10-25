//! The JAM statements service (`proving.md` §6, `spaces-pallet.md` §6.1 and
//! §6.3): a venue on JAM, as a dedicated service.
//!
//! - **Its items** ([`item`]): `Register`, `Anchor`, `Submit { statement,
//!   proof }` and `Control`, a statement in the item's payload and its
//!   proof its first extrinsic. JAM-NP's CE 133 bounds a work package at
//!   204,802 bytes, below the 256 KiB a proof may take.
//! - **Refine** ([`refine`]) reads no state: it applies the registration's
//!   checks that read none (`vos_anchor::venue::registration`), verifies an
//!   anchor's or a control's ed25519 signature against the key it names,
//!   and runs `judge`'s checks of a statement but `anchored` and `seen`,
//!   then its proof; its output is a [`verdict::Verdict`].
//! - **Accumulate** ([`accumulate`]) holds the spaces, their anchors and
//!   the statements accepted ([`state`]): it applies the venue rules
//!   (`vos_anchor::venue`) at the venue's time (the slot's) to a
//!   registration and an anchor, and checks a statement's roots anchored
//!   and its id unseen before recording it under the `Seen` rule.
//! - **A deployment's constants** ([`config`]): the JAM chain's genesis hash
//!   (the venue's id is `VenueId::jam(genesis, service)`), its genesis time
//!   and the programs it pins; set in the linked program before it is
//!   deployed, changed by redeploy.
//!
//! **What refine cannot do.** It reads no state, so it cannot check `seen`:
//! a replayed statement costs a whole refine, about 120M gas, before
//! accumulate refuses it as repeated (6). The defence on JAM is the core
//! time a package costs its submitter, not `seen` before the proof.
//!
//! **Sizes.** A statement is at most [`item::MAX_STATEMENT_BYTES`], as
//! Kreivo bounds it, and [`item::MAX_ROOTS`] roots, so a verdict is at most
//! [`MAX_VERDICT_BYTES`]: a package of [`MAX_ITEMS`] items fits its
//! report's 48 KiB whatever its statements.
//!
//! **The service's balance must stay above its threshold.** A `write` past
//! it answers `FULL` and writes nothing: the program then traps, so the
//! whole accumulate reverts rather than record an outcome without its
//! `Seen` entry or a `Last` without its anchor. Junk items' outcomes and
//! spaces' records grow the threshold; an operator alerts on the balance
//! less the threshold (`info`).
//!
//! The service carries no test mode: what an item reaches accumulate as is
//! what refine judged, and accumulate accepts a statement only on a code
//! of 0.
//!
//! The crate is `no_std`; its program (`src/bin/statement-service.rs`,
//! `--features pvm-guest`) runs refine at instruction 0 and accumulate at
//! instruction 5. No input panics it: as in `vos-statement`, an index, a
//! slice, an `unwrap`, a `panic!` or an arithmetic that can overflow is a
//! lint error outside its tests.

#![no_std]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

extern crate alloc;

pub mod accumulate;
pub mod config;
pub mod item;
pub mod refine;
pub mod state;
pub mod verdict;

pub use vos_statement;

/// A JAM slot's length.
pub const SLOT_MS: u64 = 6_000;

/// The longest verdict refine outputs: a statement's of [`item::MAX_ROOTS`]
/// roots (41 bytes each in the verdict), with its header (its tag, id,
/// program, space, code and its roots' compact count, two bytes at 64),
/// and the gas's 8 after it.
pub const MAX_VERDICT_BYTES: usize = 1 + 32 * 3 + 4 + 2 + item::MAX_ROOTS * 41 + 8;
/// A work report's elective data, `W_R`: its outputs' bound.
pub const REPORT_BYTES: usize = 48 << 10;

/// The most items a package to the service holds: their verdicts within a
/// report.
pub const MAX_ITEMS: usize = REPORT_BYTES / MAX_VERDICT_BYTES;

const _: () = assert!(MAX_ITEMS >= 1);

/// A Gray Paper natural at `at` in `bytes`: its value and where it ends.
pub fn natural(bytes: &[u8], at: usize) -> Option<(u64, usize)> {
    let (&first, rest) = bytes.get(at..)?.split_first()?;
    let extra = first.leading_ones() as usize;
    let end = at.checked_add(1)?.checked_add(extra.min(8))?;
    if extra == 8 {
        return Some((u64::from_le_bytes(rest.get(..8)?.try_into().ok()?), end));
    }
    let mut value = 0u64;
    for (shift, &byte) in (0u32..).step_by(8).zip(rest.get(..extra)?) {
        value |= u64::from(byte).checked_shl(shift)?;
    }
    let high =
        u64::from(first) & (0xffu64.checked_shr(u32::try_from(extra).ok()?.checked_add(1)?)?);
    let shift = u32::try_from(extra).ok()?.checked_mul(8)?;
    Some((value | high.checked_shl(shift)?, end))
}
