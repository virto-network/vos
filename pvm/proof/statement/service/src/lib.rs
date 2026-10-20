//! The JAM statements service (`slice-6-on-chain.md`, step 6.19; pins D and
//! F): a venue on JAM, as a dedicated service.
//!
//! - **Its items** ([`item`]): `Register`, `Migrate`, `Anchor` and
//!   `Submit { statement, proof }`, the statement in the item's payload and
//!   the proof its first extrinsic. JAM-NP's CE 133 bounds a work package
//!   at 204,802 bytes, below the 256 KiB a proof may take.
//! - **Refine** ([`refine`]) reads no state: it verifies a registration's,
//!   a migration's or an anchor's ed25519 signature against the key it
//!   names, and runs pin F's checks of a statement but `anchored` and
//!   `seen`, then its proof; its output is a [`verdict::Verdict`].
//! - **Accumulate** ([`accumulate`]) holds the spaces, their anchors and
//!   the statements accepted ([`state`]): it checks an anchor's signer
//!   against the space's keys and applies pin D's anchor rule at the
//!   venue's time (the slot's), and checks a statement's roots anchored
//!   and its id unseen before recording it under the `Seen` rule.
//! - **A deployment's constants** ([`config`]): the JAM chain's genesis hash
//!   (the venue's id is `VenueId::jam(genesis, service)`), its genesis time
//!   and the programs it pins, venue-bound or not; set in the linked
//!   program before it is deployed, changed by redeploy.
//!
//! **What refine cannot do.** It reads no state, so it cannot check `seen`:
//! a replayed statement costs a whole refine, about 120M gas, before
//! accumulate refuses it as repeated (6). The defence on JAM is the core
//! time a package costs its submitter, not `seen` before the proof.
//!
//! **Sizes.** A statement is at most [`item::MAX_STATEMENT_BYTES`], as
//! Kreivo bounds it, so a verdict is at most [`MAX_VERDICT_BYTES`] (a
//! statement's roots, 41 bytes each), within a report's 48 KiB: a package
//! of one `Submit` fits its report whatever the statement.
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

/// The longest verdict refine outputs: a statement's at its bound, every
/// byte past its header a root's (73 bytes in the statement, 41 in the
/// verdict), with its header (its tag, id, program, space, code and a
/// count of five bytes at most), and the gas's 8 after it.
pub const MAX_VERDICT_BYTES: usize = 1 + 32 * 3 + 4 + 5 + ROOTS * 41 + 8;
/// The most roots a statement of [`item::MAX_STATEMENT_BYTES`] holds.
const ROOTS: usize = item::MAX_STATEMENT_BYTES / vos_statement::RootRead::BYTES;
/// A work report's elective data, `W_R`: its outputs' bound.
pub const REPORT_BYTES: usize = 48 << 10;

const _: () = assert!(MAX_VERDICT_BYTES <= REPORT_BYTES);

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
