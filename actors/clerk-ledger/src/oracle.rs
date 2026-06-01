//! `cipher_clerk::state::Oracle` implementations: a no-op for
//! account-creation paths and a stateful one for transfer paths
//! that need commitment openings.

use cipher_clerk::crypto::{Amount, Blinding};
use cipher_clerk::state::{MerklePath, Oracle, Reveal};

use crate::wire::Opening;

/// Oracle for paths that don't read commitment openings.
/// `apply_account_creations` is the canonical user — accounts
/// have no value commitments at creation. Every method is
/// `unimplemented!()` to fail loud if a future kernel path
/// accidentally invokes one.
pub(crate) struct NoopOracle;

impl Oracle for NoopOracle {
    fn reveal_amount(&mut self, _amount: &Amount) -> Reveal {
        unimplemented!("NoopOracle: reveal_amount not used by apply_account_creations")
    }
    fn merkle_path(&mut self, _key: &[u8; 32]) -> MerklePath {
        unimplemented!("NoopOracle: merkle_path not used")
    }
    fn next_blinding(&mut self) -> Blinding {
        unimplemented!("NoopOracle: next_blinding not used")
    }
}

/// Oracle backed by the caller's openings list. `reveal_amount`
/// looks up by byte-equal commitment match. Missing or wrong
/// openings cause the kernel's `verify_reveal` to fail with
/// `BlindingMismatch`, which the handler maps to
/// `Status::AmountUnrecoverable`.
///
/// `merkle_path` and `next_blinding` are unused by `apply_batch`
/// against in-memory state (no SMT proofs, no kernel-constructed
/// commitments — the Pedersen homomorphism handles balance
/// updates without fresh blindings). Same `unimplemented!()`
/// guard as `NoopOracle`.
pub(crate) struct StatefulOracle<'a> {
    pub(crate) openings: &'a [Opening],
}

impl Oracle for StatefulOracle<'_> {
    fn reveal_amount(&mut self, amount: &Amount) -> Reveal {
        match self.openings.iter().find(|o| &o.amount == amount) {
            Some(o) => Reveal {
                value: o.value,
                blinding: o.blinding,
            },
            None => {
                // No opening on file — return junk that the
                // kernel's verify_reveal will reject with
                // BlindingMismatch. The handler then surfaces
                // Status::AmountUnrecoverable.
                Reveal {
                    value: 0,
                    blinding: Blinding([0u8; 32]),
                }
            }
        }
    }
    fn merkle_path(&mut self, _key: &[u8; 32]) -> MerklePath {
        unimplemented!("StatefulOracle: merkle_path not used by in-memory apply_batch")
    }
    fn next_blinding(&mut self) -> Blinding {
        unimplemented!(
            "StatefulOracle: next_blinding not called by apply_batch (homomorphic balance updates)"
        )
    }
}
