//! Receiver-side settlement accumulation.
//!
//! The bridge's mandatory contribution to a settlement claim is the
//! **receiver term**: the negated sum of the `amount_commit`s of every
//! voucher it has ACCEPTED from a peer this window,
//!
//! ```text
//! receiver_net(peer, window) = ⊖ Σ amount_commit(vouchers accepted from peer)
//! ```
//!
//! The per-bank driver point-adds this to its issuer term (the sum of what
//! it ISSUED to the peer) to form the full net flow it signs into a
//! `SettlementClaim`. Because both banks derive their flow from the *same*
//! voucher commitments, the blindings cancel by construction and the two
//! claims sum to the identity point — which is exactly what the venue's
//! `reconcile` checks.
//!
//! Windows are operational brackets: vouchers carry no window / timestamp /
//! currency, so the sum is bracketed by explicit `window_rotate` events and
//! keyed by the fixed demo currency the peer was registered under.

use cipher_clerk::crypto::Amount;
use vos::storage::StorageMap;

/// Domain-separated 32-byte row key for a `(peer, currency, window)`
/// receiver term. `peer_name` is operator-opaque and variable length, so
/// the composite discriminant is folded into a fixed-width key the
/// `StorageMap` can address. The map is only ever point-queried
/// (`accumulate_neg` folds one row, `window_net` reads one), never
/// iterated, so hashing forfeits nothing here.
pub(crate) fn window_key(peer_name: &[u8], currency: u32, window: u64) -> [u8; 32] {
    vos::crypto::blake2b_hash::<32>(
        b"clerk-bridge/window-net/v1",
        &[peer_name, &currency.to_be_bytes(), &window.to_be_bytes()],
    )
}

/// Fold an accepted voucher's `amount_commit` into the receiver term for
/// `(peer_name, currency, window)`: `neg_sum ← neg_sum ⊖ commit`. Called at
/// exactly the accept points that advance the F2 `last_root_after` anchor,
/// so the receiver term and the anchor never diverge. One point read plus
/// one point write, independent of how many windows the bridge tracks.
pub(crate) fn accumulate_neg(
    nets: &mut StorageMap<[u8; 32], [u8; 32]>,
    peer_name: &[u8],
    currency: u32,
    window: u64,
    commit: &Amount,
) {
    let key = window_key(peer_name, currency, window);
    let current = nets.get(&key).map(Amount).unwrap_or(Amount::ZERO);
    let updated = sub_commit(&current, commit);
    nets.insert(&key, &updated.0);
}

/// The stored receiver term for `(peer_name, currency, window)`, or `None`
/// if nothing has accumulated there yet.
pub(crate) fn window_net(
    nets: &StorageMap<[u8; 32], [u8; 32]>,
    peer_name: &[u8],
    currency: u32,
    window: u64,
) -> Option<[u8; 32]> {
    nets.get(&window_key(peer_name, currency, window))
}

/// `a ⊖ b` over the Pedersen group. A degenerate (non-decompressable)
/// operand is treated as the identity so accumulation can never panic on a
/// malformed commit. The accept paths (`submit_voucher`/`redeem_voucher`)
/// already reject a non-canonical `amount_commit` before folding it in, so
/// the `None` arms are unreachable defense-in-depth — the receiver term
/// must not be a crash oracle even if that ingress guard ever regresses.
fn sub_commit(a: &Amount, b: &Amount) -> Amount {
    match (a.to_point(), b.to_point()) {
        (Some(pa), Some(pb)) => Amount::from_point(&(pa - pb)),
        (Some(pa), None) => Amount::from_point(&pa),
        (None, Some(pb)) => Amount::from_point(&(-pb)),
        (None, None) => Amount::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher_clerk::crypto::{Amount, Blinding};

    const USD: u32 = 840;

    /// Point-add two commits — the driver's `issuer_term ⊕ receiver_term`.
    fn add(a: &Amount, b: &Amount) -> Amount {
        match (a.to_point(), b.to_point()) {
            (Some(pa), Some(pb)) => Amount::from_point(&(pa + pb)),
            _ => Amount::ZERO,
        }
    }

    /// The normative worked example (federation-showcase.md §4 S2): A pays
    /// B 10 (commit C₁), B pays A 3 (commit C₂). Bank A's claim nets
    /// C₁ ⊖ C₂ and bank B's nets C₂ ⊖ C₁; their sum is the identity point.
    /// Both banks' terms are derived from the SAME two commitments, so the
    /// blindings cancel by construction. The receiver term a bridge folds is
    /// `sub_commit(ZERO, commit)` = ⊖commit — the arithmetic
    /// `accumulate_neg` now writes through a `StorageMap`; the map's
    /// get/insert round-trip is exercised by vos's own storage tests and the
    /// federation e2e, so these cases pin the crypto, not the backend.
    #[test]
    fn worked_example_two_bank_net_flows_cancel() {
        let c1 = Amount::commit(10, &Blinding([1u8; 32])); // A → B voucher
        let c2 = Amount::commit(3, &Blinding([2u8; 32])); // B → A voucher

        // Receiver terms the two bridges accumulate: A's bridge accepted C₂
        // from B; B's bridge accepted C₁ from A.
        let recv_a = sub_commit(&Amount::ZERO, &c2); // ⊖C₂
        let recv_b = sub_commit(&Amount::ZERO, &c1); // ⊖C₁

        // Issuer terms the drivers keep: what each bank ISSUED to the peer.
        let net_a = add(&c1, &recv_a); // C₁ ⊖ C₂
        let net_b = add(&c2, &recv_b); // C₂ ⊖ C₁

        assert!(
            add(&net_a, &net_b).is_zero(),
            "C₁⊖C₂ and C₂⊖C₁ must sum to the identity point",
        );
    }

    #[test]
    fn accumulate_folds_multiple_accepts_in_one_window() {
        // Two accepts in the same window fold as ⊖C₁ then ⊖C₂ over the
        // running term — the exact sequence `accumulate_neg` applies after
        // reading the current row back.
        let c1 = Amount::commit(10, &Blinding([1u8; 32]));
        let c2 = Amount::commit(5, &Blinding([3u8; 32]));
        let term = sub_commit(&sub_commit(&Amount::ZERO, &c1), &c2);
        // term == ⊖(C₁ ⊕ C₂).
        let expected = Amount::from_point(&(-add(&c1, &c2).to_point().unwrap()));
        assert_eq!(term.0, expected.0);
    }

    #[test]
    fn window_key_separates_windows_peers_and_currencies() {
        // Distinct discriminants must land on distinct rows so terms never
        // cross-contaminate; identical ones must collide so folds accumulate.
        assert_ne!(
            window_key(b"peer", USD, 0),
            window_key(b"peer", USD, 1),
            "a window rotation moves to a fresh row",
        );
        assert_ne!(
            window_key(b"peer", USD, 0),
            window_key(b"other", USD, 0),
            "a different peer is a different row",
        );
        assert_ne!(
            window_key(b"peer", USD, 0),
            window_key(b"peer", USD + 1, 0),
            "a different currency is a different row",
        );
        assert_eq!(
            window_key(b"peer", USD, 0),
            window_key(b"peer", USD, 0),
            "the same triple is the same row, so accepts accumulate",
        );
    }
}
