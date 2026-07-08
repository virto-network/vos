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

use alloc::vec::Vec;

use cipher_clerk::crypto::Amount;

use crate::WindowNetEntry;

/// Fold an accepted voucher's `amount_commit` into the receiver term for
/// `(peer_name, currency, window)`: `neg_sum ← neg_sum ⊖ commit`. Called at
/// exactly the accept points that advance the F2 `last_root_after` anchor,
/// so the receiver term and the anchor never diverge.
pub(crate) fn accumulate_neg(
    nets: &mut Vec<WindowNetEntry>,
    peer_name: &[u8],
    currency: u32,
    window: u64,
    commit: &Amount,
) {
    let idx = nets.iter().position(|n| {
        n.peer_name == peer_name && n.currency == currency && n.window == window
    });
    let current = match idx {
        Some(i) => Amount(nets[i].neg_sum),
        None => Amount::ZERO,
    };
    let updated = sub_commit(&current, commit);
    match idx {
        Some(i) => nets[i].neg_sum = updated.0,
        None => nets.push(WindowNetEntry {
            peer_name: peer_name.to_vec(),
            currency,
            window,
            neg_sum: updated.0,
        }),
    }
}

/// The stored receiver term for `(peer_name, currency, window)`, or `None`
/// if nothing has accumulated there yet.
pub(crate) fn window_net(
    nets: &[WindowNetEntry],
    peer_name: &[u8],
    currency: u32,
    window: u64,
) -> Option<[u8; 32]> {
    nets.iter()
        .find(|n| n.peer_name == peer_name && n.currency == currency && n.window == window)
        .map(|n| n.neg_sum)
}

/// `a ⊖ b` over the Pedersen group. A degenerate (non-decompressable)
/// operand is treated as the identity so accumulation can never panic on a
/// malformed commit — a signature-verified voucher never carries one, but
/// the receiver term must not be a crash oracle regardless.
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
    /// blindings cancel by construction.
    #[test]
    fn worked_example_two_bank_net_flows_cancel() {
        let c1 = Amount::commit(10, &Blinding([1u8; 32])); // A → B voucher
        let c2 = Amount::commit(3, &Blinding([2u8; 32])); // B → A voucher

        // Receiver terms the two bridges accumulate: A's bridge accepted C₂
        // from B; B's bridge accepted C₁ from A.
        let mut nets_a: Vec<WindowNetEntry> = Vec::new();
        accumulate_neg(&mut nets_a, b"bank-b", USD, 0, &c2);
        let recv_a = Amount(window_net(&nets_a, b"bank-b", USD, 0).unwrap()); // ⊖C₂

        let mut nets_b: Vec<WindowNetEntry> = Vec::new();
        accumulate_neg(&mut nets_b, b"bank-a", USD, 0, &c1);
        let recv_b = Amount(window_net(&nets_b, b"bank-a", USD, 0).unwrap()); // ⊖C₁

        // Issuer terms the drivers keep: what each bank ISSUED to the peer.
        let net_a = add(&c1, &recv_a); // C₁ ⊖ C₂
        let net_b = add(&c2, &recv_b); // C₂ ⊖ C₁

        assert!(
            add(&net_a, &net_b).is_zero(),
            "C₁⊖C₂ and C₂⊖C₁ must sum to the identity point",
        );
    }

    #[test]
    fn accumulate_neg_sums_multiple_accepts_in_one_window() {
        let c1 = Amount::commit(10, &Blinding([1u8; 32]));
        let c2 = Amount::commit(5, &Blinding([3u8; 32]));
        let mut nets = Vec::new();
        accumulate_neg(&mut nets, b"peer", USD, 0, &c1);
        accumulate_neg(&mut nets, b"peer", USD, 0, &c2);
        assert_eq!(nets.len(), 1);
        // neg_sum == ⊖(C₁ ⊕ C₂).
        let expected = Amount::from_point(&(-add(&c1, &c2).to_point().unwrap()));
        assert_eq!(nets[0].neg_sum, expected.0);
    }

    #[test]
    fn accumulate_neg_separates_windows_and_peers() {
        let c = Amount::commit(10, &Blinding([1u8; 32]));
        let mut nets = Vec::new();
        accumulate_neg(&mut nets, b"peer", USD, 0, &c);
        accumulate_neg(&mut nets, b"peer", USD, 1, &c); // next bracket
        accumulate_neg(&mut nets, b"other", USD, 0, &c); // different peer
        assert_eq!(nets.len(), 3);
        assert!(window_net(&nets, b"peer", USD, 2).is_none());
    }
}
