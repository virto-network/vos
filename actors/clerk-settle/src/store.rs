//! The claim-store logic behind the venue handlers — kept as free
//! functions over the actor's borrowed state vecs so the store semantics
//! (registration, replace-until-settled, freeze-on-settle, reconcile
//! mapping) unit-test in isolation without a PVM rebuild. The `#[msg]`
//! handlers in `lib.rs` are thin wrappers over these.

use alloc::vec::Vec;

use cipher_clerk::settlement::{SettlementClaim, SettlementError, reconcile};

use crate::{BankEntry, CLAIM_VERSION_V1, ClaimReport, SettledEntry, Status, StoredClaim};

/// Order a pair's two clerk pubkeys ascending so a `(pair, …)` key is
/// direction-independent.
pub(crate) fn sorted_pair(a: [u8; 32], b: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    if a <= b { (a, b) } else { (b, a) }
}

pub(crate) fn bank_pubkey(banks: &[BankEntry], name: &[u8]) -> Option<[u8; 32]> {
    banks
        .binary_search_by(|e| e.name.as_slice().cmp(name))
        .ok()
        .map(|i| banks[i].clerk_pubkey)
}

fn is_registered(banks: &[BankEntry], pubkey: &[u8; 32]) -> bool {
    banks.iter().any(|e| &e.clerk_pubkey == pubkey)
}

fn find_claim(
    claims: &[StoredClaim],
    claimant: &[u8; 32],
    peer: &[u8; 32],
    currency: u32,
    window_start: u64,
    window_end: u64,
) -> Option<usize> {
    claims.iter().position(|c| {
        &c.claimant == claimant
            && &c.peer == peer
            && c.currency == currency
            && c.window_start == window_start
            && c.window_end == window_end
    })
}

fn settled_index(
    settled: &[SettledEntry],
    lo: &[u8; 32],
    hi: &[u8; 32],
    currency: u32,
    window_start: u64,
    window_end: u64,
) -> Option<usize> {
    settled.iter().position(|s| {
        &s.bank_lo == lo
            && &s.bank_hi == hi
            && s.currency == currency
            && s.window_start == window_start
            && s.window_end == window_end
    })
}

pub(crate) fn register_bank(
    banks: &mut Vec<BankEntry>,
    name: Vec<u8>,
    clerk_pubkey: [u8; 32],
) -> Status {
    if name.is_empty() {
        return Status::BadInput;
    }
    match banks.binary_search_by(|e| e.name.cmp(&name)) {
        Ok(i) => banks[i].clerk_pubkey = clerk_pubkey,
        Err(i) => banks.insert(i, BankEntry { name, clerk_pubkey }),
    }
    Status::Ok
}

pub(crate) fn submit_claim(
    banks: &[BankEntry],
    claims: &mut Vec<StoredClaim>,
    settled: &[SettledEntry],
    claim: Vec<u8>,
    voucher_count: u32,
    rk_set_hash: [u8; 32],
) -> Status {
    let Some(parsed) = SettlementClaim::from_bytes(&claim) else {
        return Status::BadInput;
    };
    let claimant = parsed.claimant_clerk.0;
    let peer = parsed.peer_clerk.0;
    // Both parties must be venue-known banks: the claimant so its signature
    // is trusted against a registered key, the peer so the pair can ever
    // settle.
    if !is_registered(banks, &claimant) || !is_registered(banks, &peer) {
        return Status::UnknownBank;
    }
    if parsed.verify_signature().is_err() {
        return Status::SignatureInvalid;
    }
    // Frozen once the pair/currency/window has settled.
    let (lo, hi) = sorted_pair(claimant, peer);
    if settled_index(
        settled,
        &lo,
        &hi,
        parsed.currency,
        parsed.window_start,
        parsed.window_end,
    )
    .is_some()
    {
        return Status::AlreadySettled;
    }
    let entry = StoredClaim {
        claimant,
        peer,
        currency: parsed.currency,
        window_start: parsed.window_start,
        window_end: parsed.window_end,
        version: CLAIM_VERSION_V1,
        claim_bytes: claim,
        voucher_count,
        rk_set_hash,
    };
    // Latest-signed wins for an unsettled window.
    match find_claim(
        claims,
        &claimant,
        &peer,
        parsed.currency,
        parsed.window_start,
        parsed.window_end,
    ) {
        Some(i) => claims[i] = entry,
        None => claims.push(entry),
    }
    Status::Ok
}

pub(crate) fn settle_window(
    banks: &[BankEntry],
    claims: &[StoredClaim],
    settled: &mut Vec<SettledEntry>,
    bank_a: Vec<u8>,
    bank_b: Vec<u8>,
    currency: u32,
    window_start: u64,
    window_end: u64,
) -> Status {
    let Some(pk_a) = bank_pubkey(banks, &bank_a) else {
        return Status::UnknownBank;
    };
    let Some(pk_b) = bank_pubkey(banks, &bank_b) else {
        return Status::UnknownBank;
    };
    let (lo, hi) = sorted_pair(pk_a, pk_b);
    if settled_index(settled, &lo, &hi, currency, window_start, window_end).is_some() {
        // Idempotent: an already-settled window stays settled.
        return Status::AlreadySettled;
    }
    let Some(ia) = find_claim(claims, &pk_a, &pk_b, currency, window_start, window_end) else {
        return Status::ClaimMissing;
    };
    let Some(ib) = find_claim(claims, &pk_b, &pk_a, currency, window_start, window_end) else {
        return Status::ClaimMissing;
    };
    let Some(claim_a) = SettlementClaim::from_bytes(&claims[ia].claim_bytes) else {
        return Status::BadInput;
    };
    let Some(claim_b) = SettlementClaim::from_bytes(&claims[ib].claim_bytes) else {
        return Status::BadInput;
    };
    match reconcile(&claim_a, &claim_b) {
        Ok(()) => {
            settled.push(SettledEntry {
                bank_lo: lo,
                bank_hi: hi,
                currency,
                window_start,
                window_end,
                outcome: Status::Ok as u8,
            });
            Status::Ok
        }
        Err(e) => map_settlement_error(e),
    }
}

pub(crate) fn settlement_status(
    banks: &[BankEntry],
    settled: &[SettledEntry],
    bank_a: &[u8],
    bank_b: &[u8],
    currency: u32,
    window_start: u64,
    window_end: u64,
) -> u8 {
    let (Some(pk_a), Some(pk_b)) = (bank_pubkey(banks, bank_a), bank_pubkey(banks, bank_b)) else {
        return 255;
    };
    let (lo, hi) = sorted_pair(pk_a, pk_b);
    settled_index(settled, &lo, &hi, currency, window_start, window_end)
        .map(|i| settled[i].outcome)
        .unwrap_or(255)
}

pub(crate) fn claim_diagnostics(
    claims: &[StoredClaim],
    claimant: [u8; 32],
    peer: [u8; 32],
    currency: u32,
    window_start: u64,
    window_end: u64,
) -> ClaimReport {
    match find_claim(claims, &claimant, &peer, currency, window_start, window_end) {
        Some(i) => ClaimReport {
            present: true,
            voucher_count: claims[i].voucher_count,
            rk_set_hash: claims[i].rk_set_hash.to_vec(),
        },
        None => ClaimReport {
            present: false,
            voucher_count: 0,
            rk_set_hash: Vec::new(),
        },
    }
}

fn map_settlement_error(e: SettlementError) -> Status {
    match e {
        SettlementError::BadSignature => Status::SignatureInvalid,
        SettlementError::PeerMismatch => Status::PeerMismatch,
        SettlementError::CurrencyMismatch => Status::CurrencyMismatch,
        SettlementError::WindowMismatch => Status::WindowMismatch,
        SettlementError::NetFlowDoesNotCancel => Status::NetFlowMismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipher_clerk::crypto::{Amount, Blinding, Keypair};
    use cipher_clerk::settlement::SettlementClaim;

    /// ISO-4217 USD — the fixed demo currency constant.
    const USD: u32 = 840;
    const WINDOW: (u64, u64) = (1_000, 2_000);

    fn bank_entry(name: &str, pk: [u8; 32]) -> BankEntry {
        BankEntry {
            name: name.as_bytes().to_vec(),
            clerk_pubkey: pk,
        }
    }

    fn commit(value: u64, blind: u8) -> Amount {
        Amount::commit(value, &Blinding([blind; 32]))
    }

    /// A signed claim for `me` against `peer` with net flow `my_net`, and its
    /// negated-flow mirror signed by `peer` — the pair whose commitments
    /// cancel to identity.
    fn canceling_pair(
        me: &Keypair,
        peer: &Keypair,
        window: (u64, u64),
        my_net: Amount,
    ) -> (Vec<u8>, Vec<u8>) {
        let peer_net = Amount::from_point(&-my_net.to_point().unwrap());
        let mine = SettlementClaim::sign(
            me.public, peer.public, USD, window.0, window.1, my_net, &me.secret,
        );
        let theirs = SettlementClaim::sign(
            peer.public, me.public, USD, window.0, window.1, peer_net, &peer.secret,
        );
        (mine.to_bytes(), theirs.to_bytes())
    }

    #[test]
    fn register_bank_inserts_sorted_and_refreshes() {
        let mut banks = Vec::new();
        assert_eq!(
            register_bank(&mut banks, b"bank-b".to_vec(), [2u8; 32]),
            Status::Ok
        );
        assert_eq!(
            register_bank(&mut banks, b"bank-a".to_vec(), [1u8; 32]),
            Status::Ok
        );
        // Sorted by name.
        assert_eq!(banks[0].name, b"bank-a");
        assert_eq!(banks[1].name, b"bank-b");
        // Re-register overwrites the pubkey (key rotation).
        assert_eq!(
            register_bank(&mut banks, b"bank-a".to_vec(), [9u8; 32]),
            Status::Ok
        );
        assert_eq!(banks.len(), 2);
        assert_eq!(banks[0].clerk_pubkey, [9u8; 32]);
        // An empty name is refused; the pubkey length is now a compile-time
        // invariant of the typed `[u8; 32]` arg.
        assert_eq!(
            register_bank(&mut banks, Vec::new(), [1u8; 32]),
            Status::BadInput
        );
    }

    #[test]
    fn submit_claim_requires_both_banks_registered() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let (claim_a, _) = canceling_pair(&a, &b, WINDOW, commit(10, 7));

        // Neither registered.
        let mut claims = Vec::new();
        assert_eq!(
            submit_claim(&[], &mut claims, &[], claim_a.clone(), 3, [1u8; 32]),
            Status::UnknownBank
        );
        // Only claimant registered — the peer is still unknown.
        let banks = vec![bank_entry("bank-a", a.public.0)];
        assert_eq!(
            submit_claim(&banks, &mut claims, &[], claim_a, 3, [1u8; 32]),
            Status::UnknownBank
        );
        assert!(claims.is_empty());
    }

    #[test]
    fn submit_claim_rejects_tampered_signature() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let (mut claim_a, _) = canceling_pair(&a, &b, WINDOW, commit(10, 7));
        // Flip a byte inside the trailing 64-byte signature.
        let n = claim_a.len();
        claim_a[n - 1] ^= 0x01;

        let banks = vec![bank_entry("bank-a", a.public.0), bank_entry("bank-b", b.public.0)];
        let mut claims = Vec::new();
        assert_eq!(
            submit_claim(&banks, &mut claims, &[], claim_a, 3, [1u8; 32]),
            Status::SignatureInvalid
        );
        assert!(claims.is_empty());
    }

    #[test]
    fn submit_claim_stores_and_replaces_until_settled() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let banks = vec![bank_entry("bank-a", a.public.0), bank_entry("bank-b", b.public.0)];
        let mut claims = Vec::new();

        let (claim1, _) = canceling_pair(&a, &b, WINDOW, commit(10, 7));
        assert_eq!(
            submit_claim(&banks, &mut claims, &[], claim1, 3, [0xAAu8; 32]),
            Status::Ok
        );
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].voucher_count, 3);

        // Resubmit for the same directional window — latest-signed wins, no
        // new row, diagnostics refreshed.
        let (claim2, _) = canceling_pair(&a, &b, WINDOW, commit(12, 5));
        assert_eq!(
            submit_claim(&banks, &mut claims, &[], claim2, 4, [0xBBu8; 32]),
            Status::Ok
        );
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].voucher_count, 4);
        assert_eq!(claims[0].rk_set_hash, [0xBBu8; 32]);
        assert_eq!(claims[0].version, CLAIM_VERSION_V1);
    }

    #[test]
    fn settle_window_reconciles_canceling_pair_and_freezes() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let banks = vec![bank_entry("bank-a", a.public.0), bank_entry("bank-b", b.public.0)];
        let mut claims = Vec::new();
        let mut settled = Vec::new();

        let (claim_ab, claim_ba) = canceling_pair(&a, &b, WINDOW, commit(10, 7));
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, claim_ab, 2, [1u8; 32]),
            Status::Ok
        );
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, claim_ba, 1, [2u8; 32]),
            Status::Ok
        );

        assert_eq!(
            settle_window(
                &banks,
                &claims,
                &mut settled,
                b"bank-a".to_vec(),
                b"bank-b".to_vec(),
                USD,
                WINDOW.0,
                WINDOW.1,
            ),
            Status::Ok
        );
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].outcome, Status::Ok as u8);
        // Direction-independent lookup.
        assert_eq!(
            settlement_status(&banks, &settled, b"bank-b", b"bank-a", USD, WINDOW.0, WINDOW.1),
            Status::Ok as u8
        );

        // Frozen: a further submit for this window is refused.
        let (again, _) = canceling_pair(&a, &b, WINDOW, commit(99, 3));
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, again, 9, [3u8; 32]),
            Status::AlreadySettled
        );
        // And re-settling is an idempotent no-op.
        assert_eq!(
            settle_window(
                &banks,
                &claims,
                &mut settled,
                b"bank-a".to_vec(),
                b"bank-b".to_vec(),
                USD,
                WINDOW.0,
                WINDOW.1,
            ),
            Status::AlreadySettled
        );
        assert_eq!(settled.len(), 1);
    }

    #[test]
    fn settle_window_reports_mismatch_without_freezing() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let banks = vec![bank_entry("bank-a", a.public.0), bank_entry("bank-b", b.public.0)];
        let mut claims = Vec::new();
        let mut settled = Vec::new();

        // Both sides claim the SAME positive net flow → commitments don't
        // cancel.
        let net = commit(10, 7);
        let claim_ab =
            SettlementClaim::sign(a.public, b.public, USD, WINDOW.0, WINDOW.1, net, &a.secret)
                .to_bytes();
        let claim_ba =
            SettlementClaim::sign(b.public, a.public, USD, WINDOW.0, WINDOW.1, net, &b.secret)
                .to_bytes();
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, claim_ab, 1, [0u8; 32]),
            Status::Ok
        );
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, claim_ba, 1, [0u8; 32]),
            Status::Ok
        );
        assert_eq!(
            settle_window(
                &banks,
                &claims,
                &mut settled,
                b"bank-a".to_vec(),
                b"bank-b".to_vec(),
                USD,
                WINDOW.0,
                WINDOW.1,
            ),
            Status::NetFlowMismatch
        );
        // NOT frozen — the window stays open for a corrected resubmission.
        assert!(settled.is_empty());
        let (fixed, _) = canceling_pair(&a, &b, WINDOW, commit(5, 4));
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, fixed, 1, [0u8; 32]),
            Status::Ok
        );
    }

    #[test]
    fn settle_window_missing_and_unknown() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let banks = vec![bank_entry("bank-a", a.public.0), bank_entry("bank-b", b.public.0)];
        let mut claims = Vec::new();
        let mut settled = Vec::new();

        // Only one directional claim present.
        let (claim_ab, _) = canceling_pair(&a, &b, WINDOW, commit(10, 7));
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, claim_ab, 1, [0u8; 32]),
            Status::Ok
        );
        assert_eq!(
            settle_window(
                &banks,
                &claims,
                &mut settled,
                b"bank-a".to_vec(),
                b"bank-b".to_vec(),
                USD,
                WINDOW.0,
                WINDOW.1,
            ),
            Status::ClaimMissing
        );
        // Unknown bank name.
        assert_eq!(
            settle_window(
                &banks,
                &claims,
                &mut settled,
                b"bank-a".to_vec(),
                b"bank-z".to_vec(),
                USD,
                WINDOW.0,
                WINDOW.1,
            ),
            Status::UnknownBank
        );
    }

    #[test]
    fn claim_diagnostics_reports_stored_or_absent() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let banks = vec![bank_entry("bank-a", a.public.0), bank_entry("bank-b", b.public.0)];
        let mut claims = Vec::new();

        let (claim_ab, _) = canceling_pair(&a, &b, WINDOW, commit(10, 7));
        assert_eq!(
            submit_claim(&banks, &mut claims, &[], claim_ab, 5, [0xEEu8; 32]),
            Status::Ok
        );

        let present = claim_diagnostics(
            &claims,
            a.public.0,
            b.public.0,
            USD,
            WINDOW.0,
            WINDOW.1,
        );
        assert!(present.present);
        assert_eq!(present.voucher_count, 5);
        assert_eq!(present.rk_set_hash, [0xEEu8; 32].to_vec());

        // A directional key with no stored claim.
        let absent = claim_diagnostics(
            &claims,
            b.public.0,
            a.public.0,
            USD,
            WINDOW.0,
            WINDOW.1,
        );
        assert!(!absent.present);
    }

    /// Native end-to-end of the settlement SIGN convention — the
    /// `issuer ⊕ receiver → reconcile` composition the ELF federation e2es
    /// exercise, pinned here without a PVM rebuild. Each bank's claimed net
    /// flow is `issuer_term ⊕ receiver_term`, where the receiver term is the
    /// negated sum of the commits it accepted. This test rebuilds that shape
    /// with local point math (it does not call
    /// `clerk_bridge::window::accumulate_neg` — that fold's own sign is
    /// pinned by the bridge crate's `worked_example_two_bank_net_flows_cancel`);
    /// what it pins is that the composition, signed this way, cancels through
    /// `settle_window`/`reconcile`. A sign regression in the composition or the
    /// store/reconcile drive makes the commitments miss cancellation, so
    /// `settle_window` returns `NetFlowMismatch` and this fails under plain
    /// `cargo test`.
    #[test]
    fn settle_window_accepts_composed_issuer_minus_receiver_terms() {
        let a = Keypair::generate();
        let b = Keypair::generate();
        let banks = vec![bank_entry("bank-a", a.public.0), bank_entry("bank-b", b.public.0)];
        let mut claims = Vec::new();
        let mut settled = Vec::new();

        // Two cross-clerk vouchers this window: A→B for 10, B→A for 3, with
        // DISTINCT blindings as real vouchers carry. Both banks derive their
        // terms from the SAME two commits, so the blindings cancel by
        // construction.
        let c_ab = commit(10, 7); // A issued to B
        let c_ba = commit(3, 9); // B issued to A

        // receiver = ⊖Σ(accepted commits); issuer = Σ(issued commits);
        // net = issuer ⊕ receiver — the accumulate_neg-shaped derivation.
        let neg = |x: &Amount| Amount::from_point(&-x.to_point().unwrap());
        let add = |x: &Amount, y: &Amount| {
            Amount::from_point(&(x.to_point().unwrap() + y.to_point().unwrap()))
        };
        let net_a = add(&c_ab, &neg(&c_ba)); // issued c_ab, received c_ba
        let net_b = add(&c_ba, &neg(&c_ab)); // issued c_ba, received c_ab

        let claim_a =
            SettlementClaim::sign(a.public, b.public, USD, WINDOW.0, WINDOW.1, net_a, &a.secret)
                .to_bytes();
        let claim_b =
            SettlementClaim::sign(b.public, a.public, USD, WINDOW.0, WINDOW.1, net_b, &b.secret)
                .to_bytes();
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, claim_a, 2, [1u8; 32]),
            Status::Ok
        );
        assert_eq!(
            submit_claim(&banks, &mut claims, &settled, claim_b, 2, [2u8; 32]),
            Status::Ok
        );
        assert_eq!(
            settle_window(
                &banks,
                &claims,
                &mut settled,
                b"bank-a".to_vec(),
                b"bank-b".to_vec(),
                USD,
                WINDOW.0,
                WINDOW.1,
            ),
            Status::Ok,
            "composed issuer ⊕ receiver net flows must cancel and settle",
        );
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].outcome, Status::Ok as u8);
    }
}
