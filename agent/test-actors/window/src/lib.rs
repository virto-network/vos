//! An actor that states settlement windows with a peer space, under a
//! carried commitment. The space keeps, per peer and currency, one
//! aggregate outgoing row (what it sent the peer, credit-normal) and one
//! aggregate incoming row (what it received, debit-normal), whose debit and
//! credit totals only grow. The venue's handler keeps, per pair, a
//! commitment `c` to the four totals the last settlement reached
//! ([`commitment`]); a statement opens it privately, reads the two rows at
//! one window's cut, checks no total fell, and states the net since, the
//! pair's next sequence number and the commitment to the new totals.
//!
//! The kernel's public arguments are the reader's `(agent, instance)`, the
//! peer, the currency and `c_prev`; the totals `c_prev` commits to, its
//! salt and the next commitment's salt are private; its root is the
//! space's root at the cut, and its output `(net, seq, c_new)` names no
//! anchor. The handler orders the cuts: it keeps the window of the
//! pair's last settlement beside `c` and takes a statement only at a later
//! one, so an older cut cannot restate a settled pair.
//!
//! `cipher_clerk::settlement::window` takes two anchors and per-journal
//! rows; this kernel nets the delta itself, as the Clerk's own window will
//! once it takes one cut and a carried state.

#![no_std]

extern crate alloc;

use cipher_clerk::codec;
use cipher_clerk::conventions::{Flow, PseudoAccount};
use cipher_clerk::ids::JournalId;
use cipher_clerk::kernel::Value;
use cipher_clerk::types::{Account, Layer};
use vos_sdk::prelude::*;
use vos_tree::{Blake2b, Hasher};

/// The commitment's domain.
pub const COMMITMENT_DOMAIN: &[u8] = b"vos/test/window/pair";

/// The journal the pair's aggregate rows are kept in: their ids derive from
/// it, the peer and the currency, so each pair has exactly two.
pub const AGGREGATE: JournalId = JournalId([0; 16]);

/// A pair's running totals: the debits and credits of its outgoing and of
/// its incoming row. Each only grows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Totals {
    pub out_dr: u64,
    pub out_cr: u64,
    pub in_dr: u64,
    pub in_cr: u64,
}

impl Totals {
    /// What the space owes the peer net, as these totals stand: its
    /// outgoing row's balance (credits less debits) less its incoming
    /// row's (debits less credits).
    pub fn owed(&self) -> i128 {
        let wide = |value: u64| i128::from(value);
        (wide(self.out_cr) - wide(self.out_dr)) - (wide(self.in_dr) - wide(self.in_cr))
    }

    /// Whether no total is below `earlier`'s.
    pub fn since(&self, earlier: &Totals) -> bool {
        self.out_dr >= earlier.out_dr
            && self.out_cr >= earlier.out_cr
            && self.in_dr >= earlier.in_dr
            && self.in_cr >= earlier.in_cr
    }
}

/// A pair's state at its last settlement, as its commitment opens: the
/// commitment's salt, the totals, and the settlement's sequence number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Carried {
    pub salt: [u8; 16],
    pub totals: Totals,
    pub seq: u64,
}

/// A window's statement: what the space owes the peer since the last
/// settlement, net (negative when it is owed), the settlement's sequence
/// number, and the commitment to the totals it reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Settlement {
    pub net: i128,
    pub seq: u64,
    pub c_new: [u8; 32],
}

/// `BLAKE2b-256(COMMITMENT_DOMAIN ‖ peer ‖ currency ‖ salt ‖ out_dr ‖
/// out_cr ‖ in_dr ‖ in_cr ‖ seq)`, the integers little-endian: the pair's
/// state, bound to the pair, hidden by its salt. A pair's first settlement
/// opens the commitment to `Carried::default()`.
pub fn commitment(peer: &[u8; 32], currency: u32, carried: &Carried) -> [u8; 32] {
    let totals = &carried.totals;
    Blake2b.hash(
        COMMITMENT_DOMAIN,
        &[
            peer,
            &currency.to_le_bytes(),
            &carried.salt,
            &totals.out_dr.to_le_bytes(),
            &totals.out_cr.to_le_bytes(),
            &totals.in_dr.to_le_bytes(),
            &totals.in_cr.to_le_bytes(),
            &carried.seq.to_le_bytes(),
        ],
    )
}

/// The pair's aggregate rows with `peer` in `currency`: its outgoing and
/// its incoming pseudo-account.
pub fn aggregates(peer: &[u8; 32], currency: u32) -> [PseudoAccount; 2] {
    [
        PseudoAccount::outgoing_to(AGGREGATE, *peer, currency),
        PseudoAccount::incoming_from(AGGREGATE, *peer, currency),
    ]
}

#[actor]
pub struct Window {
    /// The space's accounts, cipher-clerk's encoding, by their ids.
    accounts: CommittedMap<[u8; 16], Vec<u8>>,
}

#[messages]
impl Window {
    pub fn new() -> Self {
        Self {
            accounts: CommittedMap::default(),
        }
    }

    /// Put each account, cipher-clerk's encoding, under its id.
    #[msg(gas = 100_000_000)]
    pub async fn put(&mut self, accounts: Vec<Vec<u8>>) -> u32 {
        for bytes in &accounts {
            let account = codec::from_bytes::<Account<Value>>(bytes).expect("an account");
            self.accounts.insert(&account.id.0, bytes);
        }
        accounts.len() as u32
    }

    /// The window with `peer` in `currency` since the settlement `c_prev`
    /// commits to, at the cut of the window it asks in: the pair's two
    /// aggregate rows read.
    #[workflow(gas = 100_000_000)]
    pub async fn settle_at_cut(
        ctx: &mut Workflow<Self>,
        peer: [u8; 32],
        currency: u32,
        c_prev: [u8; 32],
        carried: Carried,
        salt: [u8; 16],
    ) -> Result<Settlement, AttestError> {
        let ids = aggregates(&peer, currency).map(|pseudo| pseudo.id().0);
        ctx.attest_at_cut(window::Settle {
            peer,
            currency,
            c_prev,
            carried,
            salt,
        })
        .reads(|window: &Window| ids.iter().map(|id| window.accounts.read(id)).collect())
        .await
    }

    /// `settle_at_cut`, its read naming the accounts `reads` alone.
    #[workflow(gas = 100_000_000)]
    pub async fn settle_reading(
        ctx: &mut Workflow<Self>,
        peer: [u8; 32],
        currency: u32,
        c_prev: [u8; 32],
        carried: Carried,
        salt: [u8; 16],
        reads: Vec<[u8; 16]>,
    ) -> Result<Settlement, AttestError> {
        ctx.attest_at_cut(window::Settle {
            peer,
            currency,
            c_prev,
            carried,
            salt,
        })
        .reads(|window: &Window| reads.iter().map(|id| window.accounts.read(id)).collect())
        .await
    }

    /// The settlement with `peer` in `currency` since `c_prev`: `carried`
    /// opens it; the pair's two aggregate rows, an absent one at totals of
    /// nothing, give the new totals, none below the carried; the net is
    /// what the space owes at the new totals less what it owed at the
    /// carried; `c_new` commits to the new totals under `salt` at the next
    /// sequence number. A `carried` that does not open `c_prev`, a total
    /// that fell (an older cut than the carried state's), or a row that is
    /// not the pseudo-account its key names trap.
    #[attestable(gas = 50_000_000)]
    pub fn settle(
        &self,
        #[public] peer: [u8; 32],
        #[public] currency: u32,
        #[public] c_prev: [u8; 32],
        carried: Carried,
        salt: [u8; 16],
    ) -> Settlement {
        assert!(
            commitment(&peer, currency, &carried) == c_prev,
            "the carried state opens c_prev"
        );
        let mut totals = Totals::default();
        for pseudo in aggregates(&peer, currency) {
            let Some(bytes) = self.accounts.get(&pseudo.id().0) else {
                continue;
            };
            let account = codec::from_bytes::<Account<Value>>(&bytes).expect("an account");
            assert!(
                PseudoAccount::of(&account) == Some(pseudo),
                "the pseudo-account its key names"
            );
            let settled = &account.balances[Layer::Settled.as_index()];
            match pseudo.flow {
                Flow::Outgoing => (totals.out_dr, totals.out_cr) = (settled.dr.0, settled.cr.0),
                Flow::Incoming => (totals.in_dr, totals.in_cr) = (settled.dr.0, settled.cr.0),
            }
        }
        assert!(totals.since(&carried.totals), "no total fell");
        let seq = carried.seq.checked_add(1).expect("a next sequence number");
        Settlement {
            net: totals.owed() - carried.totals.owed(),
            seq,
            c_new: commitment(&peer, currency, &Carried { salt, totals, seq }),
        }
    }
}
