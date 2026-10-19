//! An actor that states settlement windows with a peer space, under a
//! carried commitment: the space's pseudo-account rows with the peer in a
//! currency are cumulative, so what it owes the peer since its last
//! settlement is how much more its `outgoing_to(peer)` rows grew than its
//! `incoming_from(peer)` rows since then. The venue's handler keeps, per
//! pair and currency, a commitment `c` to the cumulative sums the last
//! settlement reached ([`commitment`]); a statement opens it privately,
//! reads the current rows at one window's cut, and states the net since,
//! the pair's next sequence number and the commitment to the new sums.
//!
//! The kernel's public arguments are the reader's `(agent, instance)`, the
//! peer, the currency and `c_prev`; the sums `c_prev` commits to, its salt
//! and the next commitment's salt are private; its root is the space's
//! root at the cut, and its output `(net, seq, c_new)` names no anchor.
//!
//! `cipher_clerk::settlement::window` takes two anchors and reads at both;
//! this kernel nets the delta itself, as the Clerk's own window will once it
//! takes one cut and a carried state.

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

/// A pair's cumulative sums at its last settlement, as its commitment
/// opens: the commitment's salt, the sums of its outgoing and its incoming
/// rows' settled nets, and the settlement's sequence number.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Carried {
    pub salt: [u8; 16],
    pub sent: i128,
    pub received: i128,
    pub seq: u64,
}

/// A window's statement: what the space owes the peer since the last
/// settlement, net (negative when it is owed), the settlement's sequence
/// number, and the commitment to the sums it reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Settlement {
    pub net: i128,
    pub seq: u64,
    pub c_new: [u8; 32],
}

/// `BLAKE2b-256(COMMITMENT_DOMAIN ‖ peer ‖ currency ‖ salt ‖ sent ‖
/// received ‖ seq)`, the integers little-endian: the pair's state, bound to
/// the pair, hidden by its salt. A pair's first settlement opens the
/// commitment to `Carried::default()`.
pub fn commitment(peer: &[u8; 32], currency: u32, carried: &Carried) -> [u8; 32] {
    Blake2b.hash(
        COMMITMENT_DOMAIN,
        &[
            peer,
            &currency.to_le_bytes(),
            &carried.salt,
            &carried.sent.to_le_bytes(),
            &carried.received.to_le_bytes(),
            &carried.seq.to_le_bytes(),
        ],
    )
}

/// The pseudo-accounts `journals` keep with `peer` in `currency`: each
/// journal's outgoing and incoming account.
pub fn pseudo_accounts(
    journals: &[[u8; 16]],
    peer: &[u8; 32],
    currency: u32,
) -> impl Iterator<Item = PseudoAccount> {
    journals.iter().flat_map(move |journal| {
        let journal = JournalId(*journal);
        [
            PseudoAccount::outgoing_to(journal, *peer, currency),
            PseudoAccount::incoming_from(journal, *peer, currency),
        ]
    })
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
    /// commits to, at the cut of the window it asks in: both pseudo-accounts
    /// of each of `journals` read.
    #[workflow(gas = 100_000_000)]
    #[allow(clippy::too_many_arguments)]
    pub async fn settle_at_cut(
        ctx: &mut Workflow<Self>,
        peer: [u8; 32],
        currency: u32,
        c_prev: [u8; 32],
        carried: Carried,
        salt: [u8; 16],
        journals: Vec<[u8; 16]>,
    ) -> Result<Settlement, AttestError> {
        let ids: Vec<[u8; 16]> = pseudo_accounts(&journals, &peer, currency)
            .map(|pseudo| pseudo.id().0)
            .collect();
        ctx.attest_at_cut(window::Settle {
            peer,
            currency,
            c_prev,
            carried,
            salt,
            journals,
        })
        .reads(|window: &Window| ids.iter().map(|id| window.accounts.read(id)).collect())
        .await
    }

    /// `settle_at_cut`, its read naming the accounts `reads` alone.
    #[workflow(gas = 100_000_000)]
    #[allow(clippy::too_many_arguments)]
    pub async fn settle_reading(
        ctx: &mut Workflow<Self>,
        peer: [u8; 32],
        currency: u32,
        c_prev: [u8; 32],
        carried: Carried,
        salt: [u8; 16],
        journals: Vec<[u8; 16]>,
        reads: Vec<[u8; 16]>,
    ) -> Result<Settlement, AttestError> {
        ctx.attest_at_cut(window::Settle {
            peer,
            currency,
            c_prev,
            carried,
            salt,
            journals,
        })
        .reads(|window: &Window| reads.iter().map(|id| window.accounts.read(id)).collect())
        .await
    }

    /// The settlement with `peer` in `currency` since `c_prev`: `carried`
    /// opens it, and each of `journals`, strictly increasing, is read for
    /// its two pseudo-accounts, an absent one counting nothing. Its rows'
    /// settled nets summed are the new cumulative sums; the net is the
    /// outgoing sum's growth less the incoming's; `c_new` commits to the
    /// new sums under `salt` at the next sequence number. A `carried` that
    /// does not open `c_prev`, journals out of order, or a row that is not
    /// the pseudo-account its key names trap.
    #[attestable(gas = 50_000_000)]
    #[allow(clippy::too_many_arguments)]
    pub fn settle(
        &self,
        #[public] peer: [u8; 32],
        #[public] currency: u32,
        #[public] c_prev: [u8; 32],
        carried: Carried,
        salt: [u8; 16],
        journals: Vec<[u8; 16]>,
    ) -> Settlement {
        assert!(
            commitment(&peer, currency, &carried) == c_prev,
            "the carried state opens c_prev"
        );
        assert!(
            journals.windows(2).all(|pair| pair[0] < pair[1]),
            "journals strictly increasing"
        );
        let (mut sent, mut received) = (0i128, 0i128);
        for pseudo in pseudo_accounts(&journals, &peer, currency) {
            let Some(bytes) = self.accounts.get(&pseudo.id().0) else {
                continue;
            };
            let account = codec::from_bytes::<Account<Value>>(&bytes).expect("an account");
            assert!(
                PseudoAccount::of(&account) == Some(pseudo),
                "the pseudo-account its key names"
            );
            let net = account.net(Layer::Settled);
            match pseudo.flow {
                Flow::Outgoing => sent += net,
                Flow::Incoming => received += net,
            }
        }
        let seq = carried.seq.checked_add(1).expect("a next sequence number");
        Settlement {
            net: (sent - carried.sent) - (received - carried.received),
            seq,
            c_new: commitment(
                &peer,
                currency,
                &Carried {
                    salt,
                    sent,
                    received,
                    seq,
                },
            ),
        }
    }
}
