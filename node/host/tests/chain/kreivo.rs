//! Kreivo, as its spaces pallet's mock models it: a chain at the host's
//! time, its fee pipeline on, a block's wait on every extrinsic, its
//! genesis the pallet's formats and programs and the accounts it funds. The
//! space is registered, its authorities added and it migrates away by the
//! pallet's calls, signed by its controller; its nodes anchor and submit
//! through their `KreivoVenue` clients, each signing as its own account.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use parity_scale_codec::Encode;
use vos_venue::kreivo::calls::{AccountId, BalancesCall, Call, MultiAddress, RuntimeCall};
use vos_venue::kreivo::mock::transport::MockChain;
use vos_venue::kreivo::mock::types::{Active, Handler, ProgramInfo};
use vos_venue::kreivo::mock::{Account, Chain, Constants, Origin, keys};
use vos_venue::kreivo::transport::{Outcome, Sent};
use vos_venue::kreivo::{KreivoVenue, Options, Sender, Transport};
use vos_venue::vos_statement::ProgramId;
use vos_wire::peer::NodeNumber;
use vos_wire::vos_anchor::{SpaceGenesis, SpaceId, VenueId, blake2b_256, space_id};

use crate::venues::Enveloped;

/// Kreivo's genesis hash in the mock: its venue id.
pub const VENUE: VenueId = VenueId([0x6b; 32]);
pub const UNITS: u128 = 1_000_000_000_000;
/// A block's wait: what an extrinsic takes to be included.
const BLOCK: Duration = Duration::from_secs(6);
/// What the founder funds the space's sovereign account with.
pub const FUNDING: u128 = 100 * UNITS;

/// An account of the run's, by its name.
pub fn account(name: &str) -> AccountId {
    blake2b_256(&[b"vos/e2e-chain/account/", name.as_bytes()])
}

/// The space's controller at Kreivo.
pub fn controller() -> AccountId {
    account("controller")
}

/// Node `number`'s account: an authority of the space.
pub fn node_account(number: NodeNumber) -> AccountId {
    account(&format!("node {number}"))
}

pub struct Kreivo {
    pub chain: Arc<MockChain>,
    envelopes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Kreivo {
    /// The chain, accepting format 39 and `programs`, none venue-bound,
    /// from its genesis; the founder and the controller funded.
    pub fn new(programs: &[ProgramId]) -> Self {
        let mut chain = Chain::new(Constants::kreivo(VENUE)).with_fees(true);
        let always = Active {
            from_ms: 0,
            until_ms: None,
        };
        chain.set_storage(keys::formats(vos_node_prover::FORMAT), always.encode());
        for program in programs {
            let info = ProgramInfo {
                handler: Handler::Record,
                venue_bound: false,
                active: always,
            };
            chain.set_storage(keys::programs(&program.0), info.encode());
        }
        for name in ["founder", "controller"] {
            chain.set_account(
                account(name),
                Account {
                    free: 1_000 * UNITS,
                    providers: 1,
                    ..Account::default()
                },
            );
        }
        let clock: Arc<dyn Fn() -> u64 + Send + Sync> = Arc::new(vos_node::wall_clock);
        let chain = MockChain::with_clock(chain, Some(clock));
        chain.set_latency(BLOCK);
        Self {
            chain,
            envelopes: Arc::default(),
        }
    }

    /// A transport signing as `who`, its envelopes kept.
    pub fn transport(&self, who: AccountId) -> Arc<dyn Transport> {
        Arc::new(Enveloped {
            inner: self.chain.transport(Origin::Signed(who)),
            envelopes: Arc::clone(&self.envelopes),
        })
    }

    /// Node `number`'s client of the space `space`, signing as its account,
    /// the space's sovereign paying.
    pub fn client(&self, number: NodeNumber, space: SpaceId) -> KreivoVenue {
        let options = Options {
            refresh: Duration::from_millis(500),
            backoff: Duration::from_millis(100),
            ..Options::default()
        };
        KreivoVenue::over(
            self.transport(node_account(number)),
            &[space],
            space,
            options,
        )
    }

    /// `call` signed by `who`, included: its outcome, which must not fail.
    pub fn call(&self, who: AccountId, call: Vec<u8>) -> Outcome {
        let sender = Sender::new(self.transport(who), Duration::from_millis(100));
        match sender.call(&call) {
            Ok(Sent::Included(outcome)) => {
                assert!(outcome.failure.is_none(), "the call failed: {outcome:?}");
                outcome
            }
            other => panic!("the call was not included: {other:?}"),
        }
    }

    /// The space `genesis` founds, registered from `start_window` by the
    /// controller with a founder's signature, its sovereign account funded
    /// by the founder first; each of `nodes` (number, anchor key) then an
    /// authority, paired with its anchor key.
    pub fn register(
        &self,
        genesis: &SpaceGenesis,
        start_window: u64,
        (founder_key, founder_sig): ([u8; 32], [u8; 64]),
        nodes: &[(NodeNumber, [u8; 32])],
    ) {
        let space = space_id(genesis);
        let sovereign = self.sovereign_of(&space);
        let funding = RuntimeCall::Balances(BalancesCall::TransferKeepAlive {
            dest: MultiAddress::Id(sovereign),
            value: FUNDING,
        });
        self.call(account("founder"), funding.encode());
        let register = Call::Register {
            genesis: genesis.encode(),
            controller: controller(),
            start_window,
            founder_key,
            founder_sig,
        };
        self.call(controller(), register.bytes());
        for (number, key) in nodes {
            let add = Call::AddAuthority {
                space: space.0,
                who: node_account(*number),
                anchor_key: Some(*key),
            };
            self.call(controller(), add.bytes());
        }
    }

    /// The space's migration to `to` from window `from_window`, by its
    /// controller.
    pub fn migrate(&self, space: &SpaceId, to: VenueId, from_window: u64) -> Outcome {
        let migrate = Call::Migrate {
            space: space.0,
            to: to.0,
            from_window,
        };
        self.call(controller(), migrate.bytes())
    }

    /// The space's sovereign account.
    pub fn sovereign_of(&self, space: &SpaceId) -> AccountId {
        self.chain.with(|chain| chain.constants.sovereign(&space.0))
    }

    /// An account's balances.
    pub fn account(&self, who: &AccountId) -> Account {
        self.chain.with(|chain| chain.account(who))
    }

    /// Whether the chain holds window `window`'s anchor of `space`.
    pub fn holds(&self, space: &SpaceId, window: u64) -> bool {
        let key = keys::anchors(&space.0, 0, window);
        self.chain.with(|chain| chain.storage().contains_key(&key))
    }

    /// Every extrinsic signed for the chain, as it was sent.
    pub fn envelopes(&self) -> Vec<Vec<u8>> {
        self.envelopes.lock().unwrap().clone()
    }

    /// The pallet's storage, every key and value: the space, its anchors,
    /// its budget, the statements seen.
    pub fn storage(&self) -> Vec<u8> {
        self.chain.with(|chain| {
            chain
                .storage()
                .iter()
                .flat_map(|(key, value)| [key.clone(), value.clone()].concat())
                .collect()
        })
    }

    /// The calls included, each with its signer.
    pub fn included(&self) -> Vec<(Origin, Vec<u8>)> {
        self.chain.included()
    }
}
