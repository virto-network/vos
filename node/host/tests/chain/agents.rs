//! The space's agents and what the run asks of them: `balance`'s balances
//! and `window`'s pair rows written, each read at a window's cut
//! (`at_least_at_cut`, `settle_at_cut`), and the reader's two rootless
//! statements (`attest_plain`: `stamped`, venue-bound, and `ordered`).
//!
//! Every value the run writes is high in entropy, so a carrier holding one
//! is found: the accounts and their balances past 2^40, the pairs' peers
//! and totals, the salts and the reader's secret.

use std::time::Duration;

use cipher_clerk::codec;
use cipher_clerk::conventions::PseudoAccount;
use cipher_clerk::ids::JournalId;
use cipher_clerk::kernel::Value;
use cipher_clerk::types::{Account, Layer};
use vos_checker::programs::{actor, method};
use vos_tree::{Blake2b, Hasher};
use vos_wire::Encode;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, MethodId, RequestId, Session};
use vos_wire::peer::NodeNumber;
use vos_wire::result::{Attest, Outcome, Step};
use vos_wire::vos_anchor::VenueId;

use crate::common::{ALICE, Cluster};
use crate::support::{READER, agent_with, call, reader_agent, results};

pub const BALANCE: InstanceId = InstanceId(3);
pub const WINDOW: InstanceId = InstanceId(4);
const REPLICAS: [NodeNumber; 3] = [1, 2, 3];
/// The window actor's pair: its currency, and the journal its aggregate
/// rows are kept in.
const CURRENCY: u32 = 840;
const AGGREGATE: JournalId = JournalId([0; 16]);
const OPERATOR: [u8; 32] = [0x0c; 32];

/// 64 bits of `seed` mixed: the run's values.
pub fn mixed(seed: u64) -> u64 {
    let mut x = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// `N` bytes mixed from `seed`.
pub fn bytes<const N: usize>(seed: u64) -> [u8; N] {
    let mut out = [0; N];
    for (at, chunk) in out.chunks_mut(8).enumerate() {
        let word = mixed(seed.wrapping_mul(1_000).wrapping_add(at as u64)).to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
    out
}

/// The space's agents: the representative, `balance`, `window` and the
/// reader, each on the three nodes.
pub struct Agents {
    pub representative: AgentId,
    pub balance: AgentId,
    pub window: AgentId,
    pub reader: AgentId,
}

/// A read asked: its agent, its workflow, the window it reads, and the
/// length of its kernel's arguments, which its witness holds before the
/// rows served.
#[derive(Clone, Copy, Debug)]
pub struct Asked {
    pub what: &'static str,
    pub agent: AgentId,
    pub read: RequestId,
    pub window: u64,
    pub arguments: usize,
}

/// A session at `agent` opened now, by its leader's clock: one a window, so
/// none is stale by the time it is first used.
pub fn session(cluster: &Cluster, agent: AgentId, nonce: u64) -> Session {
    let t0 = cluster.clock(cluster.leader(agent));
    Session {
        key: [1; 32],
        name: bytes(nonce ^ t0),
        t0,
    }
}

fn request(
    session: Session,
    sequence: u64,
    instance: InstanceId,
    method: MethodId,
    arguments: Vec<u8>,
) -> Request {
    Request {
        session,
        sequence,
        caller: ALICE,
        instance,
        method,
        arguments,
    }
}

/// `balance`'s accounts: sixteen, each its balance.
fn balances() -> Vec<([u8; 32], u64)> {
    (0..16u64)
        .map(|n| (bytes(0xba1a_0000 + n), mixed(0xba1a_1000 + n) | 1 << 40))
        .collect()
}

/// A pair's state as its commitment opens: the salt, the four totals, the
/// sequence number.
#[derive(Clone, Copy)]
struct Carried {
    salt: [u8; 16],
    totals: [u64; 4],
    seq: u64,
}

impl Carried {
    fn encode(&self) -> Vec<u8> {
        let [out_dr, out_cr, in_dr, in_cr] = self.totals;
        ((self.salt, (out_dr, out_cr)), ((in_dr, in_cr), self.seq)).encode()
    }

    /// `window`'s commitment to it for `peer`.
    fn commitment(&self, peer: &[u8; 32]) -> [u8; 32] {
        let [out_dr, out_cr, in_dr, in_cr] = self.totals;
        Blake2b.hash(
            b"vos/test/window/pair",
            &[
                peer,
                &CURRENCY.to_le_bytes(),
                &self.salt,
                &out_dr.to_le_bytes(),
                &out_cr.to_le_bytes(),
                &in_dr.to_le_bytes(),
                &in_cr.to_le_bytes(),
                &self.seq.to_le_bytes(),
            ],
        )
    }
}

/// The pair the run settles: its peer.
fn peer() -> [u8; 32] {
    bytes(0x9ee4)
}

/// The totals the pair's rows hold, and what the carried state held:
/// each below the rows'.
const ROWS: [u64; 4] = [
    0x0012_3456_789a,
    0x0098_7654_3210,
    0x0055_aa55_aa55,
    0x0000_1234_5678,
];
const CARRIED: [u64; 4] = [
    0x0001_2345_6789,
    0x0009_8765_4321,
    0x0005_5aa5_5aa5,
    0x0000_0123_4567,
];

/// `window`'s accounts: the pair's two aggregate rows, at the totals
/// [`ROWS`], and the aggregate rows of six other peers.
fn window_accounts() -> Vec<Vec<u8>> {
    let at = |pseudo: PseudoAccount, dr: u64, cr: u64| {
        let mut account: Account<Value> = pseudo.open(OPERATOR);
        let settled = &mut account.balances[Layer::Settled.as_index()];
        settled.dr = Value(dr);
        settled.cr = Value(cr);
        account.timestamp = 1_000;
        codec::to_bytes(&account)
    };
    let [out_dr, out_cr, in_dr, in_cr] = ROWS;
    let mut accounts = vec![
        at(
            PseudoAccount::outgoing_to(AGGREGATE, peer(), CURRENCY),
            out_dr,
            out_cr,
        ),
        at(
            PseudoAccount::incoming_from(AGGREGATE, peer(), CURRENCY),
            in_dr,
            in_cr,
        ),
    ];
    for n in 0..6 {
        let other: [u8; 32] = bytes(0x07e4_0000 + n);
        accounts.push(at(
            PseudoAccount::outgoing_to(AGGREGATE, other, CURRENCY),
            mixed(n) >> 24,
            mixed(n + 100) >> 24,
        ));
    }
    accounts
}

impl Agents {
    /// The representative and the three agents on the three nodes, the
    /// balances and the pairs' rows written.
    pub fn install(cluster: &Cluster) -> Self {
        let agents = Self {
            representative: cluster.representative(&REPLICAS),
            balance: agent_with(cluster, &REPLICAS, BALANCE, "balance"),
            window: agent_with(cluster, &REPLICAS, WINDOW, "window"),
            reader: reader_agent(cluster, &REPLICAS),
        };
        let set = request(
            session(cluster, agents.balance, 1),
            1,
            BALANCE,
            method(&actor("balance"), "set"),
            balances().encode(),
        );
        assert!(matches!(
            call(cluster, agents.balance, set),
            Outcome::Done(_)
        ));
        let put = request(
            session(cluster, agents.window, 1),
            1,
            WINDOW,
            method(&actor("window"), "put"),
            window_accounts().encode(),
        );
        assert!(matches!(
            call(cluster, agents.window, put),
            Outcome::Done(_)
        ));
        agents
    }

    /// `balance`'s read in window `window`, asked now: whether an account,
    /// by a fresh commitment, held at least a threshold at the cut.
    pub fn ask_balance(&self, cluster: &Cluster, window: u64) -> Asked {
        let (account, balance) = balances()[window as usize % 16];
        let salt: [u8; 16] = bytes(0x5a17_0000 + window);
        let commitment = Blake2b.hash(b"vos/test/balance/account", &[&salt, &account]);
        let threshold = balance - (mixed(window) % (balance / 2));
        let arguments = [
            commitment.encode(),
            threshold.encode(),
            salt.encode(),
            account.encode(),
        ]
        .concat();
        self.ask(
            cluster,
            "balance",
            self.balance,
            window,
            request(
                session(cluster, self.balance, window + 100),
                1,
                BALANCE,
                method(&actor("balance"), "at_least_at_cut"),
                arguments,
            ),
        )
    }

    /// `window`'s settlement in window `window`, asked now: the pair's net
    /// since its carried state, at the cut.
    pub fn ask_window(&self, cluster: &Cluster, window: u64) -> Asked {
        let carried = Carried {
            salt: bytes(0xca44_0000 + window),
            totals: CARRIED,
            seq: 6 + window,
        };
        let salt: [u8; 16] = bytes(0x5a17_1000 + window);
        let peer = peer();
        let arguments = [
            (peer, CURRENCY, carried.commitment(&peer)).encode(),
            carried.encode(),
            salt.encode(),
        ]
        .concat();
        self.ask(
            cluster,
            "window",
            self.window,
            window,
            request(
                session(cluster, self.window, window + 200),
                1,
                WINDOW,
                method(&actor("window"), "settle_at_cut"),
                arguments,
            ),
        )
    }

    fn ask(
        &self,
        cluster: &Cluster,
        what: &'static str,
        agent: AgentId,
        window: u64,
        start: Request,
    ) -> Asked {
        let arguments = start.arguments.len();
        let Outcome::Started(workflow) = call(cluster, agent, start) else {
            panic!("{what}'s read did not start");
        };
        Asked {
            what,
            agent,
            read: RequestId {
                workflow,
                awaits: 0,
            },
            window,
            arguments,
        }
    }

    /// The reader's two rootless statements, `stamped` bound to `venue`
    /// and `ordered` of no venue: their records, as its log holds them.
    pub fn plain(&self, cluster: &Cluster, venue: VenueId) -> (Attest, Attest) {
        let secret = mixed(0x5ec7) | 1 << 48;
        let arguments = [
            (venue.0, mixed(0x404e), secret).encode(),
            (7u8, 0x1234u16, mixed(0xc) as u32).encode(),
        ]
        .concat();
        let plain = request(
            session(cluster, self.reader, 300),
            1,
            READER,
            method(&actor("reader"), "attest_plain"),
            arguments,
        );
        assert!(matches!(
            call(cluster, self.reader, plain),
            Outcome::Done(_)
        ));
        let node = cluster.node(cluster.leader(self.reader));
        let attests: Vec<Attest> = results(node, self.reader, 0)
            .into_iter()
            .flat_map(|(_, result)| result.steps)
            .filter_map(|step| match step {
                Step::Ran(run) => Some(run.attests),
                _ => None,
            })
            .flatten()
            .filter(|attest| attest.roots.is_empty())
            .collect();
        let [stamped, ordered] = &attests[..] else {
            panic!("two rootless statements: {}", attests.len());
        };
        (stamped.clone(), ordered.clone())
    }
}

/// How long a read takes at most to end once asked: its window's rest, the
/// close's delay and a margin.
pub const READ_ENDS: Duration = Duration::from_secs(300);
