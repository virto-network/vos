//! A test home on the demo's node (`light-node.md` §3.3, E20): a home in
//! the shape of Virto's (its own agent, credential actor and handle, behind
//! an onion and an SSH host key of its own), in the demo's space on its
//! one node rather than a space of its own, its delays, its lease and its
//! open claim's difficulty cut to a phone session's. Its agent holds the credential
//! actor and `Homes`, in front of a pool of personal agents the keeper
//! (`vos-keeper`) makes and stocks; the registrar admits open claims at a
//! low difficulty and serves the gateway's onion as the home's onion set.
//! Two homes on the one node are two homes to a device, each its own agent,
//! credential actor and handle, as moving home needs.

use vos_abi::ids::{AgentId, InstanceId, MethodId, derive_id};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode};
use vos_keeper::{Home as Pool, Keeper};
use vos_node::client::{Client, Operator, Target};
use vos_wire::credentials::{CredentialError, Onion};
use vos_wire::homes::{Counts, HomesError, Terms};
use vos_wire::ingress::Response;
use vos_wire::personal::Policy;

use crate::LocalSpace;

/// The instances a home's agent holds, and `Personal`'s in each pool
/// agent.
pub const HOME_CREDENTIALS: InstanceId = InstanceId(9);
pub const HOMES: InstanceId = InstanceId(3);
pub use vos_wire::personal::PERSONAL;
const MINUTE: u64 = 60_000;

/// A phone session's home policy: a device's own operations (a removal, a
/// kit rotation, a regroup) mature in two minutes and the kit's (a
/// restore, an admin key's replacement by the kit) in five; a paired
/// device is on probation two minutes and seasoned five after, and an
/// admin key another device replaces takes over after the probation (E29),
/// all within the session; the lease a day, past an unattended day of
/// background runs (no device re-proves it).
pub const SESSION: Policy = Policy {
    operation_delay_ms: 2 * MINUTE,
    kit_delay_ms: 5 * MINUTE,
    probation_ms: 2 * MINUTE,
    seasoning_ms: 5 * MINUTE,
    confirm_window_ms: 15 * MINUTE,
    lease_ms: 24 * 60 * MINUTE,
    slot_ttl_ms: 10 * MINUTE,
    ..Policy::DEFAULT
};

/// The open claim's terms: eight leading zero bits of work (a phone finds
/// them in well under a second), 64 claims a day.
pub const DIFFICULTY: u8 = 8;
pub const CLAIMS_A_DAY: u32 = 64;
const DAY_MS: u64 = 86_400_000;

/// A home on the demo's node.
#[derive(Clone, Copy, Debug)]
pub struct Home {
    pub agent: AgentId,
    /// Its credential actor's handle.
    pub handle: [u8; 32],
    /// Its agent's identity, which a query's signature covers.
    pub identity: [u8; 32],
}

impl LocalSpace {
    /// A home founded on this node: its agent with the credential actor
    /// (handle `handle`) and `Homes` configured with `policy`, open claims
    /// admitted at [`DIFFICULTY`], and a pool of `pool` personal agents
    /// made and stocked by the keeper.
    pub fn found_home(&self, handle: [u8; 32], policy: Policy, pool: u32) -> Result<Home, String> {
        let target = Target::socket(self.socket.clone());
        let signed = Operator::signing(&target, self.key.clone(), self.node.id());
        let agent = crate::agent_with(
            &signed,
            &self.key,
            "the home's agent",
            &[
                (
                    HOME_CREDENTIALS,
                    vos_testkit::programs::program_elf("vos-credentials"),
                    "registrar",
                ),
                (
                    HOMES,
                    vos_testkit::programs::program_elf("vos-homes"),
                    "operator",
                ),
            ],
        )?;
        let identity = self
            .client()
            .identity(agent)
            .map_err(|error| format!("the home's identity: {error:?}"))?;
        let home = Home {
            agent,
            handle,
            identity,
        };
        self.at_home::<(), CredentialError>(&home, HOME_CREDENTIALS, "found", handle)?;
        self.at_home::<(), HomesError>(
            &home,
            HOMES,
            "configure",
            Terms {
                instance: PERSONAL.0,
                policy,
            },
        )?;
        self.at_home::<(), CredentialError>(
            &home,
            HOME_CREDENTIALS,
            "open",
            (DIFFICULTY, CLAIMS_A_DAY, DAY_MS),
        )?;
        self.top_up(&home, pool)?;
        Ok(home)
    }

    fn client(&self) -> Client {
        Client::new(&Target::socket(self.socket.clone()), self.key.clone())
    }

    /// The keeper of `home`'s pool, under the operator's key.
    fn keeper(&self, home: &Home) -> Keeper {
        let target = Target::socket(self.socket.clone());
        Keeper::new(
            vec![Operator::signing(&target, self.key.clone(), self.node.id())],
            self.client(),
            Pool {
                agent: home.agent,
                homes: HOMES,
                personal: PERSONAL,
            },
            vec![1],
        )
    }

    /// Make and stock personal agents until `home`'s pool holds `pool`.
    pub fn top_up(&self, home: &Home, pool: u32) -> Result<u32, String> {
        let elf = std::fs::read(vos_testkit::programs::program_elf("vos-personal"))
            .map_err(|error| format!("`Personal`'s ELF: {error}"))?;
        self.keeper(home)
            .top_up(pool, &elf, 4)
            .map_err(|error| error.to_string())
    }

    /// `home`'s pool: its agents pooled, claimed and assigned.
    pub fn tally(&self, home: &Home) -> Result<Counts, String> {
        self.keeper(home).tally().map_err(|error| error.to_string())
    }

    /// The home's onion set at its registrar: the gateway's onions.
    pub fn set_onions(&self, home: &Home, onions: &[Onion]) -> Result<(), String> {
        self.at_home::<(), CredentialError>(home, HOME_CREDENTIALS, "set_onions", onions.to_vec())
    }

    /// The operator's call of `name` at `home`'s `instance`: its reply, or
    /// the handler's error.
    fn at_home<T: Decode, E: Decode + std::fmt::Debug>(
        &self,
        home: &Home,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, String> {
        let answer = self.operator.lock().expect("operator poisoned").call(
            home.agent,
            instance,
            MethodId(derive_id("vos/method/", name)),
            &arguments.encode(),
        );
        match answer {
            Ok(Response::Ran {
                outcome: Outcome::Done(reply),
                ..
            }) => {
                T::decode_exact(&reply).ok_or_else(|| format!("{name}: the reply does not decode"))
            }
            Ok(Response::Ran {
                outcome: Outcome::Failed { detail, .. },
                ..
            }) => Err(format!("{name}: {:?}", E::decode_exact(&detail))),
            other => Err(format!("{name}: {other:?}")),
        }
    }

    /// `home`'s code, as the app scans or pastes it (s4's `Codes.home`):
    /// `VOSHOME1:` and upper-case hex of the space ‖ the handle ‖ the
    /// agent ‖ its identity ‖ `Homes`' instance ‖ the credential actor's ‖
    /// the onions' count ‖ each onion's key and SSH host key, the three ids
    /// as big-endian u32s.
    pub fn home_code(&self, home: &Home, onions: &[Onion]) -> String {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.space.0);
        bytes.extend_from_slice(&home.handle);
        bytes.extend_from_slice(&home.agent.0.to_be_bytes());
        bytes.extend_from_slice(&home.identity);
        bytes.extend_from_slice(&HOMES.0.to_be_bytes());
        bytes.extend_from_slice(&HOME_CREDENTIALS.0.to_be_bytes());
        bytes.push(onions.len() as u8);
        for onion in onions {
            bytes.extend_from_slice(&onion.key);
            bytes.extend_from_slice(&onion.ssh_host_key);
        }
        format!("VOSHOME1:{}", hex::encode_upper(bytes))
    }
}
