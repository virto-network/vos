//! The home on three nodes of a founded space (`light-node.md` §3.3): the
//! home's agent holding the credential actor and `Homes`; the keeper
//! (`vos-keeper`) making 200 personal agents, each `Personal` installed and the
//! home's agent granted its role `homes`, and stocking them; each claimed by a
//! member's proof of `Auth("home")`, made as a device makes it, and assigned by
//! `Personal`'s answer across agents; a member joining by the open claim, its
//! work found by the device library, and claiming the agent the keeper tops the
//! pool up with; a double claim refused at `Homes`; the scope "home" proving
//! nothing but a claim; and the keeper's upgrade across the pool in batches,
//! stopping at the batch an install refuses.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_abi::credentials::Digest;
use vos_abi::ids::{AgentId, InstanceId, MethodId};
use vos_abi::result::Outcome;
use vos_abi::{Decode, Encode, SpaceId, WindowClock};
use vos_checker::Nodes;
use vos_checker::programs::{actor_elf, program_elf};
use vos_keeper::{Home, Keeper, KeeperError};
use vos_light::{Call, DeviceError, DeviceProgram, Prover, ProverConfig, Threads, method_id};
use vos_node::client::{self, Client, Operator};
use vos_wire::credentials::{CredentialError, Open, Path};
use vos_wire::homes::{AgentsPage, Counts, HomesError, Standing, Terms};
use vos_wire::ingress::{Credentialed, NodeId, Response};
use vos_wire::personal::{AdminClass, Attestation, Kit, KitEntry, KitKind, NewDevice, Policy};

use crate::harness::{Cluster, NODES, OPERATOR_SEED, done, witness};

const SEED: u64 = 23;
pub(crate) const CREDENTIALS: InstanceId = InstanceId(9);
pub(crate) const HOMES: InstanceId = InstanceId(3);
pub(crate) const PERSONAL: InstanceId = InstanceId(5);
/// The registrar's and the operator's role byte at the home's agent: the
/// keeper's key holds both.
const ROLE: u8 = 1;
pub(crate) const HANDLE: [u8; 32] = [0x48; 32];
const POOL: u32 = 200;
/// The proofs made at once, each on a prover of its own.
const PROVERS: usize = 4;

/// Member `n`'s device secret.
fn secret(n: u32) -> vos_light::DeviceSecret {
    let mut output = [0x5c; 32];
    output[..4].copy_from_slice(&n.to_le_bytes());
    vos_light::derive_secret(&output, &HANDLE)
}

fn member(n: u32) -> Digest {
    vos_light::member(&secret(n)).to_bytes()
}

/// The home: its agent, the keeper's client there, the space and the
/// stock `auth` kernel's program.
pub(crate) struct Founded {
    pub(crate) cluster: Arc<Cluster>,
    pub(crate) agent: AgentId,
    pub(crate) space: SpaceId,
    caller: Mutex<Client>,
    pub(crate) auth: DeviceProgram,
}

impl Founded {
    fn new() -> Self {
        Self::with(Policy::DEFAULT)
    }

    /// The home, its agents configured with `policy` before their claims.
    pub(crate) fn with(policy: Policy) -> Self {
        let cluster = Cluster::founded(SEED, Some(WindowClock::DEFAULT));
        Self::on(Arc::new(cluster), policy)
    }

    fn on(cluster: Arc<Cluster>, policy: Policy) -> Self {
        let credentials = std::fs::read(program_elf("vos-credentials")).unwrap();
        let homes = std::fs::read(program_elf("vos-homes")).unwrap();
        let installs = [
            (CREDENTIALS, &credentials[..], "registrar"),
            (HOMES, &homes[..], "operator"),
        ];
        let (agent, caller) =
            cluster.found_agent(&installs, ROLE, SigningKey::from_bytes(&OPERATOR_SEED));
        let space = cluster.space.id();
        let device = vos_light::release::device(&credentials, "auth").expect("the stock kernel");
        let founded = Self {
            cluster,
            agent,
            space,
            caller: Mutex::new(caller),
            auth: DeviceProgram::from_release(&device).unwrap(),
        };
        founded
            .write::<(), CredentialError>(CREDENTIALS, "found", HANDLE)
            .unwrap();
        founded
            .write::<(), HomesError>(
                HOMES,
                "configure",
                Terms {
                    instance: PERSONAL.0,
                    policy,
                },
            )
            .unwrap();
        founded
    }

    /// The keeper's call of `name`: its reply, or the handler's error.
    #[track_caller]
    pub(crate) fn write<T: Decode, E: Decode + std::fmt::Debug>(
        &self,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> Result<T, E> {
        let answer = self
            .caller
            .lock()
            .unwrap()
            .call(
                self.agent,
                instance,
                MethodId(method_id(name)),
                &arguments.encode(),
            )
            .unwrap();
        done(name, answer)
    }

    pub(crate) fn read<T: Decode>(
        &self,
        instance: InstanceId,
        name: &str,
        arguments: impl Encode,
    ) -> T {
        let not_after = client::time(self.cluster.target(1)).unwrap() + 60_000;
        let answer = self
            .caller
            .lock()
            .unwrap()
            .query(
                self.agent,
                instance,
                MethodId(method_id(name)),
                &arguments.encode(),
                not_after,
            )
            .unwrap();
        match answer {
            Response::Ran {
                outcome: Outcome::Done(bytes),
                ..
            } => T::decode_exact(&bytes).expect("decodes"),
            other => panic!("{name}: {other:?}"),
        }
    }

    /// The keeper, on every node's operator and the keeper's client.
    pub(crate) fn keeper(&self) -> Keeper {
        let key = SigningKey::from_bytes(&OPERATOR_SEED);
        let operators = self
            .cluster
            .space
            .nodes()
            .iter()
            .map(|node| {
                Operator::signing(
                    self.cluster.target(node.number),
                    key.clone(),
                    NodeId(node.key),
                )
            })
            .collect();
        let leader = self.cluster.leader(self.agent).unwrap();
        let caller =
            Client::new(self.cluster.target(leader), key).with_routes(self.cluster.routes());
        let home = Home {
            agent: self.agent,
            homes: HOMES,
            personal: PERSONAL,
        };
        Keeper::new(operators, caller, home, (1..=NODES).collect())
    }

    /// Member `n`'s device, its nullifier in `Homes`' scope.
    fn device(&self, n: u32) -> NewDevice {
        let key = |kind: u8| {
            let mut key = [kind; 32];
            key[..4].copy_from_slice(&n.to_le_bytes());
            key
        };
        NewDevice {
            sync: key(0xd1),
            admin: key(0xd2),
            class: AdminClass::Strong,
            attestation: Attestation {
                hardware: true,
                verified_boot: true,
            },
            nullifier: vos_light::home::nullifier(&secret(n), &self.space.0, self.agent.0, HOMES.0),
            label: vec![1; 24],
        }
    }

    /// The call of `Homes`' `name` with `arguments`, good for a minute.
    fn call(&self, name: &str, arguments: impl Encode, nonce: u32) -> Call {
        let mut bytes = [0x77; 16];
        bytes[..4].copy_from_slice(&nonce.to_le_bytes());
        Call {
            space: self.space.0,
            agent: self.agent.0,
            instance: HOMES.0,
            method: method_id(name),
            arguments: arguments.encode(),
            nonce: bytes,
            expires_ms: client::time(self.cluster.target(1)).unwrap() + 60_000,
        }
    }

    /// Member `n`'s claim of the pooled `agent`, proved on `prover` and
    /// sent to a node: `Homes`' answer.
    fn claim(
        &self,
        prover: &Prover,
        n: u32,
        path: &Path,
        kit: Kit,
        agent: u32,
    ) -> Result<u32, HomesError> {
        let call = self.call("claim", (self.device(n), kit, agent), n);
        let proof = prover
            .prove_home(&secret(n), &witness(path), &call, &self.auth)
            .unwrap();
        let request = Credentialed {
            instance: HOMES,
            method: MethodId(call.method),
            arguments: call.arguments.clone(),
            nonce: call.nonce,
            expires_ms: call.expires_ms,
            format: proof.format,
            claim: proof.claim,
            proof: proof.proof,
        };
        // As a device sends it: to a node, then to the next while the
        // agent's group has no leader there.
        let until = Instant::now() + Duration::from_secs(30);
        let mut at = (n % u32::from(NODES)) as u8 + 1;
        loop {
            match client::credentialed(self.cluster.target(at), self.agent, &request).unwrap() {
                Response::NotLeader { .. } | Response::Busy | Response::Unavailable
                    if Instant::now() < until =>
                {
                    at = at % NODES + 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                answer => return done("claim", answer),
            }
        }
    }
}

fn kit(n: u32) -> Kit {
    let mut signing = [0xe1; 32];
    signing[..4].copy_from_slice(&n.to_le_bytes());
    Kit {
        entries: vec![KitEntry {
            kind: KitKind::Phrase,
            signing,
            sealing: [0xe2; 32],
            sealed_r1: vec![0xe3; 80],
        }],
        r2: [0xe4; 32],
    }
}

/// The keeper makes and stocks a pool of 200; 200 members claim it, each
/// by a proof of `Auth("home")`, and every claim is assigned once its
/// agent answers; a member's second claim is refused; the scope "home"
/// proves no other call; and the keeper's upgrade installs the next
/// `Personal` across the pool in batches, then stops at a refused batch;
/// a top-up whose install fails names the agent it left unfinished, and
/// the keeper finishes and stocks it.
#[test]
fn a_pool_of_200_is_made_by_the_keeper_and_claimed() {
    let home = Founded::new();
    let members: Vec<Digest> = (0..POOL).map(member).collect();
    home.write::<Vec<u32>, CredentialError>(CREDENTIALS, "enroll_many", members.clone())
        .unwrap();
    let keeper = home.keeper();
    let personal = std::fs::read(program_elf("vos-personal")).unwrap();
    let made = Instant::now();
    assert_eq!(keeper.top_up(POOL, &personal, 16).unwrap(), POOL);
    eprintln!(
        "the keeper made and stocked {POOL} agents in {:.1} s",
        made.elapsed().as_secs_f64()
    );
    assert_eq!(keeper.tally().unwrap().pooled, POOL);

    // Each member claims an agent of its own, as devices that each read
    // another pooled agent would.
    let page: AgentsPage = home.read(HOMES, "agents", Option::<u32>::None);
    let pooled: Vec<u32> = page.agents.iter().map(|(agent, _)| *agent).collect();
    assert_eq!(pooled.len(), POOL as usize);
    let paths: Vec<Path> = members
        .iter()
        .map(|member| {
            home.read::<Option<Path>>(CREDENTIALS, "path", *member)
                .unwrap()
        })
        .collect();
    let next = AtomicU32::new(0);
    let claimed = Mutex::new(Vec::new());
    let proving = Instant::now();
    std::thread::scope(|scope| {
        for _ in 0..PROVERS {
            scope.spawn(|| {
                let prover = Prover::new(ProverConfig {
                    threads: Threads::Count(3),
                    ..ProverConfig::default()
                })
                .unwrap();
                loop {
                    let n = next.fetch_add(1, Ordering::Relaxed);
                    if n >= POOL {
                        return;
                    }
                    let agent = home
                        .claim(&prover, n, &paths[n as usize], kit(n), pooled[n as usize])
                        .unwrap();
                    claimed.lock().unwrap().push(agent);
                }
            });
        }
    });
    eprintln!(
        "{POOL} claims proved and taken in {:.1} s, {PROVERS} at once",
        proving.elapsed().as_secs_f64()
    );
    let mut claimed = claimed.into_inner().unwrap();
    claimed.sort();
    claimed.dedup();
    assert_eq!(claimed.len(), POOL as usize, "one agent a claim");
    vos_checker::wait_until("every claim assigned", Duration::from_secs(60), || {
        keeper.tally().unwrap()
            == Counts {
                pooled: 0,
                claimed: 0,
                assigned: POOL,
            }
    });

    // A member joins by the open claim, its work found by the device
    // library, and claims the agent the keeper tops the pool up with.
    home.write::<(), CredentialError>(CREDENTIALS, "open", (8u8, 4u32, 86_400_000u64))
        .unwrap();
    let open: Open = home
        .read::<Option<Open>>(CREDENTIALS, "opening", ())
        .expect("opened");
    let joining = member(POOL);
    let nonce = vos_light::home::work(&HANDLE, &joining, &open.salt, open.difficulty, 4);
    home.write::<u32, CredentialError>(CREDENTIALS, "claim_open", (joining, nonce))
        .unwrap();
    assert_eq!(keeper.top_up(1, &personal, 16).unwrap(), 1);
    let joined: Path = home
        .read::<Option<Path>>(CREDENTIALS, "path", joining)
        .unwrap();
    let prover = Prover::new(ProverConfig {
        threads: Threads::Count(4),
        ..ProverConfig::default()
    })
    .unwrap();
    let next: Option<u32> = home.read(HOMES, "pooled", ());
    let agent = home
        .claim(&prover, POOL, &joined, kit(POOL), next.expect("topped up"))
        .unwrap();
    vos_checker::wait_until(
        "the open member's claim assigned",
        Duration::from_secs(60),
        || home.read::<Option<Standing>>(HOMES, "standing_of", agent) == Some(Standing::Assigned),
    );

    // A member's second claim.
    assert_eq!(
        home.claim(&prover, 0, &paths[0], kit(1_000), agent),
        Err(HomesError::Claimed)
    );
    // The scope "home" proves a claim alone.
    let other = home.call("stock", vec![1u32], 1_001);
    assert_eq!(
        prover
            .prove_home(&secret(1), &witness(&paths[1]), &other, &home.auth)
            .err(),
        Some(DeviceError::Reserved)
    );
    let renew = home.call("renew", claimed[1], 1_002);
    for proved in [
        prover.prove_home(&secret(1), &witness(&paths[1]), &renew, &home.auth),
        prover.prove_auth(&secret(1), &witness(&paths[1]), b"home", &renew, &home.auth),
    ] {
        assert_eq!(proved.err(), Some(DeviceError::Reserved));
    }

    // The next `Personal` over the pool, 16 at a time; then a program that
    // declares no admission, which every agent's install refuses.
    let next_version = std::fs::read(actor_elf("personal-next")).unwrap();
    assert_eq!(
        keeper.upgrade(&next_version, 16).unwrap(),
        POOL as usize + 1
    );
    let counter = std::fs::read(actor_elf("counter")).unwrap();
    match keeper.upgrade(&counter, 16) {
        Err(KeeperError::Refused { agent, .. }) => {
            assert!(claimed[..16].contains(&agent.0), "the first batch's")
        }
        other => panic!("the refused upgrade: {other:?}"),
    }

    // A top-up whose install fails (a program with an auth guard, in an
    // agent with no credential actor) leaves its agent unfinished: named
    // in the error, stocked by none; finished, it is pooled.
    let guarded = std::fs::read(actor_elf("poll")).unwrap();
    let pooled = keeper.tally().unwrap().pooled;
    let unfinished = match keeper.top_up(pooled + 1, &guarded, 1) {
        Err(KeeperError::Unfinished { agents, .. }) => agents,
        other => panic!("the failed top-up: {other:?}"),
    };
    assert_eq!(unfinished.len(), 1);
    assert_eq!(keeper.tally().unwrap().pooled, pooled);
    assert_eq!(
        keeper.finish(&unfinished, &next_version).unwrap(),
        pooled + 1
    );
    assert_eq!(
        home.read::<Option<Standing>>(HOMES, "standing_of", unfinished[0].0),
        Some(Standing::Pooled)
    );
}
