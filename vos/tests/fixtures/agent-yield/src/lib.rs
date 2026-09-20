//! Native lifecycle test fixture: two cooperative yields around Local state
//! changes, protected by a deployment-scoped actor role. Not a system actor.

use vos::prelude::*;
use vos::storage::StorageMap;

#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum ProbeRole {
    Run = 0,
}

impl vos::RoleByte for ProbeRole {
    fn from_byte(byte: u8) -> Option<Self> {
        (byte == 0).then_some(Self::Run)
    }
    fn as_byte(self) -> u8 {
        self as u8
    }
}

const PROBE_ROLES: vos::SpaceRoleMap<ProbeRole> = vos::SpaceRoleMap {
    admin: Some(ProbeRole::Run),
    developer: Some(ProbeRole::Run),
    member: Some(ProbeRole::Run),
    guest: None,
};

#[actor(agent, role = ProbeRole, default_role = ProbeRole::Run, space_role_map = PROBE_ROLES)]
pub struct AgentYieldProbe {
    #[state(local)]
    value: u64,
    #[storage(local, prefix = "s/rows/")]
    rows: StorageMap<u64, u64>,
}

#[messages(agent)]
impl AgentYieldProbe {
    fn new() -> Self {
        Self { value: 0, rows: StorageMap::default() }
    }

    #[msg(local)]
    fn row_set(&mut self, key: u64, value: u64) -> u64 {
        self.rows.insert(&key, &value);
        self.rows.get(&key).unwrap()
    }

    #[msg(local_query)]
    fn row_get(&self, key: u64) -> u64 {
        self.rows.get(&key).unwrap_or(u64::MAX)
    }

    #[msg(local)]
    fn row_rejected(&mut self, key: u64) -> u64 {
        let rejected = vos::storage::with_transaction(|| {
            self.rows.insert(&key, &999);
            let observed = self.rows.get(&key);
            assert_eq!(observed, Some(999));
            Err::<(), ()>(())
        });
        assert!(rejected.is_err());
        self.rows.get(&key).unwrap_or(u64::MAX)
    }

    #[msg(local)]
    async fn row_yield(&mut self, key: u64, ctx: &mut Context<Self>) -> u64 {
        self.rows.insert(&key, &1);
        ctx.yield_now().await;
        let next = self.rows.get(&key).unwrap().saturating_add(1);
        self.rows.insert(&key, &next);
        next
    }

    #[msg(
        local,
        role = ProbeRole::Run,
        actor_role_id = "5151515151515151515151515151515151515151515151515151515151515151"
    )]
    async fn run(&mut self, ctx: &mut Context<Self>) -> u64 {
        self.value = self.value.saturating_add(1);
        ctx.yield_now().await;
        self.value = self.value.saturating_add(10);
        ctx.yield_now().await;
        self.value = self.value.saturating_add(100);
        self.value
    }

    #[msg(local_query)]
    fn value(&self) -> u64 {
        self.value
    }

    /// Large-input probe for the generated Rust dispatch/decode path. Returns
    /// only the decoded length so reply size cannot hide an input-size failure.
    #[msg(
        local_query,
        role = ProbeRole::Run,
        actor_role_id = "5151515151515151515151515151515151515151515151515151515151515151"
    )]
    fn input_len(&self, bytes: Vec<u8>) -> u64 {
        bytes.len() as u64
    }

    #[msg(
        local_query,
        role = ProbeRole::Run,
        actor_role_id = "5151515151515151515151515151515151515151515151515151515151515151"
    )]
    fn blob_len(&self, hash: Vec<u8>, len: u64, ctx: &mut Context<Self>) -> u64 {
        let Ok(hash) = <[u8; 32]>::try_from(hash.as_slice()) else { return u64::MAX - 1 };
        let reference = vos::agent_sdk::BlobRef { hash: vos::agent_sdk::Hash(hash), len };
        match ctx.invocation_blob(&reference) {
            Ok(Some(bytes)) => bytes.len() as u64,
            Ok(None) => u64::MAX,
            Err(_) => u64::MAX - 1,
        }
    }
}
