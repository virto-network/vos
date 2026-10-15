//! Workflows as the checker starts them: the rounds actor's tours, each
//! round asking the next agent's rounds to tally its amount and awaiting
//! the total, tallying it here, sending the next agent's other rounds it to
//! tally, a message, sleeping and computing; and their owners' signed
//! reads.
//!
//! A tour's every effect is a tally of an amount no other round has: how
//! often each applied is read at the end, exactly, a failed tour's amounts
//! once or not at all and every other once. Only one client's tours touch
//! those rounds, one tour at a time, so a tour's result is known before it
//! starts while none has failed: the totals after each of its amounts, and
//! its computations' digest.

use ed25519_dalek::SigningKey;
use vos_node::client::signed_workflow_read;
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::ingress::{Consistency, Install};
use vos_wire::schema::Schema;

/// The rounds instance at each agent whose tours start there, and which
/// tallies their amounts.
pub const ROUNDS: InstanceId = InstanceId(4);
/// The rounds instance the previous agent's tours ask to tally.
pub const ASKED: InstanceId = InstanceId(5);
/// The rounds instance the previous agent's tours' messages tally at.
pub const TOLD: InstanceId = InstanceId(6);
/// A tour's rounds.
pub const ROUNDS_A_TOUR: u64 = 3;

/// The rounds actor's methods a checker calls.
#[derive(Clone, Copy, Debug)]
pub struct TourMethods {
    pub tour: MethodId,
    pub rewrite: MethodId,
    pub total: MethodId,
    pub tallies: MethodId,
}

impl TourMethods {
    /// The rounds actor's methods, by their names in its `schema`.
    pub fn of(schema: &Schema) -> Self {
        let method = |name: &str| {
            schema
                .method_id(name)
                .unwrap_or_else(|| panic!("no method {name}"))
        };
        Self {
            tour: method("tour"),
            rewrite: method("rewrite"),
            total: method("total"),
            tallies: method("tallies"),
        }
    }
}

/// The rounds actor's package and program, its workflows in it, and its
/// methods.
pub struct Rounds {
    /// Its package, the ELF its crate built.
    pub elf: Vec<u8>,
    pub program: Vec<u8>,
    pub methods: TourMethods,
}

impl Rounds {
    pub fn load() -> Self {
        let program = crate::programs::actor("rounds");
        Self {
            elf: crate::programs::package("rounds"),
            methods: TourMethods::of(&crate::programs::schema(&program)),
            program,
        }
    }

    /// An operator's install of it as `instance`.
    pub fn install(&self, instance: InstanceId) -> Install {
        crate::calls::install_of(instance, &self.elf)
    }
}

/// A tour's arguments.
#[derive(Clone, Debug)]
pub struct Tour {
    /// The agent its rounds ask and tell.
    pub other: AgentId,
    pub amounts: Vec<u64>,
    /// How long each round sleeps, in milliseconds of batch time.
    pub nap: u64,
    pub words: u32,
    pub passes: u32,
}

impl Tour {
    /// A tour asking and telling `other` `amounts`, each round sleeping
    /// `nap` milliseconds of batch time, with little to compute.
    pub fn light(other: AgentId, amounts: Vec<u64>, nap: u64) -> Self {
        Self {
            other,
            amounts,
            nap,
            words: 64,
            passes: 4,
        }
    }

    /// Its arguments as a request carries them: each field's encoding in
    /// turn.
    pub fn arguments(&self) -> Vec<u8> {
        let mut bytes = (self.other.0, ASKED.0, TOLD.0).encode();
        self.amounts.encode_to(&mut bytes);
        (self.nap, self.words, self.passes).encode_to(&mut bytes);
        bytes
    }

    /// What the tour ends with when the asked rounds' total stood at
    /// `base`: the totals after each amount, and its computations' digest.
    pub fn result(&self, base: u64) -> Vec<u8> {
        let totals: Vec<u64> = self
            .amounts
            .iter()
            .scan(base, |total, amount| {
                *total += amount;
                Some(*total)
            })
            .collect();
        let digest = self.amounts.iter().fold(0, |digest, amount| {
            digest ^ churn(*amount, self.words, self.passes)
        });
        (totals, digest).encode()
    }

    /// What its amounts add up to.
    pub fn sum(&self) -> u64 {
        self.amounts.iter().sum()
    }
}

/// The rounds actor's `churn`, on the host: `passes` passes over `words`
/// pseudo-random words drawn from `seed`, each word mixed with the next.
/// Their digest.
pub fn churn(seed: u64, words: u32, passes: u32) -> u64 {
    let mut data = vec![0u64; words.max(1) as usize];
    let mut state = seed | 1;
    for value in data.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *value = state;
    }
    let len = data.len();
    for pass in 0..passes {
        for index in 0..len {
            let next = data[(index + 1) % len];
            data[index] =
                data[index].rotate_left(pass % 63 + 1) ^ next.wrapping_mul(0x2545_f491_4f6c_dd1d);
        }
    }
    data.iter()
        .fold(0, |digest, value| digest.rotate_left(7) ^ value)
}

/// A read of `workflow` at the agent whose identity is `identity`, signed
/// by `key`, good until `not_after`, waiting up to `wait_ms` for it to end.
pub fn signed_read(
    identity: &[u8; 32],
    key: &SigningKey,
    not_after: u64,
    consistency: Consistency,
    workflow: WorkflowId,
    wait_ms: u64,
) -> Vec<u8> {
    signed_workflow_read(identity, key, not_after, consistency, workflow, wait_ms).encode()
}

/// The tour request `request` of a touring client starts, asking and
/// telling `other`: three rounds of amounts no other request uses, each
/// sleeping a few milliseconds, then computing for a few of its steps'
/// shares.
pub fn tour(other: AgentId, request: u64) -> Tour {
    Tour {
        other,
        amounts: (1..=ROUNDS_A_TOUR)
            .map(|round| request * 10 + round)
            .collect(),
        nap: 5,
        words: 128,
        passes: 400,
    }
}
