//! Statements over a reference tree, built from `vos_wire::credentials`
//! alone: the member's leaf at its slot among other members, its path, a
//! scope, the nullifier and the owner digest of its secret.

use std::collections::BTreeMap;

use vos_pvm_recair::credential::{AuthPublic, AuthWitness, OwnerPublic, Statement, Words};
use vos_wire::credentials::{DEPTH, EMPTY, P, Tag, compress, leaf};

use crate::common::Rng;

/// A digest of random words below `p`.
pub fn digest(rng: &mut Rng) -> Words {
    core::array::from_fn(|_| (rng.next_u64() % u64::from(P)) as u32)
}

/// `member(s)`.
pub fn member(secret: &Words) -> Words {
    compress(&Tag::Member.block(), secret)
}

/// `owner(s)`.
pub fn owner(secret: &Words) -> Words {
    compress(&Tag::Owner.block(), secret)
}

/// The nullifier of `secret` in `scope`.
pub fn nullifier(secret: &Words, scope: &Words) -> Words {
    compress(&compress(&Tag::Nf.block(), secret), scope)
}

/// A sparse depth-32 tree of leaves by slot: its root and paths, every
/// level rebuilt from the leaves, empty subtrees `EMPTY`'s.
pub struct Tree {
    levels: Vec<BTreeMap<u32, Words>>,
}

impl Tree {
    pub fn new(leaves: &[(u32, Words)]) -> Self {
        let mut levels = vec![leaves.iter().copied().collect::<BTreeMap<u32, Words>>()];
        for level in 0..DEPTH {
            let below = &levels[level];
            let mut above = BTreeMap::new();
            for &index in below.keys() {
                let parent = index >> 1;
                let at = |i: u32| below.get(&i).copied().unwrap_or(EMPTY[level]);
                above.insert(parent, compress(&at(parent << 1), &at((parent << 1) | 1)));
            }
            levels.push(above);
        }
        Self { levels }
    }

    pub fn root(&self) -> Words {
        self.levels[DEPTH].get(&0).copied().unwrap_or(EMPTY[DEPTH])
    }

    /// The siblings of `slot`'s leaf, from level 0 up.
    pub fn siblings(&self, slot: u32) -> [Words; DEPTH] {
        core::array::from_fn(|level| {
            let index = (slot >> level) ^ 1;
            self.levels[level]
                .get(&index)
                .copied()
                .unwrap_or(EMPTY[level])
        })
    }
}

/// A member's secret and a tree holding its leaf at each of `slots`, among
/// `others` random members.
pub struct Enrolled {
    pub secret: Words,
    pub tree: Tree,
}

pub fn enrolled(rng: &mut Rng, slots: &[u32], others: usize) -> Enrolled {
    let secret = digest(rng);
    let mut leaves: Vec<(u32, Words)> = (0..others)
        .map(|_| (rng.next_u64() as u32, leaf(&digest(rng))))
        .filter(|(slot, _)| !slots.contains(slot))
        .collect();
    leaves.extend(slots.iter().map(|&slot| (slot, leaf(&member(&secret)))));
    Enrolled {
        secret,
        tree: Tree::new(&leaves),
    }
}

/// An auth statement of `enrolled`'s member at `slot`, in a random scope,
/// with a random binding.
pub fn auth_at(rng: &mut Rng, enrolled: &Enrolled, slot: u32) -> Statement {
    let scope = digest(rng);
    let binding = digest(rng);
    auth_in(enrolled, slot, scope, binding)
}

/// An auth statement of `enrolled`'s member at `slot` in `scope`, bound to
/// `binding`.
pub fn auth_in(enrolled: &Enrolled, slot: u32, scope: Words, binding: Words) -> Statement {
    let secret = enrolled.secret;
    Statement::Auth(
        AuthPublic {
            map_root: enrolled.tree.root(),
            scope,
            nullifier: nullifier(&secret, &scope),
            binding,
        },
        AuthWitness {
            secret,
            slot,
            siblings: enrolled.tree.siblings(slot),
        },
    )
}

/// An auth statement: a member at a random slot of a tree of a few members.
pub fn auth(seed: u64) -> Statement {
    let mut rng = Rng::new(seed);
    let slot = rng.next_u64() as u32;
    let enrolled = enrolled(&mut rng, &[slot], 5);
    auth_at(&mut rng, &enrolled, slot)
}

/// An owner statement of a random secret.
pub fn owner_statement(seed: u64) -> Statement {
    let mut rng = Rng::new(seed);
    let secret = digest(&mut rng);
    Statement::Owner(
        OwnerPublic {
            owner: owner(&secret),
            binding: digest(&mut rng),
        },
        secret,
    )
}

/// A membership-and-payment statement: auth's and its secret's owner digest.
pub fn joint(seed: u64) -> Statement {
    let Statement::Auth(public, witness) = auth(seed) else {
        unreachable!("an auth statement")
    };
    Statement::Joint(public, owner(&witness.secret), witness)
}
