//! The credential circuits on the [`Context`] (`docs/design/proving.md` §8):
//! auth, owner, and membership and payment together, each a fixed wiring
//! whatever its witness, so its preprocessed root is its program.
//!
//! **The hash** is `C(l, r)`, a `p2` row's first eight output words of the
//! permutation of `l ‖ r`; a tag's block `T(name)` is a row's constants
//! ([`tagged`]), so a circuit's tags are its program's. A digest travels
//! as two wires of four words.
//!
//! - **Auth:** `m = C(T(member), s)`, the leaf `C(T(leaf), m)`, 32 node rows
//!   up the path, one bit a level constrained to 0 or 1, the last row's
//!   output the public `map_root`; `C(T(nf), s)`, then the nullifier
//!   `C(that, scope)`, its output the public `nullifier`, `scope` absorbed
//!   as a wire pair, so the circuit hashes it. 36 permutations.
//! - **Owner:** `C(T(owner), s)`, its output the public `owner`. One
//!   permutation.
//! - **Membership and payment:** auth's rows and owner's from one `s`, 37
//!   permutations; measured, not admitted.
//!
//! `binding` is a public word read by no row: the transcript and the
//! public sum bind it. Neither `scope` nor `binding` is computed from its
//! BLAKE2b preimage here: ingress computes both.

use stwo::core::fields::m31::BaseField;
use stwo::core::fields::qm31::SecureField;
use vos_pvm_recair_air::credential::{CredentialKind, DIGEST_WORDS, layout};
use vos_pvm_recair_air::p2::P2Mode;
use vos_wire::credentials::{DEPTH, P, Tag};

use crate::circuit::WiringError;
use crate::context::{Context, Finalized, Message, Mismatch, P2Handle, P2Row, Var};
use crate::gadgets::{node, tagged};
use crate::value::{Value, embed};

/// A digest's eight words, each below `p`.
pub type Words = [u32; DIGEST_WORDS];

/// Each component's rows: the masking's floor under format 44, `4h`.
pub const ROWS: [usize; 2] = [1 << 11, 1 << 11];

/// The tags' blocks a circuit's rows hold: `T(member)`, `T(owner)`,
/// `T(leaf)` and `T(nf)` (`vos_wire::credentials::Tag`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tags {
    pub member: Words,
    pub owner: Words,
    pub leaf: Words,
    pub nf: Words,
}

impl Tags {
    /// The statements' tags.
    pub const PINNED: Tags = Tags {
        member: Tag::Member.block(),
        owner: Tag::Owner.block(),
        leaf: Tag::Leaf.block(),
        nf: Tag::Nf.block(),
    };
}

/// How a circuit is built: under the pinned tags with the slot's bits, or
/// as a forger builds it (other tags, or one level's bit another value),
/// for the forgery gates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forge {
    pub tags: Tags,
    /// A level whose bit is this value, not the slot's.
    pub bit: Option<(usize, u32)>,
}

impl Forge {
    /// The honest build.
    pub const NONE: Forge = Forge {
        tags: Tags::PINNED,
        bit: None,
    };
}

/// An auth statement's witness: the secret, the member's slot and the 32
/// siblings from the leaf up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthWitness {
    pub secret: Words,
    pub slot: u32,
    pub siblings: [Words; DEPTH],
}

/// An auth statement's public digests, after its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthPublic {
    pub map_root: Words,
    pub scope: Words,
    pub nullifier: Words,
    pub binding: Words,
}

/// An owner statement's public digests, after its kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnerPublic {
    pub owner: Words,
    pub binding: Words,
}

/// A credential statement: its public digests and its witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Statement {
    Auth(AuthPublic, AuthWitness),
    Owner(OwnerPublic, Words),
    /// Membership and payment from one secret: auth's statement and the
    /// owner digest, its public words `map_root`, `scope`, `nullifier`,
    /// `owner` and `binding`, no kind.
    Joint(AuthPublic, Words, AuthWitness),
}

impl Statement {
    /// The kind it states, `None` for the joint circuit.
    pub fn kind(&self) -> Option<CredentialKind> {
        match self {
            Statement::Auth(..) => Some(CredentialKind::Auth),
            Statement::Owner(..) => Some(CredentialKind::Owner),
            Statement::Joint(..) => None,
        }
    }

    /// Whether every word of it, public and private, is below `p`.
    pub fn is_canonical(&self) -> bool {
        let below = |words: &Words| words.iter().all(|&word| word < P);
        let auth = |public: &AuthPublic, witness: &AuthWitness| {
            [
                public.map_root,
                public.scope,
                public.nullifier,
                public.binding,
                witness.secret,
            ]
            .iter()
            .chain(&witness.siblings)
            .all(below)
        };
        match self {
            Statement::Auth(public, witness) => auth(public, witness),
            Statement::Owner(public, secret) => {
                [public.owner, public.binding, *secret].iter().all(below)
            }
            Statement::Joint(public, owner, witness) => auth(public, witness) && below(owner),
        }
    }

    /// Its public words, in the circuit's output order.
    pub fn words(&self) -> Vec<u32> {
        let digests: Vec<&Words> = match self {
            Statement::Auth(public, _) => {
                vec![
                    &public.map_root,
                    &public.scope,
                    &public.nullifier,
                    &public.binding,
                ]
            }
            Statement::Owner(public, _) => vec![&public.owner, &public.binding],
            Statement::Joint(public, owner, _) => vec![
                &public.map_root,
                &public.scope,
                &public.nullifier,
                owner,
                &public.binding,
            ],
        };
        self.kind()
            .map(|kind| u32::from(kind as u8))
            .into_iter()
            .chain(digests.into_iter().flatten().copied())
            .collect()
    }
}

/// A digest's two wires' values.
fn pair<V: Value>(words: &Words) -> [V; 2] {
    [0, 1].map(|w| {
        V::from_qm31(SecureField::from_m31_array(core::array::from_fn(|j| {
            BaseField::from_u32_unchecked(words[4 * w + j])
        })))
    })
}

fn block(words: &Words) -> [BaseField; 8] {
    words.map(BaseField::from_u32_unchecked)
}

/// The lanes of a digest's two wires, in its words' order.
fn lanes(digest: [Var; 2]) -> impl Iterator<Item = (Var, usize)> {
    digest
        .into_iter()
        .flat_map(|wire| (0..4).map(move |lane| (wire, lane)))
}

/// Auth's rows over the secret `s`: the path to the stated root and the
/// nullifier. Returns the root's, the scope's and the nullifier's wires.
fn auth_rows<V: Value>(
    context: &mut Context<V>,
    forge: &Forge,
    s: [Var; 2],
    public: &AuthPublic,
    witness: &AuthWitness,
) -> [[Var; 2]; 3] {
    let tags = &forge.tags;
    context.piece("member");
    let member = tagged(context, block(&tags.member), s, None);
    context.piece("path");
    let leaf = tagged(context, block(&tags.leaf), member.digest, None);
    let root = context.guess_pair(pair(&public.map_root));
    let mut below: P2Handle<V> = leaf;
    for (level, sibling) in witness.siblings.iter().enumerate() {
        let bit = match forge.bit {
            Some((forged, value)) if forged == level => value,
            _ => (witness.slot >> level) & 1,
        };
        let bit = context.guess(V::from_qm31(embed(BaseField::from(bit))));
        let bit = context.assert_bit(bit);
        let sibling = pair::<V>(sibling).map(Message::Free);
        let out = (level == DEPTH - 1).then_some(root);
        below = node(context, &below, sibling, bit, out);
    }
    context.piece("nullifier");
    let keyed = tagged(context, block(&tags.nf), s, None);
    let scope = context.guess_pair(pair(&public.scope));
    let nullifier = context.guess_pair(pair(&public.nullifier));
    context.p2(P2Row {
        prev: Some(&keyed),
        m: scope.map(Message::Wire),
        act: [BaseField::from(1); 8],
        out: Some(nullifier),
        ..P2Row::new(P2Mode::ChannelFirst)
    });
    [root, scope, nullifier]
}

/// `statement`'s circuit as `forge` builds it, and its witness: its rows,
/// its outputs set, and the mismatches its values leave, none for a witness
/// that satisfies it (the context lenient). A circuit's wiring does not
/// depend on its values.
pub(crate) fn build<V: Value>(statement: &Statement, forge: &Forge) -> (Context<V>, Vec<Mismatch>) {
    let tags = &forge.tags;
    let words = statement.words().len();
    let mut context = Context::<V>::with_layout(layout(words)).lenient();
    let secret = match statement {
        Statement::Auth(_, witness) | Statement::Joint(_, _, witness) => &witness.secret,
        Statement::Owner(_, secret) => secret,
    };
    context.piece("secret");
    let s = context.guess_pair(pair(secret));
    let mut outputs: Vec<(Var, usize)> = Vec::with_capacity(words);
    match statement.kind() {
        Some(CredentialKind::Auth) => outputs.push((context.zero(), 0)),
        Some(CredentialKind::Owner) => outputs.push((context.one(), 0)),
        None => {}
    }
    let auth = match statement {
        Statement::Auth(public, witness) | Statement::Joint(public, _, witness) => {
            Some((auth_rows(&mut context, forge, s, public, witness), public))
        }
        Statement::Owner(..) => None,
    };
    let owner = match statement {
        Statement::Owner(public, _) => Some(public.owner),
        Statement::Joint(_, owner, _) => Some(*owner),
        Statement::Auth(..) => None,
    }
    .map(|owner| {
        context.piece("owner");
        let owner = context.guess_pair(pair(&owner));
        tagged(&mut context, block(&tags.owner), s, Some(owner));
        owner
    });
    let binding = match statement {
        Statement::Auth(public, _) | Statement::Joint(public, ..) => public.binding,
        Statement::Owner(public, _) => public.binding,
    };
    context.piece("outputs");
    let binding = context.guess_pair(pair(&binding));
    if let Some(([root, scope, nullifier], _)) = auth {
        outputs.extend(lanes(root).chain(lanes(scope)).chain(lanes(nullifier)));
    }
    if let Some(owner) = owner {
        outputs.extend(lanes(owner));
    }
    outputs.extend(lanes(binding));
    context.set_output_lanes(&outputs);
    let mismatches = context.mismatches().to_vec();
    (context, mismatches)
}

/// `statement`'s circuit as `forge` builds it, finalized at [`ROWS`]
/// without `h8`, and the mismatches its witness leaves.
pub(crate) fn finalize<V: Value>(
    statement: &Statement,
    forge: &Forge,
) -> Result<(Finalized<V>, Vec<Mismatch>), WiringError> {
    let (context, mismatches) = build::<V>(statement, forge);
    Ok((context.finalize_without_h8(ROWS)?, mismatches))
}

/// A statement of each shape with every value zero: what the wiring alone
/// is built from.
pub(crate) fn blank(statement: Option<CredentialKind>) -> Statement {
    let zero = [0; DIGEST_WORDS];
    let public = AuthPublic {
        map_root: zero,
        scope: zero,
        nullifier: zero,
        binding: zero,
    };
    let witness = AuthWitness {
        secret: zero,
        slot: 0,
        siblings: [zero; DEPTH],
    };
    match statement {
        Some(CredentialKind::Auth) => Statement::Auth(public, witness),
        Some(CredentialKind::Owner) => Statement::Owner(
            OwnerPublic {
                owner: zero,
                binding: zero,
            },
            zero,
        ),
        None => Statement::Joint(public, zero, witness),
    }
}
