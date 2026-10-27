//! The credential actor's tree and ring of roots, as its rows hold them
//! (`identity-and-authority.md` §6, `proving.md` §8): the hash, the tags,
//! the depth-32 positional sparse Merkle tree, the paths it serves and the
//! freshness rule ingress and apply judge a root by.
//!
//! **The hash** is Poseidon2-M31's compression `C(l, r)`, the `0x402`
//! precompile ([`crate::abi::precompile::POSEIDON2`]): the first eight
//! words of the width-16 permutation of `l ‖ r`. A digest is eight M31
//! words, its bytes the words as little-endian `u32`s; a word at or above p
//! is no digest.
//!
//! **The tree:** slot `i` (a `u32`) holds `leaf(member) = C(T(leaf),
//! member)`, or the empty leaf `E_0`, eight zero words; node `i` at level
//! `l` is `C(child 2i, child 2i + 1)` of level `l − 1`; the empty subtree at
//! level `l` is `E_l = C(E_{l−1}, E_{l−1})` ([`EMPTY`]). A path is the 32
//! siblings from level 0 up; bit `l` of the slot is 1 when the level-`l`
//! node is a right child.

use alloc::vec::Vec;

use scale::{Decode, DecodeError, Encode};

use crate::SpaceId;
use crate::ids::{AgentId, InstanceId, MethodId};

/// A digest's bytes: eight M31 words as little-endian `u32`s.
pub type Digest = [u8; 32];

/// A digest's eight M31 words, each below p.
pub type Words = [u32; 8];

/// The Mersenne-31 modulus, `2^31 − 1`.
pub const P: u32 = vos_pvm_precompiles::poseidon2::P;

/// The tree's depth: a slot is a `u32`.
pub const DEPTH: usize = 32;

/// The most roots the ring keeps: it bounds storage, never freshness.
pub const RING: usize = 64;

/// The most members one `enroll_many` takes.
pub const ENROLL_MANY: usize = 256;

/// The role every write but `claim` is under.
pub const REGISTRAR: &str = "registrar";

/// The actor's tables, by name: each tagged
/// `derive_id("vos/table/", name)`, plain rows.
pub mod tables {
    /// A `member` digest → its slot, a `u32`.
    pub const SLOTS: &str = "slots";
    /// `(level, index)`, one byte then four big-endian bytes → a digest,
    /// kept only when not the empty subtree's; level 0 holds the leaves.
    pub const NODES: &str = "nodes";
    /// Freed slots, keyed by their four big-endian bytes, in key order.
    pub const FREE: &str = "free";
    /// A `member` digest → its invitation's expiry, in milliseconds of
    /// batch time.
    pub const INVITES: &str = "invites";
    /// One row, under [`RING_KEY`]: the [`Ring`](super::Ring).
    pub const RING: &str = "ring";
    /// The ring's row's key, one byte.
    pub const RING_KEY: u8 = 0;
}

/// The tags' names (`proving.md` §8): `T(name)` is the block
/// `[t, 0, 0, 0, 0, 0, 0, 0]`, `t` from `BLAKE2b-256("vos/p2/" ‖ name)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum Tag {
    #[codec(index = 0)]
    Member = 0,
    #[codec(index = 1)]
    Owner = 1,
    #[codec(index = 2)]
    Leaf = 2,
    #[codec(index = 3)]
    Nf = 3,
    #[codec(index = 4)]
    Scope = 4,
    #[codec(index = 5)]
    Binding = 5,
}

impl Tag {
    pub const ALL: [Tag; 6] = [
        Tag::Member,
        Tag::Owner,
        Tag::Leaf,
        Tag::Nf,
        Tag::Scope,
        Tag::Binding,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Tag::Member => "member",
            Tag::Owner => "owner",
            Tag::Leaf => "leaf",
            Tag::Nf => "nf",
            Tag::Scope => "scope",
            Tag::Binding => "binding",
        }
    }

    /// `t`, [`tag_word`] of the name, pinned.
    pub const fn word(self) -> u32 {
        match self {
            Tag::Member => 0x7ccc_dc5c,
            Tag::Owner => 0x0784_6887,
            Tag::Leaf => 0x5ed0_2b0c,
            Tag::Nf => 0x4f1c_f1e3,
            Tag::Scope => 0x26eb_19bd,
            Tag::Binding => 0x3657_e11e,
        }
    }

    /// `T(name)`.
    pub const fn block(self) -> Words {
        [self.word(), 0, 0, 0, 0, 0, 0, 0]
    }
}

/// `t` of a tag's name: `u32_le(BLAKE2b-256("vos/p2/" ‖ name)[0..4]) &
/// 0x7fff_ffff`, reduced mod p.
pub fn tag_word(name: &str) -> u32 {
    let hash = vos_pvm_precompiles::blake2b_hash::<32>(b"vos/p2/", &[name.as_bytes()]);
    reduce(u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]))
}

/// `value & 0x7fff_ffff` reduced mod p: `2^31 − 1` becomes 0.
const fn reduce(value: u32) -> u32 {
    let value = value & P;
    if value == P { 0 } else { value }
}

/// `W(d)`: 32 bytes as eight words, word `i` `u32_le(d[4i..4i+4]) &
/// 0x7fff_ffff` reduced mod p. 248 bits.
pub fn reduced(bytes: &[u8; 32]) -> Words {
    core::array::from_fn(|i| {
        reduce(u32::from_le_bytes(
            bytes[4 * i..4 * i + 4].try_into().unwrap(),
        ))
    })
}

/// A digest's words, or `None` when one is at or above p.
pub fn words(digest: &Digest) -> Option<Words> {
    let words =
        core::array::from_fn(|i| u32::from_le_bytes(digest[4 * i..4 * i + 4].try_into().unwrap()));
    words.iter().all(|&word| word < P).then_some(words)
}

/// The digest of `words`, each below p.
pub fn digest(words: &Words) -> Digest {
    let mut digest = [0u8; 32];
    for (bytes, word) in digest.chunks_exact_mut(4).zip(words) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    digest
}

/// `C(left, right)`: one `0x402` call, or its software fallback on JAM.
pub fn compress(left: &Words, right: &Words) -> Words {
    vos_pvm_precompiles::poseidon2_compress(left, right)
}

/// `leaf(m) = C(T(leaf), m)`.
pub fn leaf(member: &Words) -> Words {
    compress(&Tag::Leaf.block(), member)
}

/// The empty subtrees: `E_0` eight zero words, `E_l = C(E_{l−1}, E_{l−1})`;
/// `E_32` is the empty tree's root.
pub const EMPTY: [Words; DEPTH + 1] = [
    [0, 0, 0, 0, 0, 0, 0, 0],
    [
        0x7603_b10e,
        0x58fe_3309,
        0x5439_45a9,
        0x2f4c_48cd,
        0x76b4_5f8f,
        0x5691_d997,
        0x7f83_35f1,
        0x06e3_7263,
    ],
    [
        0x25c5_3394,
        0x0b7b_7b9d,
        0x0576_bf12,
        0x5376_c8be,
        0x665e_ada9,
        0x6dea_114a,
        0x6fc2_9292,
        0x6f53_c66f,
    ],
    [
        0x5e87_c2cf,
        0x2c7f_1078,
        0x12dd_4d4c,
        0x19ec_4a07,
        0x0268_ba10,
        0x4c9d_92b9,
        0x4b50_6fdd,
        0x197d_7dc3,
    ],
    [
        0x30c5_3025,
        0x2f11_139e,
        0x3bd1_d5e4,
        0x1759_67a0,
        0x5a0f_6924,
        0x4821_d14a,
        0x2ced_c23d,
        0x67d7_d648,
    ],
    [
        0x2f5b_e55a,
        0x5ab3_cbd5,
        0x21ef_d0eb,
        0x424b_5ea0,
        0x3607_3250,
        0x6593_9e62,
        0x1ae9_8013,
        0x6c10_01cd,
    ],
    [
        0x0e33_e167,
        0x5c79_cc76,
        0x3bd4_4669,
        0x4214_f8ba,
        0x3486_da7d,
        0x0da6_12c8,
        0x09d2_9526,
        0x25a1_ca33,
    ],
    [
        0x0317_f855,
        0x6a42_c9f1,
        0x67b2_5f2b,
        0x2391_ac78,
        0x3fe5_2639,
        0x2427_6614,
        0x2fef_1ddf,
        0x6bfe_9366,
    ],
    [
        0x79a4_29d4,
        0x24c9_7b21,
        0x3300_3ea2,
        0x1094_a7b9,
        0x4141_cf26,
        0x3858_76f1,
        0x329b_a741,
        0x4ef5_48e8,
    ],
    [
        0x6c1c_1568,
        0x28b7_bdde,
        0x020b_26d0,
        0x0ada_e811,
        0x38dd_63a6,
        0x133b_8274,
        0x1826_7974,
        0x2190_583b,
    ],
    [
        0x353a_8124,
        0x418a_51d3,
        0x7f39_2fb9,
        0x44c6_995e,
        0x2ffa_0c11,
        0x2925_e9fe,
        0x4944_5481,
        0x2833_3f2d,
    ],
    [
        0x6a16_755e,
        0x76fc_5d5c,
        0x0cb8_3202,
        0x00e6_697f,
        0x73d4_0e2b,
        0x1767_5952,
        0x1fd2_7d3e,
        0x54c9_102f,
    ],
    [
        0x202b_ddde,
        0x301a_5d1c,
        0x0a14_896e,
        0x12a3_ac5b,
        0x1da1_8ab6,
        0x343c_8fdc,
        0x0301_fda1,
        0x1db3_fabb,
    ],
    [
        0x4b77_30b9,
        0x61a9_a56b,
        0x150b_2b77,
        0x0bb0_9ad4,
        0x7583_a656,
        0x18ea_af4b,
        0x6f2e_cd74,
        0x1346_c4ca,
    ],
    [
        0x4e1f_d281,
        0x6bbe_d364,
        0x64a0_c08b,
        0x326c_e5c3,
        0x7c76_f7e0,
        0x15c4_0800,
        0x586c_d040,
        0x618e_0e9d,
    ],
    [
        0x5e0f_1590,
        0x243c_8db5,
        0x221b_b5f1,
        0x6485_9135,
        0x73ef_95d8,
        0x4eae_d195,
        0x5516_dd1b,
        0x0c16_f124,
    ],
    [
        0x2d87_790e,
        0x5e4b_8e8c,
        0x4205_af85,
        0x7324_73d3,
        0x1049_77bd,
        0x56e1_e8dc,
        0x2950_1db2,
        0x5a9b_df3c,
    ],
    [
        0x33b6_4d1a,
        0x1403_0cb1,
        0x5d3a_4c77,
        0x1c8d_1295,
        0x7f76_77ab,
        0x5ae5_5819,
        0x7ad2_3996,
        0x69bc_c007,
    ],
    [
        0x2f35_ca98,
        0x2b99_ca58,
        0x2ef7_c95a,
        0x57b7_c34d,
        0x2ecc_202f,
        0x7841_55cb,
        0x2cee_55ae,
        0x588c_2bee,
    ],
    [
        0x6238_adda,
        0x495a_1e9d,
        0x5e3c_144c,
        0x3b17_3190,
        0x7b72_c0ae,
        0x5a82_9c12,
        0x3426_cd5f,
        0x1b9e_1cb3,
    ],
    [
        0x16ab_633e,
        0x7824_22ad,
        0x459c_e2bb,
        0x2a2d_79bf,
        0x306f_1199,
        0x4640_0c0a,
        0x3cc7_9ed1,
        0x153b_87e3,
    ],
    [
        0x3205_6652,
        0x503b_bd13,
        0x5629_2d75,
        0x7e96_5c19,
        0x2eeb_d126,
        0x5ffb_d01d,
        0x06b7_803c,
        0x4ed1_4697,
    ],
    [
        0x3586_1d4b,
        0x4585_3d51,
        0x55a2_7af8,
        0x56cb_9680,
        0x10c8_358a,
        0x3edc_0ea5,
        0x632c_f177,
        0x70d8_33d1,
    ],
    [
        0x4a1e_c84b,
        0x44be_5121,
        0x543d_200a,
        0x6dd6_70c0,
        0x6983_0b75,
        0x05e9_eddb,
        0x140f_c6ce,
        0x3f59_ff74,
    ],
    [
        0x557b_1175,
        0x44d4_7a84,
        0x7767_5621,
        0x1b67_65ef,
        0x1d03_63df,
        0x35f3_76a9,
        0x0f59_9c0d,
        0x3677_9d72,
    ],
    [
        0x70f9_1b80,
        0x0467_0031,
        0x77d0_0de6,
        0x0707_6c45,
        0x1b1d_5748,
        0x0904_546b,
        0x2e66_5843,
        0x2e6f_6336,
    ],
    [
        0x7e72_ec22,
        0x5d96_6d06,
        0x332f_3ccb,
        0x1a1a_3714,
        0x62ee_ebaa,
        0x09ac_e139,
        0x14b9_0186,
        0x6e39_3235,
    ],
    [
        0x1c88_268e,
        0x55ff_1b72,
        0x76af_4559,
        0x03eb_9f08,
        0x0523_bfdd,
        0x3429_cbd8,
        0x29d7_1c23,
        0x624e_aef1,
    ],
    [
        0x6882_1f1c,
        0x26e6_7724,
        0x74b2_36a3,
        0x488f_094d,
        0x34ad_e187,
        0x5a77_f4db,
        0x4b13_4c71,
        0x3310_420e,
    ],
    [
        0x22dc_5211,
        0x262c_78c9,
        0x46d5_4005,
        0x727c_48d0,
        0x48cc_b35c,
        0x7c0c_d611,
        0x3f3c_85f1,
        0x494b_9703,
    ],
    [
        0x3573_f203,
        0x1e4b_7425,
        0x6a64_2beb,
        0x4d08_d921,
        0x1728_7114,
        0x343a_1fb2,
        0x6ce5_e393,
        0x76aa_ea2f,
    ],
    [
        0x33f4_e041,
        0x30a5_f1b0,
        0x6961_82f8,
        0x60bd_ce0d,
        0x3d41_47b0,
        0x6d96_4b61,
        0x346c_6e1f,
        0x60ef_d1d2,
    ],
    [
        0x6469_7842,
        0x5f8b_9b95,
        0x326b_402a,
        0x6b25_6553,
        0x755c_4c66,
        0x5bd4_a59d,
        0x05b9_4321,
        0x6ccf_fdcd,
    ],
];

/// The root a path gives `leaf` at `slot`: its siblings from level 0 up.
pub fn root_of(leaf: &Words, slot: u32, siblings: &[Words; DEPTH]) -> Words {
    let mut node = *leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        node = if slot >> level & 1 == 0 {
            compress(&node, sibling)
        } else {
            compress(sibling, &node)
        };
    }
    node
}

/// A path's 32 siblings, from the leaf's level up, each a digest: 1,024
/// bytes, no length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Siblings(pub [Digest; DEPTH]);

impl Encode for Siblings {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        for sibling in &self.0 {
            buf.extend_from_slice(sibling);
        }
    }
}

impl Decode for Siblings {
    fn decode(data: &[u8]) -> Result<(Self, usize), DecodeError> {
        let bytes = data.get(..DEPTH * 32).ok_or(DecodeError::UnexpectedEof)?;
        let siblings = core::array::from_fn(|i| bytes[32 * i..32 * i + 32].try_into().unwrap());
        Ok((Self(siblings), DEPTH * 32))
    }
}

/// What `path(member)` answers: the tree's root, the member's slot and the
/// siblings from its leaf up.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Path {
    pub root: Digest,
    pub slot: u32,
    pub siblings: Siblings,
}

impl Path {
    /// Whether this path places `member`'s leaf under its root.
    pub fn proves(&self, member: &Digest) -> bool {
        let (Some(member), Some(root)) = (words(member), words(&self.root)) else {
            return false;
        };
        let mut siblings = [[0u32; 8]; DEPTH];
        for (words_of, sibling) in siblings.iter_mut().zip(&self.siblings.0) {
            match words(sibling) {
                Some(sibling) => *words_of = sibling,
                None => return false,
            }
        }
        root_of(&leaf(&member), self.slot, &siblings) == root
    }
}

/// One root of the ring: a root and the batch time it became the tree's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RootEntry {
    pub root: Digest,
    pub since: u64,
}

/// Why a root is not accepted: in no entry of the ring, or superseded more
/// than [`crate::defaults::ROOT_MAX_AGE`] before the time it is judged at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum RootRefusal {
    #[codec(index = 0)]
    Unknown = 0,
    #[codec(index = 1)]
    Stale = 1,
}

/// The last [`RING`] roots, newest last, each from the batch time it became
/// the tree's root.
#[derive(Clone, Debug, Default, PartialEq, Eq, Encode, Decode)]
pub struct Ring(pub Vec<RootEntry>);

impl Ring {
    /// The ring an install writes: the empty tree's root, from `time`.
    pub fn installed(time: u64) -> Self {
        Self(alloc::vec![RootEntry {
            root: digest(&EMPTY[DEPTH]),
            since: time,
        }])
    }

    /// The tree's root, and since when.
    pub fn newest(&self) -> Option<&RootEntry> {
        self.0.last()
    }

    /// A write at batch time `time` left `root`: the newest entry's root
    /// replaced when it is from `time`, else a new entry, the oldest dropped
    /// past [`RING`].
    pub fn record(&mut self, root: Digest, time: u64) {
        match self.0.last_mut() {
            Some(newest) if newest.since == time => newest.root = root,
            _ => {
                self.0.push(RootEntry { root, since: time });
                if self.0.len() > RING {
                    self.0.remove(0);
                }
            }
        }
    }

    /// Whether `root` is accepted at `time`: the newest, or superseded at
    /// most [`crate::defaults::ROOT_MAX_AGE`] before `time`, by the time
    /// the next entry became the root. A root the ring holds twice is
    /// judged by its later entry.
    pub fn accepts(&self, root: &Digest, time: u64) -> Result<(), RootRefusal> {
        let at = self
            .0
            .iter()
            .rposition(|entry| entry.root == *root)
            .ok_or(RootRefusal::Unknown)?;
        match self.0.get(at + 1) {
            None => Ok(()),
            Some(next) if time.saturating_sub(next.since) <= crate::defaults::ROOT_MAX_AGE => {
                Ok(())
            }
            Some(_) => Err(RootRefusal::Stale),
        }
    }
}

/// The scope a guard named `name` gives in `space`'s agent `agent`, at
/// `instance` (`identity-and-authority.md` §7):
/// `C(T(scope), W(BLAKE2b-256("vos/cred/scope/v1" ‖ space ‖ agent ‖ instance ‖ name)))`,
/// the agent and the instance four little-endian bytes each. No two
/// agents' guards of one name, in one space or two, share a pseudonym.
pub fn scope(space: &SpaceId, agent: AgentId, instance: InstanceId, name: &[u8]) -> Digest {
    let hash = vos_pvm_precompiles::blake2b_hash::<32>(
        b"vos/cred/scope/v1",
        &[
            &space.0,
            &agent.0.to_le_bytes(),
            &instance.0.to_le_bytes(),
            name,
        ],
    );
    digest(&compress(&Tag::Scope.block(), &reduced(&hash)))
}

/// What a binding digest binds: one call of one method, in one space,
/// under one statement, once, before `expires_ms`.
#[derive(Clone, Copy, Debug)]
pub struct Bound<'a> {
    pub space: &'a SpaceId,
    pub agent: AgentId,
    pub instance: InstanceId,
    pub method: MethodId,
    /// The statement's program id: its circuit's, or a device proof's
    /// kernel's.
    pub program: &'a [u8; 32],
    /// The statement's kind, [`crate::ingress::CredentialPublic`]'s index.
    pub kind: u8,
    pub arguments: &'a [u8],
    pub nonce: &'a [u8; 16],
    pub expires_ms: u64,
}

impl Bound<'_> {
    /// `b = BLAKE2b-256("vos/cred/binding/v1" ‖ space ‖ agent ‖ instance ‖
    /// method ‖ program ‖ kind ‖ arguments ‖ nonce ‖ expires_ms)`: the
    /// agent, instance and method four little-endian bytes each, the kind
    /// one byte, the arguments as the codec writes them (a `u32`
    /// little-endian length, then the bytes), `expires_ms` eight
    /// little-endian bytes.
    pub fn digest(&self) -> [u8; 32] {
        let length = (self.arguments.len() as u32).to_le_bytes();
        vos_pvm_precompiles::blake2b_hash::<32>(
            b"vos/cred/binding/v1",
            &[
                &self.space.0,
                &self.agent.0.to_le_bytes(),
                &self.instance.0.to_le_bytes(),
                &self.method.0.to_le_bytes(),
                self.program,
                &[self.kind],
                &length,
                self.arguments,
                self.nonce,
                &self.expires_ms.to_le_bytes(),
            ],
        )
    }
}

/// The proof's public `binding` of the binding digest `b`:
/// `C(T(binding), W(b))`.
pub fn binding(b: &[u8; 32]) -> Digest {
    digest(&compress(&Tag::Binding.block(), &reduced(b)))
}

/// Why the credential actor refused a call: its handlers' error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Encode, Decode)]
#[repr(u8)]
pub enum CredentialError {
    /// A `member` digest with a word at or above p.
    #[codec(index = 0)]
    NotADigest = 0,
    /// The member is enrolled.
    #[codec(index = 1)]
    Enrolled = 1,
    /// The member is neither enrolled nor invited.
    #[codec(index = 2)]
    NotEnrolled = 2,
    /// Every slot is taken.
    #[codec(index = 3)]
    Full = 3,
    /// More than [`ENROLL_MANY`] members in one call.
    #[codec(index = 4)]
    TooMany = 4,
    /// The member holds no invitation.
    #[codec(index = 5)]
    NotInvited = 5,
    /// The invitation expired before the claim.
    #[codec(index = 6)]
    Expired = 6,
    /// The handle is set already.
    #[codec(index = 7)]
    Founded = 7,
    /// No handle is set yet: the actor takes no write before it is.
    #[codec(index = 8)]
    Unfounded = 8,
    /// The handle given is all zeros, which reads as none.
    #[codec(index = 9)]
    ZeroHandle = 9,
}

/// The key of the ring's row of the credential actor at `actor`: the row
/// [`tables::RING_KEY`] of its hashed table [`tables::RING`], which
/// ingress and the refine both read. Inline, so it is compiled only where
/// it is called: a pinned kernel that does not call it keeps its program
/// id.
#[inline]
pub fn ring_key(actor: InstanceId) -> Vec<u8> {
    let rows = crate::abi::Rows::Table {
        tag: crate::ids::derive_id("vos/table/", tables::RING),
        transform: crate::keys::Transform::Hashed,
    };
    crate::keys::row(actor, rows, &[tables::RING_KEY]).expect("a hashed row's key")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The six tags' `t` are their names', distinct and nonzero.
    #[test]
    fn the_tags_are_pinned_distinct_and_nonzero() {
        let mut seen = Vec::new();
        for tag in Tag::ALL {
            assert_eq!(tag.word(), tag_word(tag.name()), "{}", tag.name());
            assert!(tag.word() != 0 && tag.word() < P, "{}", tag.name());
            assert!(!seen.contains(&tag.word()), "{}", tag.name());
            seen.push(tag.word());
        }
        // The domain is a prefix of one BLAKE2b input.
        let joined = vos_pvm_precompiles::blake2b_hash::<32>(b"", &[b"vos/p2/leaf"]);
        assert_eq!(
            Tag::Leaf.word(),
            u32::from_le_bytes(joined[..4].try_into().unwrap()) & P
        );
    }

    /// Each empty subtree is the compression of the one below.
    #[test]
    fn the_empty_subtrees_are_pinned() {
        for level in 1..=DEPTH {
            assert_eq!(
                EMPTY[level],
                compress(&EMPTY[level - 1], &EMPTY[level - 1]),
                "{level}"
            );
        }
    }

    /// `W` masks each word's top bit and maps `2^31 − 1` to 0; a digest's
    /// words refuse any word at or above p.
    #[test]
    fn words_and_reductions() {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[4..8].copy_from_slice(&P.to_le_bytes());
        bytes[8..12].copy_from_slice(&(P - 1).to_le_bytes());
        bytes[12..16].copy_from_slice(&(1u32 << 31 | 5).to_le_bytes());
        assert_eq!(reduced(&bytes)[..4], [0, 0, P - 1, 5]);
        assert_eq!(words(&bytes), None);
        let fine = digest(&[P - 1, 0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(words(&fine), Some([P - 1, 0, 1, 2, 3, 4, 5, 6]));
        for word in [P, 1 << 31, u32::MAX] {
            let mut bytes = fine;
            bytes[28..].copy_from_slice(&word.to_le_bytes());
            assert_eq!(words(&bytes), None, "{word:#x}");
        }
    }

    /// The ring: a write at the newest entry's time replaces its root,
    /// another appends, the oldest dropped past 64; a root is accepted while
    /// newest and for `ROOT_MAX_AGE` after it was superseded, judged by its
    /// later entry when held twice.
    #[test]
    fn the_ring_records_and_judges_freshness() {
        const AGE: u64 = crate::defaults::ROOT_MAX_AGE;
        let root = |n: u8| [n; 32];
        let mut ring = Ring::installed(5);
        assert_eq!(ring.newest().unwrap().root, digest(&EMPTY[DEPTH]));
        ring.record(root(1), 5);
        assert_eq!(
            ring.0,
            [RootEntry {
                root: root(1),
                since: 5
            }]
        );
        ring.record(root(2), 10);
        ring.record(root(3), 10);
        assert_eq!(ring.0.len(), 2);
        assert_eq!(ring.accepts(&root(2), 0), Err(RootRefusal::Unknown));
        assert_eq!(ring.accepts(&root(3), u64::MAX), Ok(()), "the newest");
        assert_eq!(ring.accepts(&root(1), 10 + AGE), Ok(()));
        assert_eq!(
            ring.accepts(&root(1), 10 + AGE + 1),
            Err(RootRefusal::Stale)
        );
        assert_eq!(ring.accepts(&root(1), 3), Ok(()), "before its successor");
        // root 1 again: its later entry is the newest.
        ring.record(root(1), 20);
        assert_eq!(ring.accepts(&root(1), u64::MAX), Ok(()));
        assert_eq!(
            ring.accepts(&root(3), 20 + AGE + 1),
            Err(RootRefusal::Stale)
        );
        for time in 21..21 + RING as u64 {
            ring.record(root(time as u8), time);
        }
        assert_eq!(ring.0.len(), RING);
        assert_eq!(ring.0[0].since, 20 + 1, "the oldest dropped");
        assert_eq!(ring.accepts(&root(3), 30), Err(RootRefusal::Unknown));
        assert_eq!(Ring::decode_exact(&ring.encode()), Some(ring));
    }

    /// A path's codec is its root, its slot and 1,024 bytes of siblings.
    #[test]
    fn a_path_round_trips() {
        let path = Path {
            root: [1; 32],
            slot: 7,
            siblings: Siblings(core::array::from_fn(|i| [i as u8; 32])),
        };
        let bytes = path.encode();
        assert_eq!(bytes.len(), 32 + 4 + DEPTH * 32);
        assert_eq!(Path::decode_exact(&bytes), Some(path));
        assert_eq!(Path::decode_exact(&bytes[..bytes.len() - 1]), None);
    }
}
