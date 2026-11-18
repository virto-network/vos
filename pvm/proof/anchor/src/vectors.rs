//! The golden vectors: inputs and the digests every venue must compute from
//! them, byte for byte, natively, in Wasm and in the PVM.
//!
//! A [`Vector`] is a genesis and what a venue signs over with it: a venue,
//! a controller, a window and its representative's root, and a JAM chain's
//! genesis and service. Its [`Digests`] are the space's
//! id, the space root `S_w` of the window, the anchor digest of `S_w` at the
//! venue, the registration digest and the JAM venue's id. A venue's harness
//! decodes a vector's encoding ([`Vector::encode`]), computes its digests,
//! and returns their 160 bytes ([`Digests::to_bytes`]), which [`golden`]
//! pins.

use alloc::vec::Vec;

use crate::codec::Reader;
use crate::{
    DecodeError, RootKind, SpaceGenesis, SpaceId, VenueId, WindowClock, anchor_digest,
    register_digest, space_root,
};

/// A vector's inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vector {
    pub genesis: SpaceGenesis,
    pub venue: VenueId,
    pub controller: [u8; 32],
    pub window: u64,
    /// The representative's agent root at its cut of `window`.
    pub rep_root: [u8; 32],
    /// A JAM chain's genesis hash, and a service on it.
    pub jam_genesis: [u8; 32],
    pub service: u32,
}

/// A vector's digests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Digests {
    pub space: SpaceId,
    /// `S_w` of the vector's window.
    pub space_root: [u8; 32],
    /// The anchor digest of `S_w` as the space root of the window, at the
    /// vector's venue.
    pub anchor: [u8; 32],
    pub register: [u8; 32],
    pub jam_venue: VenueId,
}

impl Digests {
    /// The bytes of [`Digests::to_bytes`].
    pub const BYTES: usize = 5 * 32;

    /// The digests in their order, each its 32 bytes.
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0u8; Self::BYTES];
        for (chunk, digest) in bytes.chunks_exact_mut(32).zip([
            &self.space.0,
            &self.space_root,
            &self.anchor,
            &self.register,
            &self.jam_venue.0,
        ]) {
            chunk.copy_from_slice(digest);
        }
        bytes
    }
}

impl Vector {
    /// Its encoding: the genesis's, then the venue, the controller, the
    /// window, the representative's root, the JAM genesis and the service.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.genesis.encode_to(&mut out);
        out.extend_from_slice(&self.venue.0);
        out.extend_from_slice(&self.controller);
        out.extend_from_slice(&self.window.to_le_bytes());
        out.extend_from_slice(&self.rep_root);
        out.extend_from_slice(&self.jam_genesis);
        out.extend_from_slice(&self.service.to_le_bytes());
        out
    }

    /// The vector `bytes` encode, all of them.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        let vector = Self {
            genesis: SpaceGenesis::decode_from(&mut reader)?,
            venue: VenueId(reader.array()?),
            controller: reader.array()?,
            window: reader.u64()?,
            rep_root: reader.array()?,
            jam_genesis: reader.array()?,
            service: reader.u32()?,
        };
        reader.finish()?;
        Ok(vector)
    }

    /// Its digests, as a venue computes them.
    pub fn digests(&self) -> Digests {
        let space = crate::space_id(&self.genesis);
        let space_root = space_root(&space, self.window, &self.rep_root);
        Digests {
            space,
            space_root,
            anchor: anchor_digest(
                &self.venue,
                &space,
                self.window,
                RootKind::Space,
                &space_root,
            ),
            register: register_digest(&self.venue, &space, &self.controller),
            jam_venue: VenueId::jam(&self.jam_genesis, self.service),
        }
    }
}

/// A golden vector: its name, its inputs, and its digests' 160 bytes in hex.
pub struct Golden {
    pub name: &'static str,
    pub vector: Vector,
    pub digests: &'static str,
}

/// `n` bytes counting up from `from`.
fn counting<const N: usize>(from: u8) -> [u8; N] {
    core::array::from_fn(|i| from.wrapping_add(i as u8))
}

/// The golden vectors: one founder at window 0; three founders at window
/// 2,966,001 of a two-minute clock; and
/// every integer at its top, 64 founders (a two-byte count, more than a
/// venue registers: the encoding's vector, not a registrable genesis).
pub fn golden() -> Vec<Golden> {
    alloc::vec![
        Golden {
            name: "one founder, window 0",
            vector: Vector {
                genesis: SpaceGenesis {
                    nodes: alloc::vec![(1, [0x11; 32])],
                    clock: WindowClock {
                        origin_ms: 1_700_000_000_000,
                        length_ms: 600_000,
                    },
                    time: 1_700_000_000_000,
                    nonce: [0x01; 16],
                },
                venue: VenueId([0x4b; 32]),
                controller: [0xc0; 32],
                window: 0,
                rep_root: [0x22; 32],
                jam_genesis: [0x7a; 32],
                service: 0,
            },
            digests: concat!(
                "67a526a077f2fb557e36a7b90d631e34a63ae33a7d4904820a6229c6d6064385",
                "59bca6cffe6878f3f5233bcb12f4ed7ae403c665814c70b12504cdcd796f06cc",
                "4a3a40450c3d61d91e3b0a5224b686bd285a0ac9e65ed1013026934600d77fae",
                "57832e0395a16310fcd11123f63aa095690452bbbc48874a06e32b8ff7beea25",
                "8a2bc027b19306035c5113f838d08e0781a3225ccf8348bde7a5a00060babff0"
            ),
        },
        Golden {
            name: "three founders",
            vector: Vector {
                genesis: SpaceGenesis {
                    nodes: alloc::vec![
                        (1, counting(0x10)),
                        (2, counting(0x30)),
                        (7, counting(0x50))
                    ],
                    clock: WindowClock {
                        origin_ms: 1_760_000_000_000,
                        length_ms: 120_000,
                    },
                    time: 1_760_000_012_345,
                    nonce: counting(0xa0),
                },
                venue: VenueId(counting(0x00)),
                controller: counting(0x80),
                window: 2_966_001,
                rep_root: counting(0xd0),
                jam_genesis: counting(0x40),
                service: 0x1234_5678,
            },
            digests: concat!(
                "5a47da04f4b9ed4554145148fa20f6c3d52d882aff6559d4df13245f5704ef72",
                "4055c65efa0159a24210735dd73e970c466a00b93cfc2b293512b880db51efdf",
                "69b5f3b3503d6d4e9035408924d7aedc7c3ca43528f60a47a915a64716a79303",
                "79d2303febeb13b866e9291d5bb9112b2cb969d9b9d9d469b5f186309b370d6d",
                "50ac7e1c9f56e745963a6ad591313eb08fabf20f2e7d2e90eed5406f0f10ca69"
            ),
        },
        Golden {
            name: "every integer at its top",
            vector: Vector {
                genesis: SpaceGenesis {
                    nodes: (0..64).map(|n| (n, [n; 32])).collect(),
                    clock: WindowClock {
                        origin_ms: u64::MAX,
                        length_ms: 3_600_000,
                    },
                    time: u64::MAX,
                    nonce: [0xff; 16],
                },
                venue: VenueId([0xff; 32]),
                controller: [0xff; 32],
                window: u64::MAX,
                rep_root: [0xff; 32],
                jam_genesis: [0xff; 32],
                service: u32::MAX,
            },
            digests: concat!(
                "680c554472cc2141f0e35a70b7340c5bc3b594bc639c34827d874cd90821a0a6",
                "8f26b88d10b59d4efd8acd101ab48b15df6a5a3ce1d696b9f51155c24810425e",
                "fa4dd591cd3f48b27447b0146233786c5ad100b9195a26f3e5eb65dbd1d27e03",
                "80d6f57b1cdfc362b78e8405b06b199585fa0c0c101fc56199a7f9cb08c96110",
                "799bf7fd73ab486ca1254788dc6d6cf91ac23d0db52c96cef0bc4f084b8795a7"
            ),
        },
    ]
}
