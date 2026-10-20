//! The service's work items, each a payload: a tag byte, then the item.
//!
//! - **`Register`** (0): the space's genesis (its canonical encoding), the
//!   controller (32), the start window (8), a founding key (32) and its
//!   signature over `vos_anchor::register_digest` (64), as Kreivo's
//!   `register` takes them;
//! - **`Migrate`** (1): a `vos_anchor::Migrate`, the controller's key (32)
//!   and its signature over [`migrate_digest`] (64). On JAM the controller
//!   is an ed25519 key: the service holds no accounts;
//! - **`Anchor`** (2): a `vos_anchor::Anchor`, its signature over its
//!   digest at this venue;
//! - **`Submit`** (3): a statement's canonical encoding, at most
//!   [`MAX_STATEMENT_BYTES`]; its final proof is the item's first extrinsic
//!   (`fetch` kind 4), at most `MAX_PROOF_BYTES`.
//!
//! JAM-NP's CE 133 bounds a work package, payloads among it, at 204,802
//! bytes, below the 256 KiB a proof may take: the proof goes as an
//! extrinsic, which a package names by hash and length, under the bundle's
//! own bound (`W_B`).

use alloc::vec::Vec;

use vos_statement::vos_anchor::codec::Reader;
use vos_statement::vos_anchor::{Anchor, Migrate, SpaceGenesis};
use vos_statement::{DecodeError, blake2b_256};

/// The longest statement the service takes, as Kreivo's `submit` bounds it:
/// longer is refused as undecodable, code 1.
pub const MAX_STATEMENT_BYTES: usize = 64 << 10;

/// The migration digest's domain.
pub const MIGRATE_DOMAIN: &[u8] = b"vos/space/migrate";

/// An item's tag: its payload's first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Register = 0,
    Migrate = 1,
    Anchor = 2,
    Submit = 3,
}

impl Kind {
    /// The kind `byte` names.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Register,
            1 => Self::Migrate,
            2 => Self::Anchor,
            3 => Self::Submit,
            _ => return None,
        })
    }
}

/// A space's registration, signed by one of its founding keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register {
    pub genesis: SpaceGenesis,
    pub controller: [u8; 32],
    pub start_window: u64,
    pub founder_key: [u8; 32],
    pub signature: [u8; 64],
}

/// A space's migration away, signed by its controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedMigrate {
    pub migrate: Migrate,
    pub controller: [u8; 32],
    pub signature: [u8; 64],
}

/// What the controller signs to migrate a space:
/// `BLAKE2b-256("vos/space/migrate" ‖ migrate)`, the migration in its
/// encoding, which names both venues.
pub fn migrate_digest(migrate: &Migrate) -> [u8; 32] {
    blake2b_256(&[MIGRATE_DOMAIN, &migrate.encode()])
}

/// A work item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Register(Register),
    Migrate(SignedMigrate),
    Anchor(Anchor),
    /// A statement's encoding, decoded by refine: an undecodable one is a
    /// verdict, code 1.
    Submit(Vec<u8>),
}

impl Item {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Register(_) => Kind::Register,
            Self::Migrate(_) => Kind::Migrate,
            Self::Anchor(_) => Kind::Anchor,
            Self::Submit(_) => Kind::Submit,
        }
    }

    /// Its payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = alloc::vec![self.kind() as u8];
        match self {
            Self::Register(register) => {
                register.genesis.encode_to(&mut out);
                out.extend_from_slice(&register.controller);
                out.extend_from_slice(&register.start_window.to_le_bytes());
                out.extend_from_slice(&register.founder_key);
                out.extend_from_slice(&register.signature);
            }
            Self::Migrate(signed) => {
                out.extend_from_slice(&signed.migrate.encode());
                out.extend_from_slice(&signed.controller);
                out.extend_from_slice(&signed.signature);
            }
            Self::Anchor(anchor) => out.extend_from_slice(&anchor.encode()),
            Self::Submit(statement) => out.extend_from_slice(statement),
        }
        out
    }

    /// The item `payload` holds, all of it, canonically; a `Submit`'s
    /// statement is left undecoded.
    pub fn decode(payload: &[u8]) -> Result<Self, DecodeError> {
        let (&tag, body) = payload.split_first().ok_or(DecodeError::Short)?;
        let kind = Kind::from_u8(tag).ok_or(DecodeError::Noncanonical)?;
        if kind == Kind::Submit {
            return Ok(Self::Submit(body.to_vec()));
        }
        let mut reader = Reader::new(body);
        let item = match kind {
            Kind::Register => Self::Register(Register {
                genesis: SpaceGenesis::decode_from(&mut reader)?,
                controller: reader.array()?,
                start_window: reader.u64()?,
                founder_key: reader.array()?,
                signature: reader.array()?,
            }),
            Kind::Migrate => Self::Migrate(SignedMigrate {
                migrate: Migrate::decode(reader.take(MIGRATE_BYTES)?)?,
                controller: reader.array()?,
                signature: reader.array()?,
            }),
            Kind::Anchor => Self::Anchor(Anchor::decode(reader.take(Anchor::BYTES)?)?),
            Kind::Submit => return Err(DecodeError::Noncanonical),
        };
        reader.finish()?;
        Ok(item)
    }
}

/// A migration's bytes: the space, the venues and the window.
const MIGRATE_BYTES: usize = 32 * 3 + 8;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use vos_statement::vos_anchor::{RootKind, SpaceId, VenueId, WindowClock};

    fn genesis() -> SpaceGenesis {
        SpaceGenesis {
            version: 1,
            nodes: vec![(0, [1; 32]), (3, [2; 32])],
            clock: WindowClock::DEFAULT,
            time: 5,
            nonce: [6; 16],
        }
    }

    /// Each item decodes from its payload; a byte short, a byte more and an
    /// unknown tag are refused, a statement's bytes taken as they are.
    #[test]
    fn every_item_decodes_from_its_payload() {
        let items = [
            Item::Register(Register {
                genesis: genesis(),
                controller: [3; 32],
                start_window: 9,
                founder_key: [1; 32],
                signature: [4; 64],
            }),
            Item::Migrate(SignedMigrate {
                migrate: Migrate {
                    space: SpaceId([5; 32]),
                    from: VenueId([6; 32]),
                    to: VenueId([7; 32]),
                    from_window: 11,
                },
                controller: [8; 32],
                signature: [9; 64],
            }),
            Item::Anchor(Anchor {
                space: SpaceId([5; 32]),
                window: 12,
                kind: RootKind::Space,
                root: [10; 32],
                signer: [11; 32],
                signature: [12; 64],
            }),
        ];
        for item in items {
            let payload = item.encode();
            assert_eq!(Item::decode(&payload), Ok(item.clone()));
            assert!(Item::decode(&payload[..payload.len() - 1]).is_err());
            let mut more = payload.clone();
            more.push(0);
            assert_eq!(Item::decode(&more), Err(DecodeError::Trailing));
        }
        assert_eq!(Item::decode(&[3, 1, 2]), Ok(Item::Submit(vec![1, 2])));
        assert_eq!(Item::decode(&[4]), Err(DecodeError::Noncanonical));
        assert_eq!(Item::decode(&[]), Err(DecodeError::Short));
    }
}
