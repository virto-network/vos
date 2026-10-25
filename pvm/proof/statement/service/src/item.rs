//! The service's work items, each a payload: a tag byte, then the item.
//!
//! - **`Register`** (0): the space's genesis (its canonical encoding), the
//!   controller (32), a founding key (32) and its signature over
//!   `vos_anchor::register_digest` (64), as Kreivo's `register` takes them.
//!   On JAM the controller is an ed25519 key: the service holds no
//!   accounts;
//! - **`Anchor`** (2): a `vos_anchor::Anchor`, its signature over its
//!   digest at this venue;
//! - **`Submit`** (3): a statement's canonical encoding, at most
//!   [`MAX_STATEMENT_BYTES`] and [`MAX_ROOTS`] roots; its final proof is
//!   the item's first extrinsic (`fetch` kind 4), at most
//!   `MAX_PROOF_BYTES`;
//! - **`Control`** (4): the controller's management of its space, the
//!   space's spaces-pallet calls 2–4 and 1 on JAM: add or remove an anchor
//!   key, set another controller; each with the space's next nonce, so
//!   none is replayed, and the controller's signature over
//!   [`control_digest`].
//!
//! Tag 1 and op 2 are retired, never reused.
//!
//! JAM-NP's CE 133 bounds a work package, payloads among it, at 204,802
//! bytes, below the 256 KiB a proof may take: the proof goes as an
//! extrinsic, which a package names by hash and length, under the bundle's
//! own bound (`W_B`).

use alloc::vec::Vec;

use vos_statement::vos_anchor::codec::Reader;
use vos_statement::vos_anchor::{Anchor, SpaceGenesis, SpaceId, VenueId};
use vos_statement::{DecodeError, blake2b_256};

/// The longest statement the service takes, as Kreivo's `submit` bounds it:
/// longer is refused as undecodable, code 1.
pub const MAX_STATEMENT_BYTES: usize = 64 << 10;

/// The most roots a statement the service takes reads: more is refused as
/// undecodable, code 1. A kernel reads a root a window it states over; at
/// 64, a statement's accumulate stays within its item's gas.
pub const MAX_ROOTS: usize = 64;

/// The control digest's domain.
pub const CONTROL_DOMAIN: &[u8] = b"vos/space/control";

/// An item's tag: its payload's first byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Register = 0,
    Anchor = 2,
    Submit = 3,
    Control = 4,
}

impl Kind {
    /// The kind `byte` names.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Register,
            2 => Self::Anchor,
            3 => Self::Submit,
            4 => Self::Control,
            _ => return None,
        })
    }
}

/// A space's registration, signed by one of its founding keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register {
    pub genesis: SpaceGenesis,
    pub controller: [u8; 32],
    pub founder_key: [u8; 32],
    pub signature: [u8; 64],
}

/// What the controller does to its space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// List another anchor key (at most `MAX_FOUNDING_KEYS`, none of small
    /// order).
    AddKey([u8; 32]),
    /// Delist an anchor key.
    RemoveKey([u8; 32]),
    /// Hand the space to another controller key.
    SetController([u8; 32]),
}

impl Op {
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            Self::AddKey(key) => {
                out.push(0);
                out.extend_from_slice(key);
            }
            Self::RemoveKey(key) => {
                out.push(1);
                out.extend_from_slice(key);
            }
            Self::SetController(key) => {
                out.push(3);
                out.extend_from_slice(key);
            }
        }
    }

    pub fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(match reader.u8()? {
            0 => Self::AddKey(reader.array()?),
            1 => Self::RemoveKey(reader.array()?),
            3 => Self::SetController(reader.array()?),
            _ => return Err(DecodeError::Noncanonical),
        })
    }
}

/// The controller's operation on its space, at its nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Control {
    pub space: SpaceId,
    /// The space's nonce at this venue: its count of controls taken.
    pub nonce: u64,
    pub op: Op,
}

impl Control {
    /// Its encoding: the space, the nonce (8, LE), the op's byte and its key.
    pub fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.space.0);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        self.op.encode_to(out);
    }

    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            space: SpaceId(reader.array()?),
            nonce: reader.u64()?,
            op: Op::decode_from(reader)?,
        })
    }
}

/// What the controller signs to control its space at `venue`:
/// `BLAKE2b-256("vos/space/control" ‖ venue ‖ control)`.
pub fn control_digest(venue: &VenueId, control: &Control) -> [u8; 32] {
    let mut bytes = Vec::new();
    control.encode_to(&mut bytes);
    blake2b_256(&[CONTROL_DOMAIN, &venue.0, &bytes])
}

/// A control, signed by the controller key it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignedControl {
    pub control: Control,
    pub controller: [u8; 32],
    pub signature: [u8; 64],
}

/// A work item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    Register(Register),
    Anchor(Anchor),
    /// A statement's encoding, decoded by refine: an undecodable one is a
    /// verdict, code 1.
    Submit(Vec<u8>),
    Control(SignedControl),
}

impl Item {
    pub fn kind(&self) -> Kind {
        match self {
            Self::Register(_) => Kind::Register,
            Self::Anchor(_) => Kind::Anchor,
            Self::Submit(_) => Kind::Submit,
            Self::Control(_) => Kind::Control,
        }
    }

    /// Its payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = alloc::vec![self.kind() as u8];
        match self {
            Self::Register(register) => {
                register.genesis.encode_to(&mut out);
                out.extend_from_slice(&register.controller);
                out.extend_from_slice(&register.founder_key);
                out.extend_from_slice(&register.signature);
            }
            Self::Anchor(anchor) => out.extend_from_slice(&anchor.encode()),
            Self::Submit(statement) => out.extend_from_slice(statement),
            Self::Control(signed) => {
                signed.control.encode_to(&mut out);
                out.extend_from_slice(&signed.controller);
                out.extend_from_slice(&signed.signature);
            }
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
                founder_key: reader.array()?,
                signature: reader.array()?,
            }),
            Kind::Anchor => Self::Anchor(Anchor::decode(reader.take(Anchor::BYTES)?)?),
            Kind::Control => Self::Control(SignedControl {
                control: Control::decode_from(&mut reader)?,
                controller: reader.array()?,
                signature: reader.array()?,
            }),
            Kind::Submit => return Err(DecodeError::Noncanonical),
        };
        reader.finish()?;
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use vos_statement::vos_anchor::{RootKind, WindowClock};

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
                founder_key: [1; 32],
                signature: [4; 64],
            }),
            Item::Anchor(Anchor {
                space: SpaceId([5; 32]),
                window: 12,
                kind: RootKind::Space,
                root: [10; 32],
                signer: [11; 32],
                signature: [12; 64],
            }),
            Item::Control(SignedControl {
                control: Control {
                    space: SpaceId([5; 32]),
                    nonce: 3,
                    op: Op::AddKey([13; 32]),
                },
                controller: [14; 32],
                signature: [15; 64],
            }),
            Item::Control(SignedControl {
                control: Control {
                    space: SpaceId([5; 32]),
                    nonce: 4,
                    op: Op::SetController([16; 32]),
                },
                controller: [14; 32],
                signature: [15; 64],
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
        for retired in [1, 5] {
            assert_eq!(Item::decode(&[retired]), Err(DecodeError::Noncanonical));
        }
        assert_eq!(Item::decode(&[]), Err(DecodeError::Short));
    }
}
