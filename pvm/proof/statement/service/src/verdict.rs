//! What refine hands accumulate for an item ([`Verdict`]), and the codes an
//! item's outcome reports.
//!
//! Refine reads no state: it checks what an item's own bytes show (a
//! signature, a genesis, a statement's checks but `anchored` and `seen`, a
//! proof) and names what accumulate must check against the service's state
//! (the signer, the space, the window, the roots). An item refine refuses
//! reaches accumulate as its refusal, which accumulate records.

use alloc::vec::Vec;

use vos_statement::vos_anchor::codec::{self, Reader};
use vos_statement::vos_anchor::{RootKind, SpaceId, WindowClock};
use vos_statement::{DecodeError, MAX_ROOT_AGE_MS};

use crate::item::{Kind, Op};

/// What a registration refine admitted names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    pub space: SpaceId,
    pub clock: WindowClock,
    pub controller: [u8; 32],
    pub start_window: u64,
    /// The founding keys, its first anchor keys.
    pub keys: Vec<[u8; 32]>,
}

/// A root a statement read, of the statement's space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Root {
    pub kind: RootKind,
    pub window: u64,
    pub root: [u8; 32],
}

impl Root {
    const BYTES: usize = 1 + 8 + 32;
}

/// A statement's judgement at refine: every check of `judge`'s but
/// `anchored` and `seen`, which accumulate makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Judged {
    /// Its id; zeros when the statement does not decode.
    pub id: [u8; 32],
    /// Its program id's 32 bytes; zeros when it does not decode.
    pub program: [u8; 32],
    pub space: SpaceId,
    /// Its roots, each of `space`: empty unless `code` is 0.
    pub roots: Vec<Root>,
    /// `vos_statement::code`'s: 0 when every check at refine passed.
    pub code: u32,
}

impl Judged {
    /// When its `Seen` entry may be dropped, by `clock`, its space's:
    /// `vos_statement::seen_expiry`'s rule over its roots, `u64::MAX` for a
    /// rootless statement or a boundary past `u64`.
    pub fn seen_expiry(&self, clock: &WindowClock) -> u64 {
        self.roots
            .iter()
            .map(|root| root.window)
            .max()
            .and_then(|window| clock.boundary(window))
            .and_then(|boundary| boundary.checked_add(MAX_ROOT_AGE_MS))
            .unwrap_or(u64::MAX)
    }
}

/// Refine's output for an item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A registration whose genesis and signature passed.
    Register(Registered),
    /// A migration signed by the key it names, away from this venue.
    Migrate {
        space: SpaceId,
        from_window: u64,
        controller: [u8; 32],
    },
    /// An anchor signed by the key it names.
    Anchor {
        space: SpaceId,
        window: u64,
        kind: RootKind,
        root: [u8; 32],
        signer: [u8; 32],
    },
    /// A statement judged.
    Submit(Judged),
    /// A control signed by the key it names, which accumulate checks is the
    /// space's controller.
    Control {
        space: SpaceId,
        nonce: u64,
        op: Op,
        controller: [u8; 32],
    },
    /// An item of `kind` (none: no item's) refused at refine by `code`, its
    /// kind's ([`RegisterCode`], [`MigrateCode`], [`AnchorCode`]).
    Refused { kind: Option<Kind>, code: u32 },
}

impl Verdict {
    /// Its encoding: a tag, then its fields; integers little-endian, a
    /// sequence a compact count before its items. At most
    /// [`crate::MAX_VERDICT_BYTES`] for an item refine takes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Register(registered) => {
                out.push(0);
                out.extend_from_slice(&registered.space.0);
                registered.clock.encode_to(&mut out);
                out.extend_from_slice(&registered.controller);
                out.extend_from_slice(&registered.start_window.to_le_bytes());
                codec::compact(&mut out, registered.keys.len() as u64);
                for key in &registered.keys {
                    out.extend_from_slice(key);
                }
            }
            Self::Migrate {
                space,
                from_window,
                controller,
            } => {
                out.push(1);
                out.extend_from_slice(&space.0);
                out.extend_from_slice(&from_window.to_le_bytes());
                out.extend_from_slice(controller);
            }
            Self::Anchor {
                space,
                window,
                kind,
                root,
                signer,
            } => {
                out.push(2);
                out.extend_from_slice(&space.0);
                out.extend_from_slice(&window.to_le_bytes());
                out.push(*kind as u8);
                out.extend_from_slice(root);
                out.extend_from_slice(signer);
            }
            Self::Submit(judged) => {
                out.push(3);
                out.extend_from_slice(&judged.id);
                out.extend_from_slice(&judged.program);
                out.extend_from_slice(&judged.space.0);
                out.extend_from_slice(&judged.code.to_le_bytes());
                codec::compact(&mut out, judged.roots.len() as u64);
                for root in &judged.roots {
                    out.push(root.kind as u8);
                    out.extend_from_slice(&root.window.to_le_bytes());
                    out.extend_from_slice(&root.root);
                }
            }
            Self::Control {
                space,
                nonce,
                op,
                controller,
            } => {
                out.push(5);
                out.extend_from_slice(&space.0);
                out.extend_from_slice(&nonce.to_le_bytes());
                op.encode_to(&mut out);
                out.extend_from_slice(controller);
            }
            Self::Refused { kind, code } => {
                out.push(4);
                out.push(kind.map_or(u8::MAX, |kind| kind as u8));
                out.extend_from_slice(&code.to_le_bytes());
            }
        }
        out
    }

    /// The verdict at the start of `bytes`, and the bytes it takes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut reader = Reader::new(bytes);
        let verdict = match reader.u8()? {
            0 => {
                let space = SpaceId(reader.array()?);
                let clock = WindowClock::decode_from(&mut reader)?;
                let controller = reader.array()?;
                let start_window = reader.u64()?;
                let count = reader.count(32)?;
                let keys = (0..count)
                    .map(|_| reader.array())
                    .collect::<Result<_, _>>()?;
                Self::Register(Registered {
                    space,
                    clock,
                    controller,
                    start_window,
                    keys,
                })
            }
            1 => Self::Migrate {
                space: SpaceId(reader.array()?),
                from_window: reader.u64()?,
                controller: reader.array()?,
            },
            2 => Self::Anchor {
                space: SpaceId(reader.array()?),
                window: reader.u64()?,
                kind: RootKind::decode_from(&mut reader)?,
                root: reader.array()?,
                signer: reader.array()?,
            },
            3 => {
                let id = reader.array()?;
                let program = reader.array()?;
                let space = SpaceId(reader.array()?);
                let code = reader.u32()?;
                let count = reader.count(Root::BYTES)?;
                let roots = (0..count)
                    .map(|_| {
                        Ok(Root {
                            kind: RootKind::decode_from(&mut reader)?,
                            window: reader.u64()?,
                            root: reader.array()?,
                        })
                    })
                    .collect::<Result<_, DecodeError>>()?;
                Self::Submit(Judged {
                    id,
                    program,
                    space,
                    roots,
                    code,
                })
            }
            4 => {
                let kind = match reader.u8()? {
                    u8::MAX => None,
                    byte => Some(Kind::from_u8(byte).ok_or(DecodeError::Noncanonical)?),
                };
                Self::Refused {
                    kind,
                    code: reader.u32()?,
                }
            }
            5 => Self::Control {
                space: SpaceId(reader.array()?),
                nonce: reader.u64()?,
                op: Op::decode_from(&mut reader)?,
                controller: reader.array()?,
            },
            _ => return Err(DecodeError::Noncanonical),
        };
        Ok((verdict, reader.used()))
    }

    /// The item kind it is of: none for an item that did not decode.
    pub fn kind(&self) -> Option<Kind> {
        match self {
            Self::Register(_) => Some(Kind::Register),
            Self::Migrate { .. } => Some(Kind::Migrate),
            Self::Anchor { .. } => Some(Kind::Anchor),
            Self::Submit(_) => Some(Kind::Submit),
            Self::Control { .. } => Some(Kind::Control),
            Self::Refused { kind, .. } => *kind,
        }
    }
}

/// A registration's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum RegisterCode {
    Registered = 0,
    /// The item does not decode.
    Item = 1,
    /// A genesis of no founding key or more than `MAX_FOUNDING_KEYS`, or a
    /// window length the venue does not register.
    Genesis = 2,
    /// The signing key is not one of the genesis's founding keys.
    Founder = 3,
    Signature = 4,
    /// The space is registered already.
    Again = 5,
    /// The start window is outside `[now_w − MaxRootAge / length, now_w + 1]`.
    Start = 6,
    /// The venue's time is before the clock's origin.
    Clock = 7,
}

/// A migration's outcome: `vos_venue::MigrateRefusal`'s, and refine's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum MigrateCode {
    Migrated = 0,
    Item = 1,
    /// It names another venue to leave, or this one to go to.
    Venue = 2,
    Signature = 3,
    Unregistered = 4,
    /// The signer is not the space's controller.
    Controller = 5,
    AlreadyMigrated = 6,
    /// Its window is at or before one anchored, before the venue's next
    /// window, or before the space's start here.
    Window = 7,
}

/// An anchor's outcome: `vos_venue::Anchored`'s and `AnchorRefusal`'s,
/// and refine's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum AnchorCode {
    New = 0,
    /// The venue held that root already.
    Again = 1,
    Item = 2,
    Signature = 3,
    Unregistered = 4,
    Suspended = 5,
    /// The signer is not one of the space's anchor keys.
    Key = 6,
    /// At or before the last window anchored, or outside the space's range.
    Window = 7,
    /// The space's open window or later, by the venue's clock.
    Open = 8,
    /// Past `MaxRootAge`.
    Age = 9,
    /// Another root of the space's kind at the window is held: kept as
    /// evidence, the space suspended.
    Equivocation = 10,
}

/// A control's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ControlCode {
    Done = 0,
    Item = 1,
    Signature = 2,
    Unregistered = 3,
    /// The signer is not the space's controller.
    Controller = 4,
    /// Not the space's next nonce: a replay, or one out of order.
    Nonce = 5,
    /// A key listed already, or `MAX_FOUNDING_KEYS` listed, to add; one not
    /// listed to remove.
    Key = 6,
    /// A resume while a signer of one of its equivocations is listed.
    Suspended = 7,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Each verdict decodes from its encoding, taking all of it.
    #[test]
    fn every_verdict_decodes_from_its_encoding() {
        let verdicts = [
            Verdict::Register(Registered {
                space: SpaceId([1; 32]),
                clock: WindowClock::DEFAULT,
                controller: [2; 32],
                start_window: 3,
                keys: vec![[4; 32], [5; 32]],
            }),
            Verdict::Migrate {
                space: SpaceId([1; 32]),
                from_window: 7,
                controller: [2; 32],
            },
            Verdict::Anchor {
                space: SpaceId([1; 32]),
                window: 8,
                kind: RootKind::Space,
                root: [9; 32],
                signer: [10; 32],
            },
            Verdict::Submit(Judged {
                id: [11; 32],
                program: [12; 32],
                space: SpaceId([1; 32]),
                roots: vec![Root {
                    kind: RootKind::Space,
                    window: 41,
                    root: [0x41; 32],
                }],
                code: 0,
            }),
            Verdict::Control {
                space: SpaceId([1; 32]),
                nonce: 9,
                op: Op::SetController([3; 32]),
                controller: [2; 32],
            },
            Verdict::Refused {
                kind: None,
                code: 1,
            },
            Verdict::Refused {
                kind: Some(Kind::Anchor),
                code: AnchorCode::Signature as u32,
            },
        ];
        for verdict in verdicts {
            let bytes = verdict.encode();
            assert_eq!(Verdict::decode_prefix(&bytes), Ok((verdict, bytes.len())));
        }
        assert!(Verdict::decode_prefix(&[5]).is_err());
    }
}
