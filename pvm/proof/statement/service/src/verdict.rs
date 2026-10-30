//! What refine hands accumulate for an item ([`Verdict`]), and the codes an
//! item's outcome reports.
//!
//! Refine reads no state: it checks what an item's own bytes show (a
//! signature, a genesis, a statement's checks but `anchored` and `seen`, a
//! proof) and names what accumulate must check against the service's state
//! (the signer, the space, the window, the roots). An item refine refuses
//! reaches accumulate as its refusal, which accumulate records.

use alloc::vec::Vec;

use vos_statement::DecodeError;
use vos_statement::vos_anchor::codec::{self, Reader};
use vos_statement::vos_anchor::venue::{AnchorRefusal, RegisterRefusal};
use vos_statement::vos_anchor::{RootKind, RootRead, SpaceId, WindowClock};

use crate::item::{Kind, Op};

/// What a registration refine admitted names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    pub space: SpaceId,
    pub clock: WindowClock,
    pub controller: [u8; 32],
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

impl From<&RootRead> for Root {
    fn from(read: &RootRead) -> Self {
        Self {
            kind: read.kind,
            window: read.window,
            root: read.root,
        }
    }
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
    /// `vos_anchor::venue::seen_expiry` over its roots' windows.
    pub fn seen_expiry(&self, clock: &WindowClock) -> u64 {
        vos_statement::vos_anchor::venue::seen_expiry(
            clock,
            self.roots.iter().map(|root| root.window),
        )
    }
}

/// Refine's output for an item; tag 1 is retired, never reused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// A registration whose genesis and signature passed.
    Register(Registered),
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
    /// kind's ([`RegisterCode`], [`AnchorCode`], [`ControlCode`]).
    Refused { kind: Option<Kind>, code: u32 },
}

/// A verdict's tag, its first byte; 1 is retired, never reused. Not an
/// item's [`Kind`]: a control's verdict is 5 where its item is 4, and 4 is
/// a refusal's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Tag {
    Register = 0,
    Anchor = 2,
    Submit = 3,
    Refused = 4,
    Control = 5,
}

impl Tag {
    const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Register,
            2 => Self::Anchor,
            3 => Self::Submit,
            4 => Self::Refused,
            5 => Self::Control,
            _ => return None,
        })
    }
}

impl Verdict {
    /// Its encoding: a tag, then its fields; integers little-endian, a
    /// sequence a compact count before its items. At most
    /// [`crate::MAX_VERDICT_BYTES`] for an item refine takes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Register(registered) => {
                out.push(Tag::Register as u8);
                out.extend_from_slice(&registered.space.0);
                registered.clock.encode_to(&mut out);
                out.extend_from_slice(&registered.controller);
                codec::compact(&mut out, registered.keys.len() as u64);
                for key in &registered.keys {
                    out.extend_from_slice(key);
                }
            }
            Self::Anchor {
                space,
                window,
                kind,
                root,
                signer,
            } => {
                out.push(Tag::Anchor as u8);
                out.extend_from_slice(&space.0);
                out.extend_from_slice(&window.to_le_bytes());
                out.push(*kind as u8);
                out.extend_from_slice(root);
                out.extend_from_slice(signer);
            }
            Self::Submit(judged) => {
                out.push(Tag::Submit as u8);
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
                out.push(Tag::Control as u8);
                out.extend_from_slice(&space.0);
                out.extend_from_slice(&nonce.to_le_bytes());
                op.encode_to(&mut out);
                out.extend_from_slice(controller);
            }
            Self::Refused { kind, code } => {
                out.push(Tag::Refused as u8);
                out.push(Kind::encode_option(*kind));
                out.extend_from_slice(&code.to_le_bytes());
            }
        }
        out
    }

    /// The verdict at the start of `bytes`, and the bytes it takes.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), DecodeError> {
        let mut reader = Reader::new(bytes);
        let tag = Tag::from_u8(reader.u8()?).ok_or(DecodeError::Noncanonical)?;
        let verdict = match tag {
            Tag::Register => {
                let space = SpaceId(reader.array()?);
                let clock = WindowClock::decode_from(&mut reader)?;
                let controller = reader.array()?;
                let count = reader.count(32)?;
                let keys = (0..count)
                    .map(|_| reader.array())
                    .collect::<Result<_, _>>()?;
                Self::Register(Registered {
                    space,
                    clock,
                    controller,
                    keys,
                })
            }
            Tag::Anchor => Self::Anchor {
                space: SpaceId(reader.array()?),
                window: reader.u64()?,
                kind: RootKind::decode_from(&mut reader)?,
                root: reader.array()?,
                signer: reader.array()?,
            },
            Tag::Submit => {
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
            Tag::Refused => Self::Refused {
                kind: Kind::decode_option(reader.u8()?)?,
                code: reader.u32()?,
            },
            Tag::Control => Self::Control {
                space: SpaceId(reader.array()?),
                nonce: reader.u64()?,
                op: Op::decode_from(&mut reader)?,
                controller: reader.array()?,
            },
        };
        Ok((verdict, reader.used()))
    }

    /// The item kind it is of: none for an item that did not decode.
    pub fn kind(&self) -> Option<Kind> {
        match self {
            Self::Register(_) => Some(Kind::Register),
            Self::Anchor { .. } => Some(Kind::Anchor),
            Self::Submit(_) => Some(Kind::Submit),
            Self::Control { .. } => Some(Kind::Control),
            Self::Refused { kind, .. } => *kind,
        }
    }
}

/// An outcome's codes, a `#[repr(u32)]` enum, with the variant a code
/// names (`TryFrom<u32>`, the code back when it names none).
macro_rules! codes {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $($(#[$doc:meta])* $variant:ident = $code:literal,)+
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u32)]
        pub enum $name {
            $($(#[$doc])* $variant = $code,)+
        }

        impl TryFrom<u32> for $name {
            type Error = u32;

            fn try_from(code: u32) -> Result<Self, u32> {
                match code {
                    $($code => Ok(Self::$variant),)+
                    _ => Err(code),
                }
            }
        }
    };
}

codes! {
/// A registration's outcome (`vos_anchor::venue::RegisterRefusal`'s); 4, 6
/// and 7 are retired, never reused.
pub enum RegisterCode {
    Registered = 0,
    /// The item does not decode.
    Item = 1,
    /// A genesis of no founding key or more than `MAX_FOUNDING_KEYS`, a key
    /// twice or of small order, or a window length the venue does not
    /// register.
    Genesis = 2,
    /// The signing key is not one of the genesis's founding keys, or its
    /// signature does not verify.
    Founder = 3,
    /// The space is registered already, ended or not.
    Again = 5,
}
}

impl From<RegisterRefusal> for RegisterCode {
    fn from(refusal: RegisterRefusal) -> Self {
        match refusal {
            RegisterRefusal::Genesis | RegisterRefusal::Clock => Self::Genesis,
            RegisterRefusal::Founder => Self::Founder,
            RegisterRefusal::Exists => Self::Again,
        }
    }
}

codes! {
/// An anchor's outcome: `vos_anchor::venue::anchor`'s, and refine's.
pub enum AnchorCode {
    New = 0,
    /// The venue held that root already.
    Again = 1,
    Item = 2,
    Signature = 3,
    Unregistered = 4,
    /// The space ended: it equivocated.
    Ended = 5,
    /// The signer is not one of the space's anchor keys.
    Key = 6,
    /// At or before the last window anchored, or before the space's first.
    Window = 7,
    /// The space's open window or later, by the venue's clock.
    Open = 8,
    /// Past `MaxRootAge`.
    Age = 9,
    /// Another root of the space's kind at the window is held: kept as
    /// evidence, the space ended for good.
    Equivocation = 10,
}
}

impl From<AnchorRefusal> for AnchorCode {
    fn from(refusal: AnchorRefusal) -> Self {
        match refusal {
            AnchorRefusal::Unregistered => Self::Unregistered,
            AnchorRefusal::Stopped => Self::Ended,
            AnchorRefusal::Key => Self::Key,
            AnchorRefusal::Signature => Self::Signature,
            AnchorRefusal::Window => Self::Window,
            AnchorRefusal::Open => Self::Open,
            AnchorRefusal::Age => Self::Age,
        }
    }
}

codes! {
/// A control's outcome; 7 is retired, never reused.
pub enum ControlCode {
    Done = 0,
    Item = 1,
    Signature = 2,
    Unregistered = 3,
    /// The signer is not the space's controller.
    Controller = 4,
    /// Not the space's next nonce: a replay, or one out of order.
    Nonce = 5,
    /// A key listed already, `MAX_FOUNDING_KEYS` listed, or a key of small
    /// order, to add; one not listed to remove.
    Key = 6,
}
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
                keys: vec![[4; 32], [5; 32]],
            }),
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
        assert!(Verdict::decode_prefix(&[1]).is_err());
    }

    /// A code names its variant, and no variant another code.
    #[test]
    fn a_code_names_its_variant() {
        for code in 0..=11 {
            if let Ok(anchor) = AnchorCode::try_from(code) {
                assert_eq!(anchor as u32, code);
            }
            if let Ok(register) = RegisterCode::try_from(code) {
                assert_eq!(register as u32, code);
            }
            if let Ok(control) = ControlCode::try_from(code) {
                assert_eq!(control as u32, code);
            }
        }
        assert_eq!(AnchorCode::try_from(10), Ok(AnchorCode::Equivocation));
        assert_eq!(AnchorCode::try_from(11), Err(11));
        assert_eq!(RegisterCode::try_from(4), Err(4));
        assert_eq!(ControlCode::try_from(7), Err(7));
    }
}
