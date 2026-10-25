//! Refine: an item's checks that read no state.
//!
//! - **A registration:** `vos_anchor::venue::registration`, the checks that
//!   read no state: its genesis of 1 to `MAX_FOUNDING_KEYS` distinct keys,
//!   none of small order, and a window length the venue registers; the
//!   signing key one of them, its signature over `register_digest` at this
//!   venue.
//! - **An anchor:** signed by the key it names over its digest at this
//!   venue; accumulate applies the anchor rule, the signature taken as
//!   verified here.
//! - **A control:** signed by the key it names over its digest at this
//!   venue; accumulate checks the key is the space's controller.
//! - **A statement:** at most [`MAX_STATEMENT_BYTES`] and [`MAX_ROOTS`]
//!   roots, decoding; then pin
//!   F's checks in order, but `anchored` and `seen`, which accumulate makes:
//!   the format, the program against this deployment's pins, the space
//!   rule, the io-hash and the id; then its proof,
//!   the item's first extrinsic, at most `MAX_PROOF_BYTES`, read only once
//!   the checks before it pass.
//!
//! A signature is verified with `verify_strict`, as the venue rules ask.
//! Refine reads no state, so it judges an anchor's signature before the
//! venue rules' space, status and key checks, which accumulate makes: an
//! anchor failing both a state check and its signature is refused
//! `Signature` here where another venue says the state's refusal. The
//! codes differ only when two faults coincide.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey};
use vos_statement::vos_anchor::RootRead;
use vos_statement::vos_anchor::venue::{self as rules, RegisterRefusal};
use vos_statement::vos_pvm_final_verifier::{self, MAX_PROOF_BYTES};
use vos_statement::{
    DecodeError, LINKED, ProgramId, Refusal, SpaceId, Statement, StatementId, Venue, VenueId, admit,
};

use crate::config::Config;
use crate::item::{Item, Kind, MAX_ROOTS, MAX_STATEMENT_BYTES, control_digest};
use crate::verdict::{AnchorCode, ControlCode, Judged, RegisterCode, Registered, Root, Verdict};

/// The item's extrinsics, which a `Submit` reads its proof from.
pub trait Extrinsics {
    /// The first extrinsic's length, if the item has one.
    fn proof_len(&mut self) -> Option<usize>;
    /// The first extrinsic's `len` bytes.
    fn proof(&mut self, len: usize) -> Vec<u8>;
}

/// The venue as refine sees it: the formats this build links; every root
/// anchored and no statement seen, which accumulate checks.
struct Stateless;

impl Venue for Stateless {
    fn accepts(&self, format: u32) -> bool {
        LINKED.contains(&format)
    }

    fn anchored(&self, _: &RootRead) -> bool {
        true
    }

    fn seen(&self, _: &StatementId) -> bool {
        false
    }
}

/// The venue's id for service `service` of `config`'s chain:
/// `VenueId::jam(genesis, service)`.
pub fn venue(config: &Config, service: u32) -> VenueId {
    VenueId::jam(&config.genesis, service)
}

/// Whether `signature` is `key`'s over `digest`.
fn signed(key: &[u8; 32], digest: &[u8; 32], signature: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(key).is_ok_and(|key| {
        key.verify_strict(digest, &Signature::from_bytes(signature))
            .is_ok()
    })
}

/// The verdict on `payload`, an item at `venue` ([`venue`]'s for the
/// running service).
pub fn refine(
    config: &Config,
    venue: VenueId,
    payload: &[u8],
    extrinsics: &mut impl Extrinsics,
) -> Verdict {
    let item = match Item::decode(payload) {
        Ok(item) => item,
        Err(_) => {
            let kind = payload.first().copied().and_then(Kind::from_u8);
            let code = match kind {
                Some(Kind::Anchor) => AnchorCode::Item as u32,
                Some(Kind::Control) => ControlCode::Item as u32,
                _ => RegisterCode::Item as u32,
            };
            return Verdict::Refused { kind, code };
        }
    };
    match item {
        Item::Register(register) => match rules::registration(
            &venue,
            &register.genesis,
            &register.controller,
            &register.founder_key,
            &register.signature,
            signed,
        ) {
            Ok(registration) => Verdict::Register(Registered {
                space: registration.space,
                clock: registration.clock,
                controller: register.controller,
                keys: registration.keys,
            }),
            Err(refusal) => Verdict::Refused {
                kind: Some(Kind::Register),
                code: register_code(refusal) as u32,
            },
        },
        Item::Anchor(anchor) => {
            if !signed(&anchor.signer, &anchor.digest(&venue), &anchor.signature) {
                return Verdict::Refused {
                    kind: Some(Kind::Anchor),
                    code: AnchorCode::Signature as u32,
                };
            }
            Verdict::Anchor {
                space: anchor.space,
                window: anchor.window,
                kind: anchor.kind,
                root: anchor.root,
                signer: anchor.signer,
            }
        }
        Item::Submit(bytes) => Verdict::Submit(judge(config, &bytes, extrinsics)),
        Item::Control(signed_control) => {
            let digest = control_digest(&venue, &signed_control.control);
            if !signed(
                &signed_control.controller,
                &digest,
                &signed_control.signature,
            ) {
                return Verdict::Refused {
                    kind: Some(Kind::Control),
                    code: ControlCode::Signature as u32,
                };
            }
            let control = signed_control.control;
            Verdict::Control {
                space: control.space,
                nonce: control.nonce,
                op: control.op,
                controller: signed_control.controller,
            }
        }
    }
}

/// The service's code of a registration's refusal.
pub fn register_code(refusal: RegisterRefusal) -> RegisterCode {
    match refusal {
        RegisterRefusal::Genesis | RegisterRefusal::Clock => RegisterCode::Genesis,
        RegisterRefusal::Founder => RegisterCode::Founder,
        RegisterRefusal::Exists => RegisterCode::Again,
    }
}

/// A statement's judgement at refine.
fn judge(config: &Config, bytes: &[u8], extrinsics: &mut impl Extrinsics) -> Judged {
    let statement = if bytes.len() > MAX_STATEMENT_BYTES {
        Err(DecodeError::Trailing)
    } else {
        Statement::decode(bytes).and_then(|statement| {
            if statement.roots.len() > MAX_ROOTS {
                return Err(DecodeError::Noncanonical);
            }
            Ok(statement)
        })
    };
    let statement = match statement {
        Ok(statement) => statement,
        Err(error) => {
            return Judged {
                id: [0; 32],
                program: [0; 32],
                space: SpaceId::NONE,
                roots: Vec::new(),
                code: Refusal::Statement(error).code(),
            };
        }
    };
    // A program it pins none for is refused as `admit` refuses another
    // program than the pinned one, after the format: no program id has a
    // word at `u32::MAX`.
    let program = if config.pins.contains(&statement.program) {
        statement.program
    } else {
        ProgramId([u32::MAX; 8])
    };
    let verdict = admit(&Stateless, &program, &statement).and_then(|admitted| {
        let proof = match extrinsics.proof_len() {
            Some(len) if len > MAX_PROOF_BYTES => {
                return Err(Refusal::Proof(vos_pvm_final_verifier::Error::Length));
            }
            Some(len) => extrinsics.proof(len),
            None => Vec::new(),
        };
        admitted.verify(&proof)
    });
    let code = vos_statement::code(&verdict);
    let roots = match verdict {
        Ok(_) => statement
            .roots
            .iter()
            .map(|root| Root {
                kind: root.kind,
                window: root.window,
                root: root.root,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    Judged {
        id: statement.id().0,
        program: statement.program.to_bytes(),
        space: statement.space,
        roots,
        code,
    }
}
