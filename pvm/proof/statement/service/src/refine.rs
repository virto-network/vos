//! Refine: an item's checks that read no state.
//!
//! - **A registration:** its genesis decodes, of 1 to `MAX_FOUNDING_KEYS`
//!   founding keys and a window length the venue registers; the signing
//!   key one of them, its signature over `register_digest` at this venue.
//! - **A migration:** away from this venue to another, signed by the key it
//!   names, which accumulate checks is the space's controller.
//! - **An anchor:** signed by the key it names over its digest at this
//!   venue; accumulate checks the key is one of the space's.
//! - **A control:** signed by the key it names over its digest at this
//!   venue; accumulate checks the key is the space's controller.
//! - **A statement:** at most [`MAX_STATEMENT_BYTES`] and [`MAX_ROOTS`]
//!   roots, decoding; then pin
//!   F's checks in order, but `anchored` and `seen`, which accumulate makes:
//!   the format, the program against this deployment's pins, the venue if
//!   venue-bound, the space rule, the io-hash and the id; then its proof,
//!   the item's first extrinsic, at most `MAX_PROOF_BYTES`, read only once
//!   the checks before it pass.
//!
//! A signature is verified with `verify_strict`, as the model venue does.

use alloc::vec::Vec;

use ed25519_dalek::{Signature, VerifyingKey};
use vos_statement::vos_anchor::{MAX_FOUNDING_KEYS, RootRead, register_digest, space_id};
use vos_statement::vos_pvm_final_verifier::{self, MAX_PROOF_BYTES};
use vos_statement::{
    DecodeError, LINKED, Pin, ProgramId, Refusal, SpaceId, Statement, StatementId, Venue, VenueId,
    admit,
};

use crate::config::Config;
use crate::item::{Item, Kind, MAX_ROOTS, MAX_STATEMENT_BYTES, control_digest, migrate_digest};
use crate::verdict::{
    AnchorCode, ControlCode, Judged, MigrateCode, RegisterCode, Registered, Root, Verdict,
};

/// The item's extrinsics, which a `Submit` reads its proof from.
pub trait Extrinsics {
    /// The first extrinsic's length, if the item has one.
    fn proof_len(&mut self) -> Option<usize>;
    /// The first extrinsic's `len` bytes.
    fn proof(&mut self, len: usize) -> Vec<u8>;
}

/// The venue as refine sees it: its id and the formats this build links;
/// every root anchored and no statement seen, which accumulate checks.
struct Stateless {
    venue: VenueId,
}

impl Venue for Stateless {
    fn id(&self) -> VenueId {
        self.venue
    }

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
                Some(Kind::Migrate) => MigrateCode::Item as u32,
                Some(Kind::Control) => ControlCode::Item as u32,
                _ => RegisterCode::Item as u32,
            };
            return Verdict::Refused { kind, code };
        }
    };
    match item {
        Item::Register(register) => {
            let refused = |code: RegisterCode| Verdict::Refused {
                kind: Some(Kind::Register),
                code: code as u32,
            };
            let genesis = &register.genesis;
            if genesis.nodes.len() > MAX_FOUNDING_KEYS || !genesis.clock.registrable() {
                return refused(RegisterCode::Genesis);
            }
            let keys: Vec<[u8; 32]> = genesis.nodes.iter().map(|(_, key)| *key).collect();
            if !keys.contains(&register.founder_key) {
                return refused(RegisterCode::Founder);
            }
            let space = space_id(genesis);
            let digest =
                register_digest(&venue, &space, &register.controller, register.start_window);
            if !signed(&register.founder_key, &digest, &register.signature) {
                return refused(RegisterCode::Signature);
            }
            Verdict::Register(Registered {
                space,
                clock: genesis.clock,
                controller: register.controller,
                start_window: register.start_window,
                keys,
            })
        }
        Item::Migrate(signed_migrate) => {
            let refused = |code: MigrateCode| Verdict::Refused {
                kind: Some(Kind::Migrate),
                code: code as u32,
            };
            let migrate = &signed_migrate.migrate;
            if migrate.from != venue || migrate.to == venue {
                return refused(MigrateCode::Venue);
            }
            let digest = migrate_digest(migrate);
            if !signed(
                &signed_migrate.controller,
                &digest,
                &signed_migrate.signature,
            ) {
                return refused(MigrateCode::Signature);
            }
            Verdict::Migrate {
                space: migrate.space,
                from_window: migrate.from_window,
                controller: signed_migrate.controller,
            }
        }
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
        Item::Submit(bytes) => Verdict::Submit(judge(config, venue, &bytes, extrinsics)),
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

/// A statement's judgement at refine.
fn judge(
    config: &Config,
    venue: VenueId,
    bytes: &[u8],
    extrinsics: &mut impl Extrinsics,
) -> Judged {
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
    let pin = config.pin(&statement.program).unwrap_or(Pin {
        program: ProgramId([u32::MAX; 8]),
        venue_bound: false,
    });
    let verdict = admit(&Stateless { venue }, &pin, &statement).and_then(|admitted| {
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
