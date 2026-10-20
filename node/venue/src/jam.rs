//! A JAM statements service as a node's venue ([`JamVenue`]), through
//! `vos_jam::live::statements`: each call an item in a work package of its
//! own, waited for until its outcome lands in the service's storage, about
//! two slots past the finalized block it was anchored at.
//!
//! Its answers are the service's (`vos_statement_service::verdict`'s
//! codes), mapped onto the trait's: a transport failure, or a package that
//! never lands, is an anchor's `Open` (refused for now: the representative's
//! leader tries it again) and a statement's [`Refusal::Format`]; a refused
//! proof keeps its class and its final verifier's code, but for a STARK's
//! refusal other than OODS or PoW, which reads as an invalid structure:
//! [`JamVenue::submit_code`] gives the service's code itself.

use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use vos_anchor::{Anchor, Migrate, RootRead, SpaceGenesis, SpaceId, VenueId, register_digest};
use vos_jam::Error;
use vos_jam::live::statements::{Item as Package, Statements};
use vos_statement::vos_pvm_final_verifier::Error as ProofError;
use vos_statement::{DecodeError, MAX_ROOT_AGE_MS, Refusal, Statement, StatementId};
use vos_statement_service::item::{Item, Register, SignedMigrate, migrate_digest};
use vos_statement_service::state::{AnchorRecord, Outcome, SpaceRecord, keys};
use vos_statement_service::verdict::{AnchorCode, MigrateCode, RegisterCode};

use crate::{AnchorRefusal, Anchored, MigrateRefusal, VenueClient};

/// How long an item's outcome may take to land.
pub const LANDING: Duration = Duration::from_secs(120);

/// A JAM statements service, as a node's venue.
pub struct JamVenue {
    pub statements: Statements,
    /// The JAM chain's genesis hash, which the venue's id hashes.
    pub genesis: [u8; 32],
}

impl JamVenue {
    /// The service `statements` of the chain whose genesis hash is
    /// `genesis`.
    pub fn new(statements: Statements, genesis: [u8; 32]) -> Self {
        Self {
            statements,
            genesis,
        }
    }

    /// One item, landed: its outcome.
    pub fn land(&self, payload: Vec<u8>, extrinsics: Vec<Vec<u8>>) -> Result<Outcome, Error> {
        let mut outcomes = self.statements.land(&[(payload, extrinsics)], LANDING)?;
        outcomes
            .pop()
            .ok_or_else(|| Error::Node("no outcome".into()))
    }

    /// Items landed together, in one package: each one's outcome.
    pub fn land_all(&self, items: &[Package]) -> Result<Vec<Outcome>, Error> {
        self.statements.land(items, LANDING)
    }

    /// Register the space `genesis` founds under `controller` (an ed25519
    /// key's 32 bytes), anchoring from `start_window`, signed by `founder`,
    /// one of its founding keys: the service's code
    /// (`RegisterCode`).
    pub fn register(
        &self,
        genesis: &SpaceGenesis,
        controller: [u8; 32],
        start_window: u64,
        founder: &SigningKey,
    ) -> Result<u32, Error> {
        let space = vos_anchor::space_id(genesis);
        let digest = register_digest(&self.id(), &space, &controller, start_window);
        let item = Item::Register(Register {
            genesis: genesis.clone(),
            controller,
            start_window,
            founder_key: founder.verifying_key().to_bytes(),
            signature: founder.sign(&digest).to_bytes(),
        });
        Ok(self.land(item.encode(), Vec::new())?.code)
    }

    /// A space's migration away from this venue, signed by its controller.
    pub fn migrate(
        &self,
        migrate: &Migrate,
        controller: &SigningKey,
    ) -> Result<(), MigrateRefusal> {
        let item = Item::Migrate(SignedMigrate {
            migrate: *migrate,
            controller: controller.verifying_key().to_bytes(),
            signature: controller.sign(&migrate_digest(migrate)).to_bytes(),
        });
        let code = self
            .land(item.encode(), Vec::new())
            .map_err(|_| MigrateRefusal::Window)?
            .code;
        match code {
            code if code == MigrateCode::Migrated as u32 => Ok(()),
            code if code == MigrateCode::Unregistered as u32 => Err(MigrateRefusal::Unregistered),
            code if code == MigrateCode::Venue as u32 => Err(MigrateRefusal::Venue),
            code if code == MigrateCode::AlreadyMigrated as u32 => {
                Err(MigrateRefusal::AlreadyMigrated)
            }
            _ => Err(MigrateRefusal::Window),
        }
    }

    /// Submit `statement` with its final proof as the item's extrinsic: the
    /// service's code (`vos_statement::code`'s) and the statement's id.
    pub fn submit_code(&self, statement: &Statement, proof: &[u8]) -> Result<u32, Error> {
        let payload = Item::Submit(statement.encode()).encode();
        Ok(self.land(payload, vec![proof.to_vec()])?.code)
    }

    /// The space `space` as the finalized block holds it.
    pub fn space(&self, space: &SpaceId) -> Result<Option<SpaceRecord>, Error> {
        Ok(self
            .statements
            .value(&keys::space(space))?
            .and_then(|bytes| SpaceRecord::decode(&bytes).ok()))
    }
}

/// The refusal a statement's code `code` names: its class, and a refused
/// proof's verifier code but for a STARK's refusals other than OODS and
/// PoW, which read as an invalid structure.
pub fn refusal(code: u32) -> Refusal {
    use stwo::core::verifier::VerificationError;
    match code {
        1 => Refusal::Statement(DecodeError::Noncanonical),
        3 => Refusal::Program,
        4 => Refusal::Space,
        5 => Refusal::Unanchored,
        6 => Refusal::Repeated,
        7 => Refusal::Venue,
        0x100..=0x1ff => Refusal::Proof(match code & 0xff {
            1 => ProofError::Decode,
            2 => ProofError::Length,
            3 => ProofError::PublicWords,
            4 => ProofError::Format,
            5 => ProofError::Circuit,
            6 => ProofError::Shape("the proof's shape, at the JAM venue"),
            7 => ProofError::Noncanonical,
            8 => ProofError::InteractionPow,
            9 => ProofError::Logup,
            0x13 => ProofError::Stark(VerificationError::OodsNotMatching),
            0x15 => ProofError::Stark(VerificationError::ProofOfWork),
            other => ProofError::Stark(VerificationError::InvalidStructure(format!(
                "the JAM venue's code {:#x}",
                0x100 | other
            ))),
        }),
        _ => Refusal::Format,
    }
}

impl VenueClient for JamVenue {
    fn id(&self) -> VenueId {
        let service = u32::try_from(self.statements.service).unwrap_or(u32::MAX);
        VenueId::jam(&self.genesis, service)
    }

    fn anchor(&self, anchor: &Anchor) -> Result<Anchored, AnchorRefusal> {
        let payload = Item::Anchor(*anchor).encode();
        let Ok(outcome) = self.land(payload, Vec::new()) else {
            return Err(AnchorRefusal::Open);
        };
        let codes = [
            (AnchorCode::New, Ok(Anchored::New)),
            (AnchorCode::Again, Ok(Anchored::Again)),
            (AnchorCode::Item, Err(AnchorRefusal::Signature)),
            (AnchorCode::Signature, Err(AnchorRefusal::Signature)),
            (AnchorCode::Unregistered, Err(AnchorRefusal::Unregistered)),
            (AnchorCode::Suspended, Err(AnchorRefusal::Suspended)),
            (AnchorCode::Key, Err(AnchorRefusal::Key)),
            (AnchorCode::Window, Err(AnchorRefusal::Window)),
            (AnchorCode::Open, Err(AnchorRefusal::Open)),
            (AnchorCode::Age, Err(AnchorRefusal::Age)),
            (AnchorCode::Equivocation, Err(AnchorRefusal::Equivocation)),
        ];
        codes
            .into_iter()
            .find(|(code, _)| *code as u32 == outcome.code)
            .map_or(Err(AnchorRefusal::Open), |(_, answer)| answer)
    }

    fn submit(&self, statement: &Statement, proof: &[u8]) -> Result<StatementId, Refusal> {
        match self.submit_code(statement, proof) {
            Ok(0) => Ok(statement.id()),
            Ok(code) => Err(refusal(code)),
            Err(_) => Err(Refusal::Format),
        }
    }

    fn anchored(&self, root: &RootRead) -> bool {
        let Ok(Some(space)) = self.space(&root.space) else {
            return false;
        };
        let Ok(now) = self.statements.now() else {
            return false;
        };
        let fresh = space
            .clock
            .boundary(root.window)
            .and_then(|boundary| boundary.checked_add(MAX_ROOT_AGE_MS))
            .is_some_and(|last| now <= last);
        let held = self
            .statements
            .value(&keys::anchor(&root.space, root.kind, root.window))
            .ok()
            .flatten()
            .and_then(|bytes| AnchorRecord::decode(&bytes).ok())
            .is_some_and(|held| held.root == root.root);
        !space.suspended && space.range.contains(root.window) && fresh && held
    }

    fn anchor_keys(&self, space: &SpaceId) -> Vec<[u8; 32]> {
        self.space(space)
            .ok()
            .flatten()
            .map(|space| space.keys)
            .unwrap_or_default()
    }
}

/// A registration's code read as its name, for a record.
pub fn register_code(code: u32) -> &'static str {
    [
        (RegisterCode::Registered, "registered"),
        (RegisterCode::Item, "undecodable"),
        (RegisterCode::Genesis, "genesis"),
        (RegisterCode::Founder, "not a founder"),
        (RegisterCode::Signature, "signature"),
        (RegisterCode::Again, "registered already"),
        (RegisterCode::Start, "start window"),
        (RegisterCode::Clock, "before the clock's origin"),
    ]
    .into_iter()
    .find(|(named, _)| *named as u32 == code)
    .map_or("unknown", |(_, name)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each class's code reads back as a refusal of that code; a STARK's
    /// OODS and PoW refusals too.
    #[test]
    fn a_code_reads_as_its_refusal() {
        for code in [
            1, 3, 4, 5, 6, 7, 0x101, 0x102, 0x104, 0x106, 0x108, 0x109, 0x113, 0x115,
        ] {
            assert_eq!(refusal(code).code(), code, "{code:#x}");
        }
        assert_eq!(refusal(0x112).code() >> 8, 1, "a proof's class");
    }
}
