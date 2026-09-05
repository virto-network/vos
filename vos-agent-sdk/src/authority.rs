//! Guest-verifiable authority receipt model.

use alloc::vec::Vec;

use crate::{
    ActorId, AgentId, BlobRef, DeploymentId, Hash, PrincipalId, ProducerId, ProgramId, SpaceId,
};

pub const AUTHORITY_PUBLIC_KEY_BYTES: usize = 32;
pub const AUTHORITY_SIGNATURE_BYTES: usize = 64;

/// Policy operation selected by an authority receipt. Tags are stable wire
/// values; unknown tags fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityOperationKind {
    CreateAgent = 0,
    InstallActor = 1,
    UpgradeActor = 2,
    SuspendActor = 3,
    ResumeActor = 4,
    RemoveActor = 5,
    UpgradeRuntime = 6,
    InvokeActor = 7,
    ChangeReplicaSet = 8,
    InvitePrivateNode = 9,
    RevokePrivateNode = 10,
    RecoverPrivateAgent = 11,
    PublishCatalog = 12,
}

impl AuthorityOperationKind {
    pub const fn requires_actor(self) -> bool {
        matches!(
            self,
            Self::InstallActor
                | Self::UpgradeActor
                | Self::SuspendActor
                | Self::ResumeActor
                | Self::RemoveActor
                | Self::InvokeActor
        )
    }
}

/// Exact visible authority actor which issued the receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorityIssuer {
    pub principal: PrincipalId,
    pub actor: ActorId,
    pub deployment: DeploymentId,
    pub program: ProgramId,
    pub producer: ProducerId,
}

impl AuthorityIssuer {
    pub fn is_valid(self) -> bool {
        self.principal.0 != PrincipalId::ZERO.0
            && self.actor.0 != ActorId::ZERO.0
            && self.deployment.0 != DeploymentId::ZERO.0
            && self.program.0 != ProgramId::ZERO.0
            && self.producer.0 != ProducerId::ZERO.0
    }
}

/// Relevant lane commitments selected at authorization time. Missing lanes
/// are explicit and cannot be confused with a zero root.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AuthorityLaneRoots {
    pub control: Option<Hash>,
    pub linear: Option<Hash>,
    pub merge: Option<Hash>,
    pub local: Option<Hash>,
}

impl AuthorityLaneRoots {
    pub fn is_valid(self) -> bool {
        option_hash_valid(self.control)
            && option_hash_valid(self.linear)
            && option_hash_valid(self.merge)
            && option_hash_valid(self.local)
    }
}

fn option_hash_valid(value: Option<Hash>) -> bool {
    match value {
        Some(value) => value.0 != Hash::ZERO.0,
        None => true,
    }
}

/// Optional package/proof objects plus the mandatory complete evidence
/// commitment used by the policy decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityEvidence {
    pub package: Option<BlobRef>,
    pub proof: Option<BlobRef>,
    pub commitment: Hash,
}

impl AuthorityEvidence {
    pub fn is_valid(&self) -> bool {
        self.commitment != Hash::ZERO
            && self.package.as_ref().is_none_or(valid_reference)
            && self.proof.as_ref().is_none_or(valid_reference)
    }
}

fn valid_reference(reference: &BlobRef) -> bool {
    reference.hash != Hash::ZERO
        && reference.len != 0
        && reference.len <= crate::MAX_CATALOG_ARTIFACT_BYTES
}

/// Complete policy selector signed by the authority actor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReceiptSelector {
    pub policy: Hash,
    pub issuer: AuthorityIssuer,
    pub space: SpaceId,
    pub agent: AgentId,
    pub operation: AuthorityOperationKind,
    pub runtime_deployment: DeploymentId,
    pub actor: Option<ActorId>,
    pub actor_deployment: Option<DeploymentId>,
    pub evidence: AuthorityEvidence,
    pub lane_roots: AuthorityLaneRoots,
    /// Monotonic policy/committee epoch.
    pub epoch: u64,
    /// First logical slot at which this decision may be consumed.
    pub valid_from: u64,
    /// Last logical slot at which this decision may be consumed, inclusive.
    pub expires_at: u64,
    /// Hash of the exact canonical request bytes authorized by this receipt.
    pub request: Hash,
}

impl AuthorityReceiptSelector {
    pub fn validate(&self) -> Result<(), AuthorityReceiptError> {
        if self.policy == Hash::ZERO
            || !self.issuer.is_valid()
            || self.space == SpaceId::ZERO
            || self.agent == AgentId::ZERO
            || self.runtime_deployment == DeploymentId::ZERO
            || self.request == Hash::ZERO
            || self.valid_from > self.expires_at
            || !self.evidence.is_valid()
            || !self.lane_roots.is_valid()
        {
            return Err(AuthorityReceiptError::InvalidSelector);
        }
        match (
            self.operation.requires_actor(),
            self.actor,
            self.actor_deployment,
        ) {
            (true, Some(actor), Some(deployment))
                if actor != ActorId::ZERO && deployment != DeploymentId::ZERO => {}
            (false, None, None) => {}
            _ => return Err(AuthorityReceiptError::InvalidSelector),
        }
        Ok(())
    }

    pub fn is_live_at(&self, logical_slot: u64) -> bool {
        logical_slot >= self.valid_from && logical_slot <= self.expires_at
    }
}

/// Signed, self-describing authority evidence. The verifier implementation is
/// supplied by the guest runtime so the SDK does not choose a cryptographic
/// provider or introduce host calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReceipt {
    pub selector: AuthorityReceiptSelector,
    pub public_key: [u8; AUTHORITY_PUBLIC_KEY_BYTES],
    pub signature: [u8; AUTHORITY_SIGNATURE_BYTES],
}

impl AuthorityReceipt {
    pub fn signing_bytes(&self) -> Vec<u8> {
        crate::wire::authority_signing_bytes(self)
    }

    pub fn commitment(&self) -> Hash {
        Hash::digest(
            b"vos/authority/receipt",
            &[&self.signing_bytes(), &self.signature],
        )
    }

    pub fn validate_shape(&self) -> Result<(), AuthorityReceiptError> {
        self.selector.validate()?;
        if self.public_key == [0; AUTHORITY_PUBLIC_KEY_BYTES]
            || self.signature == [0; AUTHORITY_SIGNATURE_BYTES]
        {
            return Err(AuthorityReceiptError::InvalidSignature);
        }
        if ProducerId::of_public_key(&self.public_key) != self.selector.issuer.producer {
            return Err(AuthorityReceiptError::WrongSigner);
        }
        Ok(())
    }

    pub fn verify_at<V: AuthorityVerifier>(
        &self,
        logical_slot: u64,
        verifier: &V,
    ) -> Result<(), AuthorityReceiptError> {
        self.validate_shape()?;
        if !self.selector.is_live_at(logical_slot) {
            return Err(AuthorityReceiptError::Expired);
        }
        if !verifier.verify(&self.public_key, &self.signing_bytes(), &self.signature) {
            return Err(AuthorityReceiptError::InvalidSignature);
        }
        Ok(())
    }
}

pub trait AuthorityVerifier {
    fn verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityReceiptError {
    InvalidSelector,
    WrongSigner,
    InvalidSignature,
    Expired,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selector(producer: ProducerId) -> AuthorityReceiptSelector {
        AuthorityReceiptSelector {
            policy: Hash([1; 32]),
            issuer: AuthorityIssuer {
                principal: PrincipalId([2; 32]),
                actor: ActorId([3; 32]),
                deployment: DeploymentId([4; 32]),
                program: ProgramId([5; 32]),
                producer,
            },
            space: SpaceId([6; 32]),
            agent: AgentId([7; 32]),
            operation: AuthorityOperationKind::InvokeActor,
            runtime_deployment: DeploymentId([8; 32]),
            actor: Some(ActorId([9; 32])),
            actor_deployment: Some(DeploymentId([10; 32])),
            evidence: AuthorityEvidence {
                package: None,
                proof: None,
                commitment: Hash([11; 32]),
            },
            lane_roots: AuthorityLaneRoots {
                linear: Some(Hash([12; 32])),
                ..AuthorityLaneRoots::default()
            },
            epoch: 4,
            valid_from: 20,
            expires_at: 30,
            request: Hash([13; 32]),
        }
    }

    #[test]
    fn selector_binds_actor_and_runtime_deployments() {
        let key = [14; 32];
        let value = selector(ProducerId::of_public_key(&key));
        assert_eq!(value.validate(), Ok(()));
        let mut missing_actor = value.clone();
        missing_actor.actor = None;
        assert_eq!(
            missing_actor.validate(),
            Err(AuthorityReceiptError::InvalidSelector)
        );
    }

    #[test]
    fn logical_expiry_is_inclusive_and_deterministic() {
        let key = [14; 32];
        let value = selector(ProducerId::of_public_key(&key));
        assert!(!value.is_live_at(19));
        assert!(value.is_live_at(20));
        assert!(value.is_live_at(30));
        assert!(!value.is_live_at(31));
    }
}
