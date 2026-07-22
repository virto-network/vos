//! Canonical v2 role authority.
//!
//! This actor is an ordinary stateful PVM installed as its own root service.
//! It owns grants and revocation high-waters, verifies every mutation under
//! the space's genesis Ed25519 identity, and emits only an exact
//! invocation-scoped [`RoleAuthorizationClaimV2`] when the requested role is
//! currently live. The generic service's Accumulate receipt turns that reply
//! into the credential accepted by another root service.

use vos::prelude::*;
use vos::v2::{RoleAuthorityMutationV2, RoleAuthorizationClaimV2, SpaceId, V2Wire};

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct GrantRow {
    holder: vos::v2::Origin,
    role: u8,
    grant_epoch: u64,
    revoke_epoch: u64,
}

/// A package host can use this to construct the immutable initial actor state
/// committed by service genesis. Empty or malformed root identities produce
/// no state rather than an authority which could be claimed after install.
pub fn initial_state(space: SpaceId, root_peer_id: Vec<u8>) -> Option<Vec<u8>> {
    vos::registry::ed25519_pubkey_from_peer_id(&root_peer_id)?;
    Some(
        SpaceAuthority {
            space,
            root_peer_id,
            grants: Vec::new(),
        }
        .encode(),
    )
}

#[actor]
pub struct SpaceAuthority {
    space: SpaceId,
    root_peer_id: Vec<u8>,
    grants: Vec<GrantRow>,
}

#[messages]
impl SpaceAuthority {
    /// The empty constructor is fail-closed. Production installation supplies
    /// the encoded genesis state from [`initial_state`].
    fn new() -> Self {
        Self {
            space: SpaceId([0; 32]),
            root_peer_id: Vec::new(),
            grants: Vec::new(),
        }
    }

    /// Apply one root-signed grant or revoke. Epochs are strictly monotonic
    /// per holder, making retries idempotent and stale signed operations inert.
    #[msg]
    fn mutate_role(&mut self, mutation: Vec<u8>, signature: Vec<u8>) -> bool {
        let Ok(mutation) = RoleAuthorityMutationV2::decode(&mutation) else {
            return false;
        };
        if mutation.space() != self.space
            || !self.verify_root_signature(&mutation.encode(), &signature)
        {
            return false;
        }
        let holder = mutation.holder();
        let epoch = mutation.epoch();
        let index = self.grants.iter().position(|row| row.holder == holder);
        let current_epoch = index
            .map(|index| {
                self.grants[index]
                    .grant_epoch
                    .max(self.grants[index].revoke_epoch)
            })
            .unwrap_or(0);
        if epoch <= current_epoch {
            return false;
        }
        let index = match index {
            Some(index) => index,
            None => {
                self.grants.push(GrantRow {
                    holder,
                    role: SpaceRole::Guest.as_u8(),
                    grant_epoch: 0,
                    revoke_epoch: 0,
                });
                self.grants.len() - 1
            }
        };
        match mutation {
            RoleAuthorityMutationV2::Grant { role, .. } => {
                self.grants[index].role = role.as_u8();
                self.grants[index].grant_epoch = epoch;
            }
            RoleAuthorityMutationV2::Revoke { .. } => {
                self.grants[index].revoke_epoch = epoch;
            }
        }
        true
    }

    /// Return the exact claim bytes only when the current grant satisfies its
    /// threshold. The generated actor ABI frames this `Vec<u8>` as
    /// `Value::Bytes`; [`RoleAuthorizationClaimV2::authority_reply`] binds the
    /// same frame when validating the committed receipt.
    #[msg]
    fn authorize_role(&self, claim: Vec<u8>) -> Vec<u8> {
        let Ok(claim) = RoleAuthorizationClaimV2::decode(&claim) else {
            return Vec::new();
        };
        if claim.space != self.space || claim.audience.space != self.space {
            return Vec::new();
        }
        let Some(row) = self.grants.iter().find(|row| row.holder == claim.holder) else {
            return Vec::new();
        };
        let Some(granted) = SpaceRole::from_u8(row.role) else {
            return Vec::new();
        };
        if row.grant_epoch <= row.revoke_epoch || granted < claim.role {
            return Vec::new();
        }
        claim.encode()
    }

    fn verify_root_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        let Some(public_key) = vos::registry::ed25519_pubkey_from_peer_id(&self.root_peer_id)
        else {
            return false;
        };
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&public_key) else {
            return false;
        };
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        verifying_key
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use vos::abi::service::ServiceId;
    use vos::v2::{
        ActorId, DeploymentId, Hash, InvocationId, Origin, ProgramId, RootServiceId,
        ServiceIdentityV2, SubjectId,
    };
    use vos::{Decode, Message};

    fn root_peer(signing: &SigningKey) -> Vec<u8> {
        let mut peer = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        peer.extend_from_slice(signing.verifying_key().as_bytes());
        peer
    }

    fn claim(space: SpaceId, holder: Origin, role: SpaceRole) -> RoleAuthorizationClaimV2 {
        RoleAuthorizationClaimV2 {
            space,
            holder,
            role,
            audience: ServiceIdentityV2 {
                space,
                root_service: RootServiceId([3; 32]),
                deployment: DeploymentId([4; 32]),
                service_program: ProgramId([5; 32]),
                service_abi: vos::v2::ABI_VERSION,
                execution_semantics: vos::v2::EXECUTION_SEMANTICS_ID,
            },
            invocation: InvocationId([6; 32]),
            target: ActorId([7; 32]),
            method: "restricted".into(),
            policy: Hash([8; 32]),
        }
    }

    fn actor(space: SpaceId, signing: &SigningKey) -> SpaceAuthority {
        let bytes = initial_state(space, root_peer(signing)).unwrap();
        SpaceAuthority::decode(&bytes)
    }

    fn apply(
        actor: &mut SpaceAuthority,
        signing: &SigningKey,
        mutation: RoleAuthorityMutationV2,
    ) -> bool {
        let signature = signing.sign(&mutation.encode()).to_bytes().to_vec();
        dispatch(
            actor,
            MutateRole {
                mutation: mutation.encode(),
                signature,
            },
        )
    }

    fn dispatch<M>(actor: &mut SpaceAuthority, message: M) -> <SpaceAuthority as Message<M>>::Output
    where
        SpaceAuthority: Message<M>,
    {
        let mut context = Context::new(ServiceId(0));
        vos::block_on(<SpaceAuthority as Message<M>>::handle(
            actor,
            message,
            &mut context,
        ))
    }

    fn authorize(actor: &mut SpaceAuthority, claim: &RoleAuthorizationClaimV2) -> Vec<u8> {
        dispatch(
            actor,
            AuthorizeRole {
                claim: claim.encode(),
            },
        )
    }

    #[test]
    fn signed_grant_authorizes_exact_claim_and_threshold() {
        let signing = SigningKey::from_bytes(&[1; 32]);
        let space = SpaceId([2; 32]);
        let holder = Origin::Member(SubjectId([9; 32]));
        let mut actor = actor(space, &signing);
        assert!(apply(
            &mut actor,
            &signing,
            RoleAuthorityMutationV2::Grant {
                space,
                holder,
                role: SpaceRole::Developer,
                epoch: 1,
            },
        ));

        let member = claim(space, holder, SpaceRole::Member);
        assert_eq!(authorize(&mut actor, &member), member.encode());
        let admin = claim(space, holder, SpaceRole::Admin);
        assert!(authorize(&mut actor, &admin).is_empty());
    }

    #[test]
    fn revoke_and_stale_replay_fail_closed() {
        let signing = SigningKey::from_bytes(&[10; 32]);
        let attacker = SigningKey::from_bytes(&[11; 32]);
        let space = SpaceId([12; 32]);
        let holder = Origin::Actor(ActorId([13; 32]));
        let grant = RoleAuthorityMutationV2::Grant {
            space,
            holder,
            role: SpaceRole::Admin,
            epoch: 4,
        };
        let mut actor = actor(space, &signing);
        assert!(!apply(&mut actor, &attacker, grant.clone()));
        assert!(apply(&mut actor, &signing, grant.clone()));
        assert!(apply(
            &mut actor,
            &signing,
            RoleAuthorityMutationV2::Revoke {
                space,
                holder,
                epoch: 5,
            },
        ));
        assert!(!apply(&mut actor, &signing, grant));
        assert!(authorize(&mut actor, &claim(space, holder, SpaceRole::Member)).is_empty());
    }

    #[test]
    fn empty_default_state_cannot_be_claimed() {
        let signing = SigningKey::from_bytes(&[14; 32]);
        let space = SpaceId([15; 32]);
        let holder = Origin::Member(SubjectId([16; 32]));
        let mutation = RoleAuthorityMutationV2::Grant {
            space,
            holder,
            role: SpaceRole::Admin,
            epoch: 1,
        };
        let mut actor = SpaceAuthority::new();
        assert!(!apply(&mut actor, &signing, mutation));
        assert!(authorize(&mut actor, &claim(space, holder, SpaceRole::Guest)).is_empty());
    }
}
