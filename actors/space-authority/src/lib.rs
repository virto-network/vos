//! Canonical v2 role authority.
//!
//! This actor is an ordinary stateful PVM installed as its own root service.
//! It owns grants and revocation high-waters, verifies every mutation under
//! the space's genesis Ed25519 identity, and emits only an exact
//! invocation-scoped [`RoleAuthorizationClaimV2`] when the requested role is
//! currently live. The generic service's Accumulate receipt turns that reply
//! into the credential accepted by another root service.

use vos::prelude::*;
use vos::v2::{
    Origin, RoleAuthorityInviteRedemptionV2, RoleAuthorityMutationV2, RoleAuthorizationClaimV2,
    SpaceId, SubjectId, V2Wire,
};

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct GrantRow {
    holder: vos::v2::Origin,
    role: u8,
    grant_epoch: u64,
    revoke_epoch: u64,
    grantor: vos::v2::Origin,
}

/// A package host can use this to construct the immutable initial actor state
/// committed by service genesis. Empty or malformed root identities produce
/// no state rather than an authority which could be claimed after install.
pub fn initial_state(space: SpaceId, root_peer_id: Vec<u8>) -> Option<Vec<u8>> {
    vos::registry::ed25519_pubkey_from_peer_id(&root_peer_id)?;
    let root = Origin::Member(SubjectId::of_authenticated_peer(&root_peer_id));
    Some(
        SpaceAuthority {
            space,
            root_peer_id,
            grants: vec![GrantRow {
                holder: root,
                role: SpaceRole::Admin.as_u8(),
                grant_epoch: 1,
                revoke_epoch: 0,
                grantor: root,
            }],
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
        match mutation {
            RoleAuthorityMutationV2::Grant {
                holder,
                role,
                epoch,
                ..
            } => self.apply_grant(holder, role, epoch, self.root_origin()),
            RoleAuthorityMutationV2::Revoke { holder, epoch, .. } => {
                self.apply_revoke(holder, epoch)
            }
        }
    }

    /// Apply an offline invite only after verifying the same delegated chain
    /// as the legacy registry admission: current admin → token → controlled
    /// node peer. Expiry is checked by the serving host before this
    /// deterministic method is admitted and is never consulted during replay.
    #[msg]
    fn redeem_invite(&mut self, redemption: Vec<u8>) -> bool {
        let Ok(redemption) = RoleAuthorityInviteRedemptionV2::decode(&redemption) else {
            return false;
        };
        if redemption.space != self.space {
            return false;
        }
        let grantor = redemption.grantor();
        if self.effective_role(grantor) != Some(SpaceRole::Admin) {
            return false;
        }
        let invite = vos::registry::canonical_op_bytes(
            "invite",
            &[
                &redemption.space.0,
                &[redemption.role.as_u8()],
                &redemption.expires_at.to_le_bytes(),
                &redemption.token_pub,
            ],
        );
        if !Self::verify_peer_signature(
            &redemption.admin_peer_id,
            &invite,
            &redemption.admin_signature,
        ) {
            return false;
        }
        let redeem = vos::registry::canonical_op_bytes(
            "redeem_invite",
            &[&redemption.token_pub, &redemption.holder_peer_id],
        );
        if !Self::verify_raw_signature(&redemption.token_pub, &redeem, &redemption.redeem_signature)
            || !Self::verify_peer_signature(
                &redemption.holder_peer_id,
                &redeem,
                &redemption.holder_signature,
            )
        {
            return false;
        }
        self.apply_grant(
            redemption.holder(),
            redemption.role,
            redemption.expires_at,
            grantor,
        )
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
        let Some(granted) = self.effective_role(claim.holder) else {
            return Vec::new();
        };
        if granted < claim.role {
            return Vec::new();
        }
        claim.encode()
    }

    fn root_origin(&self) -> Origin {
        Origin::Member(SubjectId::of_authenticated_peer(&self.root_peer_id))
    }

    fn effective_role(&self, holder: Origin) -> Option<SpaceRole> {
        self.effective_role_inner(holder, &mut Vec::new())
    }

    fn effective_role_inner(&self, holder: Origin, seen: &mut Vec<Origin>) -> Option<SpaceRole> {
        if seen.contains(&holder) {
            return None;
        }
        seen.push(holder);
        let row = self.grants.iter().find(|row| row.holder == holder)?;
        if row.grant_epoch <= row.revoke_epoch {
            return None;
        }
        let role = SpaceRole::from_u8(row.role)?;
        let root = self.root_origin();
        if holder == root {
            return (row.grantor == root).then_some(role);
        }
        (self.effective_role_inner(row.grantor, seen) == Some(SpaceRole::Admin)).then_some(role)
    }

    fn apply_grant(
        &mut self,
        holder: Origin,
        role: SpaceRole,
        epoch: u64,
        grantor: Origin,
    ) -> bool {
        let index = self.grants.iter().position(|row| row.holder == holder);
        if let Some(index) = index {
            let row = &self.grants[index];
            let current_epoch = row.grant_epoch.max(row.revoke_epoch);
            if epoch < current_epoch {
                return false;
            }
            if epoch == current_epoch {
                return row.grant_epoch == epoch
                    && row.revoke_epoch < epoch
                    && row.role == role.as_u8()
                    && row.grantor == grantor;
            }
        }
        let index = match index {
            Some(index) => index,
            None => {
                self.grants.push(GrantRow {
                    holder,
                    role: SpaceRole::Guest.as_u8(),
                    grant_epoch: 0,
                    revoke_epoch: 0,
                    grantor,
                });
                self.grants.len() - 1
            }
        };
        self.grants[index].role = role.as_u8();
        self.grants[index].grant_epoch = epoch;
        self.grants[index].grantor = grantor;
        true
    }

    fn apply_revoke(&mut self, holder: Origin, epoch: u64) -> bool {
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
                    grantor: self.root_origin(),
                });
                self.grants.len() - 1
            }
        };
        self.grants[index].revoke_epoch = epoch;
        true
    }

    fn verify_root_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        Self::verify_peer_signature(&self.root_peer_id, message, &signature)
    }

    fn verify_peer_signature(peer_id: &[u8], message: &[u8], signature: &[u8; 64]) -> bool {
        let Some(public_key) = vos::registry::ed25519_pubkey_from_peer_id(peer_id) else {
            return false;
        };
        Self::verify_raw_signature(&public_key, message, signature)
    }

    fn verify_raw_signature(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        verifying_key
            .verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use vos::abi::service::ServiceId;
    use vos::v2::{
        ActorId, DeploymentId, Hash, InvocationId, ProgramId, RootServiceId, ServiceIdentityV2,
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

    fn invite_redemption(
        space: SpaceId,
        admin: &SigningKey,
        token: &SigningKey,
        holder: &SigningKey,
        role: SpaceRole,
        expires_at: u64,
    ) -> RoleAuthorityInviteRedemptionV2 {
        let token_pub = *token.verifying_key().as_bytes();
        let admin_peer_id = root_peer(admin);
        let holder_peer_id = root_peer(holder);
        let invite = vos::registry::canonical_op_bytes(
            "invite",
            &[
                &space.0,
                &[role.as_u8()],
                &expires_at.to_le_bytes(),
                &token_pub,
            ],
        );
        let redeem =
            vos::registry::canonical_op_bytes("redeem_invite", &[&token_pub, &holder_peer_id]);
        RoleAuthorityInviteRedemptionV2 {
            space,
            token_pub,
            role,
            expires_at,
            admin_peer_id,
            admin_signature: admin.sign(&invite).to_bytes(),
            holder_peer_id,
            redeem_signature: token.sign(&redeem).to_bytes(),
            holder_signature: holder.sign(&redeem).to_bytes(),
        }
    }

    fn redeem(actor: &mut SpaceAuthority, redemption: &RoleAuthorityInviteRedemptionV2) -> bool {
        dispatch(
            actor,
            RedeemInvite {
                redemption: redemption.encode(),
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
    fn initial_state_contains_an_explicit_root_admin_grant() {
        let signing = SigningKey::from_bytes(&[21; 32]);
        let peer = root_peer(&signing);
        let space = SpaceId([22; 32]);
        let mut authority = actor(space, &signing);
        let root = Origin::Member(SubjectId::of_authenticated_peer(&peer));
        let admin = claim(space, root, SpaceRole::Admin);
        assert_eq!(authorize(&mut authority, &admin), admin.encode());
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

    #[test]
    fn delegated_invite_grant_is_idempotent_and_tracks_its_admin() {
        let root = SigningKey::from_bytes(&[31; 32]);
        let admin = SigningKey::from_bytes(&[32; 32]);
        let token = SigningKey::from_bytes(&[33; 32]);
        let holder_key = SigningKey::from_bytes(&[34; 32]);
        let space = SpaceId([35; 32]);
        let admin_holder = Origin::Member(SubjectId::of_authenticated_peer(&root_peer(&admin)));
        let holder = Origin::Member(SubjectId::of_authenticated_peer(&root_peer(&holder_key)));
        let mut authority = actor(space, &root);
        assert!(apply(
            &mut authority,
            &root,
            RoleAuthorityMutationV2::Grant {
                space,
                holder: admin_holder,
                role: SpaceRole::Admin,
                epoch: 2,
            },
        ));

        let redemption =
            invite_redemption(space, &admin, &token, &holder_key, SpaceRole::Developer, 50);
        assert!(redeem(&mut authority, &redemption));
        assert!(
            redeem(&mut authority, &redemption),
            "an exact retry is idempotent"
        );
        let developer = claim(space, holder, SpaceRole::Developer);
        assert_eq!(authorize(&mut authority, &developer), developer.encode());

        assert!(apply(
            &mut authority,
            &root,
            RoleAuthorityMutationV2::Revoke {
                space,
                holder: admin_holder,
                epoch: 3,
            },
        ));
        assert!(
            authorize(&mut authority, &developer).is_empty(),
            "revoking the minting admin invalidates its delegated invite grants",
        );
    }

    #[test]
    fn invite_rejects_tampering_and_non_admin_minters() {
        let root = SigningKey::from_bytes(&[41; 32]);
        let stranger = SigningKey::from_bytes(&[42; 32]);
        let token = SigningKey::from_bytes(&[43; 32]);
        let holder = SigningKey::from_bytes(&[44; 32]);
        let space = SpaceId([45; 32]);
        let mut authority = actor(space, &root);
        let redemption =
            invite_redemption(space, &stranger, &token, &holder, SpaceRole::Member, 70);
        assert!(!redeem(&mut authority, &redemption));

        let mut tampered = invite_redemption(space, &root, &token, &holder, SpaceRole::Member, 70);
        tampered.holder_signature[0] ^= 1;
        assert!(!redeem(&mut authority, &tampered));
        tampered.holder_signature[0] ^= 1;
        tampered.space = SpaceId([46; 32]);
        assert!(!redeem(&mut authority, &tampered));
    }
}
