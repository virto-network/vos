//! Canonical v2 role authority.
//!
//! This actor is an ordinary stateful PVM installed as its own root service.
//! It owns grants and revocation high-waters, verifies every mutation under
//! the space's genesis Ed25519 identity, and emits only an exact
//! invocation-scoped [`RoleAuthorizationClaimV2`] when the requested role is
//! currently live. The generic service's Accumulate receipt turns that reply
//! into the credential accepted by another root service.

use vos::prelude::*;
use vos::registry::{invite_signed_bytes, role_grant_supersedes};
use vos::v2::{
    Origin, RoleAuthorityInviteRedemptionV2, RoleAuthorityInviteRevocationV2,
    RoleAuthorityMutationV2, RoleAuthorizationClaimV2, SpaceId, SubjectId, V2Wire,
};

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct GrantRow {
    holder_kind: u8,
    holder: [u8; 32],
    role: u8,
    grant_epoch: u64,
    revoke_epoch: u64,
    grantor_kind: u8,
    grantor: [u8; 32],
    /// Exact PeerId bytes used by the registry's canonical equal-epoch
    /// ordering. `grantor` remains the compact authorization identity.
    grantor_peer_id: Vec<u8>,
}

/// A package host can use this to construct the immutable initial actor state
/// committed by service genesis. Empty or malformed root identities produce
/// no state rather than an authority which could be claimed after install.
pub fn initial_state(
    space: SpaceId,
    root_peer_id: Vec<u8>,
    authority_replication_id: [u8; 32],
) -> Option<Vec<u8>> {
    vos::registry::ed25519_pubkey_from_peer_id(&root_peer_id)?;
    (authority_replication_id != [0; 32]).then_some(())?;
    let root = vos::v2::SubjectId::of_authenticated_peer(&root_peer_id);
    let root_grantor_peer_id = root_peer_id.clone();
    Some(
        SpaceAuthority {
            space: space.0,
            authority_replication_id,
            root_peer_id,
            revoked_invites: Vec::new(),
            grants: vec![GrantRow {
                holder_kind: 0,
                holder: root.0,
                role: SpaceRole::Admin.as_u8(),
                grant_epoch: 1,
                revoke_epoch: 0,
                grantor_kind: 0,
                grantor: root.0,
                grantor_peer_id: root_grantor_peer_id,
            }],
        }
        .encode(),
    )
}

#[actor]
pub struct SpaceAuthority {
    space: [u8; 32],
    authority_replication_id: [u8; 32],
    root_peer_id: Vec<u8>,
    revoked_invites: Vec<[u8; 32]>,
    grants: Vec<GrantRow>,
}

#[messages]
impl SpaceAuthority {
    /// The empty constructor is fail-closed. Production installation supplies
    /// the encoded genesis state from [`initial_state`].
    fn new() -> Self {
        Self {
            space: [0; 32],
            authority_replication_id: [0; 32],
            root_peer_id: Vec::new(),
            revoked_invites: Vec::new(),
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
        if mutation.space().0 != self.space
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
            } => self.apply_grant(
                holder,
                role,
                epoch,
                self.root_origin(),
                self.root_peer_id.clone(),
            ),
            RoleAuthorityMutationV2::Revoke { holder, epoch, .. } => {
                self.apply_revoke(holder, epoch)
            }
        }
    }

    /// Apply an offline invite only after verifying the complete delegated
    /// chain: current admin → token → controlled node peer. Expiry is checked
    /// by the serving host before this deterministic method is admitted.
    #[msg]
    fn redeem_invite(&mut self, redemption: Vec<u8>) -> bool {
        let Ok(redemption) = RoleAuthorityInviteRedemptionV2::decode(&redemption) else {
            return false;
        };
        if redemption.space.0 != self.space
            || redemption.authority_replication_id != self.authority_replication_id
        {
            return false;
        }
        if self
            .revoked_invites
            .binary_search(&redemption.token_pub)
            .is_ok()
        {
            return false;
        }
        let grantor = redemption.grantor();
        if self.effective_role(grantor) != Some(SpaceRole::Admin) {
            return false;
        }
        let invite = invite_signed_bytes(
            &redemption.space.0,
            redemption.role.as_u8(),
            redemption.expires_at,
            &redemption.token_pub,
            Some(&redemption.authority_replication_id),
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
            redemption.admin_peer_id,
        )
    }

    /// Permanently cancel an offline bearer. The authority authenticates the
    /// admin independently of the legacy registry and stores a sorted,
    /// grow-only token set, so replay and merge order cannot resurrect it.
    #[msg]
    fn revoke_invite(&mut self, revocation: Vec<u8>, signature: Vec<u8>) -> bool {
        let Ok(revocation) = RoleAuthorityInviteRevocationV2::decode(&revocation) else {
            return false;
        };
        if revocation.space.0 != self.space
            || self.effective_role(revocation.grantor()) != Some(SpaceRole::Admin)
        {
            return false;
        }
        let Ok(signature) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        if !Self::verify_peer_signature(&revocation.admin_peer_id, &revocation.encode(), &signature)
        {
            return false;
        }
        if let Err(index) = self.revoked_invites.binary_search(&revocation.token_pub) {
            self.revoked_invites.insert(index, revocation.token_pub);
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
        if claim.space.0 != self.space || claim.audience.space.0 != self.space {
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
        let holder = holder_key(holder)?;
        self.effective_role_inner(holder, &mut Vec::new())
    }

    fn effective_role_inner(
        &self,
        holder: (u8, [u8; 32]),
        seen: &mut Vec<(u8, [u8; 32])>,
    ) -> Option<SpaceRole> {
        if seen.contains(&holder) {
            return None;
        }
        seen.push(holder);
        let row = self
            .grants
            .iter()
            .find(|row| (row.holder_kind, row.holder) == holder)?;
        if row.grant_epoch <= row.revoke_epoch {
            return None;
        }
        let role = SpaceRole::from_u8(row.role)?;
        let root = holder_key(self.root_origin())?;
        let grantor = (row.grantor_kind, row.grantor);
        if holder == root {
            return (grantor == root).then_some(role);
        }
        (self.effective_role_inner(grantor, seen) == Some(SpaceRole::Admin)).then_some(role)
    }

    fn apply_grant(
        &mut self,
        holder: Origin,
        role: SpaceRole,
        epoch: u64,
        grantor: Origin,
        grantor_peer_id: Vec<u8>,
    ) -> bool {
        let Some((holder_kind, holder)) = holder_key(holder) else {
            return false;
        };
        let Some((grantor_kind, grantor)) = holder_key(grantor) else {
            return false;
        };
        let root = holder_key(self.root_origin());
        let grantor_identity = Origin::Member(SubjectId::of_authenticated_peer(&grantor_peer_id));
        let grantor_matches = if Some((grantor_kind, grantor)) == root {
            grantor_peer_id == self.root_peer_id
        } else {
            holder_key(grantor_identity) == Some((grantor_kind, grantor))
        };
        if !grantor_matches {
            return false;
        }
        let index = self
            .grants
            .iter()
            .position(|row| row.holder_kind == holder_kind && row.holder == holder);
        if let Some(index) = index {
            let row = &self.grants[index];
            if row.grant_epoch == epoch
                && row.role == role.as_u8()
                && row.grantor_kind == grantor_kind
                && row.grantor == grantor
                && row.grantor_peer_id == grantor_peer_id
            {
                return true;
            }
            if !role_grant_supersedes(
                epoch,
                &grantor_peer_id,
                row.grant_epoch,
                &row.grantor_peer_id,
                &self.root_peer_id,
            ) {
                // Valid but dominated evidence is an idempotent success in
                // both stores; callers must not retry it forever.
                return true;
            }
        }
        let index = match index {
            Some(index) => index,
            None => {
                self.grants.push(GrantRow {
                    holder_kind,
                    holder,
                    role: SpaceRole::Guest.as_u8(),
                    grant_epoch: 0,
                    revoke_epoch: 0,
                    grantor_kind,
                    grantor,
                    grantor_peer_id: grantor_peer_id.clone(),
                });
                self.grants.len() - 1
            }
        };
        self.grants[index].role = role.as_u8();
        self.grants[index].grant_epoch = epoch;
        self.grants[index].grantor_kind = grantor_kind;
        self.grants[index].grantor = grantor;
        self.grants[index].grantor_peer_id = grantor_peer_id;
        true
    }

    fn apply_revoke(&mut self, holder: Origin, epoch: u64) -> bool {
        let Some((holder_kind, holder)) = holder_key(holder) else {
            return false;
        };
        let index = self
            .grants
            .iter()
            .position(|row| row.holder_kind == holder_kind && row.holder == holder);
        let Some(root) = holder_key(self.root_origin()) else {
            return false;
        };
        let index = match index {
            Some(index) => index,
            None => {
                self.grants.push(GrantRow {
                    holder_kind,
                    holder,
                    role: SpaceRole::Guest.as_u8(),
                    grant_epoch: 0,
                    revoke_epoch: 0,
                    grantor_kind: root.0,
                    grantor: root.1,
                    grantor_peer_id: self.root_peer_id.clone(),
                });
                self.grants.len() - 1
            }
        };
        self.grants[index].revoke_epoch = self.grants[index].revoke_epoch.max(epoch);
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

fn holder_key(holder: vos::v2::Origin) -> Option<(u8, [u8; 32])> {
    match holder {
        vos::v2::Origin::Member(subject) => Some((0, subject.0)),
        vos::v2::Origin::Actor(actor) => Some((1, actor.0)),
        vos::v2::Origin::Anonymous | vos::v2::Origin::System => None,
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
                gas_schedule: vos::v2::GasScheduleV2::new(1_000_000_000, 5_000_000_000),
            },
            invocation: InvocationId([6; 32]),
            scope: Hash([17; 32]),
            target: ActorId([7; 32]),
            method: "restricted".into(),
            policy: Hash([8; 32]),
        }
    }

    fn actor(space: SpaceId, signing: &SigningKey) -> SpaceAuthority {
        let bytes = initial_state(space, root_peer(signing), [90; 32]).unwrap();
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
        let authority_replication_id = [90; 32];
        let token_pub = *token.verifying_key().as_bytes();
        let admin_peer_id = root_peer(admin);
        let holder_peer_id = root_peer(holder);
        let invite = invite_signed_bytes(
            &space.0,
            role.as_u8(),
            expires_at,
            &token_pub,
            Some(&authority_replication_id),
        );
        let redeem =
            vos::registry::canonical_op_bytes("redeem_invite", &[&token_pub, &holder_peer_id]);
        RoleAuthorityInviteRedemptionV2 {
            space,
            authority_replication_id,
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
        assert!(
            apply(&mut actor, &signing, grant),
            "valid but revoke-dominated evidence is idempotent"
        );
        assert!(authorize(&mut actor, &claim(space, holder, SpaceRole::Member)).is_empty());
    }

    #[test]
    fn root_grant_dominates_a_later_delegated_invite_in_registry_order() {
        let root = SigningKey::from_bytes(&[60; 32]);
        let admin = SigningKey::from_bytes(&[61; 32]);
        let token = SigningKey::from_bytes(&[62; 32]);
        let holder_key = SigningKey::from_bytes(&[63; 32]);
        let space = SpaceId([64; 32]);
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
        let root_grant = RoleAuthorityMutationV2::Grant {
            space,
            holder,
            role: SpaceRole::Developer,
            epoch: 3,
        };
        assert!(apply(&mut authority, &root, root_grant.clone()));

        let delegated = invite_redemption(
            space,
            &admin,
            &token,
            &holder_key,
            SpaceRole::Member,
            2_000_000_000,
        );
        assert!(
            redeem(&mut authority, &delegated),
            "valid dominated evidence is acknowledged instead of retried forever"
        );
        let developer = claim(space, holder, SpaceRole::Developer);
        assert_eq!(
            authorize(&mut authority, &developer),
            developer.encode(),
            "the delegated Unix expiry cannot displace a root grant"
        );
        assert!(
            apply(&mut authority, &root, root_grant),
            "registry-epoch repair remains idempotent after dominated evidence"
        );
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
        let mut wrong_incarnation = redemption.clone();
        wrong_incarnation.authority_replication_id[0] ^= 1;
        assert!(
            !redeem(&mut authority, &wrong_incarnation),
            "a direct actor call cannot replay a bearer from another authority incarnation"
        );
        assert!(redeem(&mut authority, &redemption));
        assert!(
            redeem(&mut authority, &redemption),
            "an exact retry is idempotent"
        );
        let developer = claim(space, holder, SpaceRole::Developer);
        assert_eq!(authorize(&mut authority, &developer), developer.encode());

        let second_holder_key = SigningKey::from_bytes(&[36; 32]);
        let second_holder = Origin::Member(SubjectId::of_authenticated_peer(&root_peer(
            &second_holder_key,
        )));
        let second_redemption = invite_redemption(
            space,
            &admin,
            &token,
            &second_holder_key,
            SpaceRole::Developer,
            50,
        );
        assert!(
            redeem(&mut authority, &second_redemption),
            "partitioned redemption of the same bearer token grants each proven holder"
        );
        let second_developer = claim(space, second_holder, SpaceRole::Developer);
        assert_eq!(
            authorize(&mut authority, &second_developer),
            second_developer.encode()
        );

        let revocation = RoleAuthorityInviteRevocationV2 {
            space,
            token_pub: *token.verifying_key().as_bytes(),
            admin_peer_id: root_peer(&admin),
        };
        let revoke_signature = admin.sign(&revocation.encode()).to_bytes().to_vec();
        assert!(dispatch(
            &mut authority,
            RevokeInvite {
                revocation: revocation.encode(),
                signature: revoke_signature.clone(),
            },
        ));
        assert!(
            dispatch(
                &mut authority,
                RevokeInvite {
                    revocation: revocation.encode(),
                    signature: revoke_signature,
                },
            ),
            "revocation replay is idempotent"
        );
        let blocked_holder = SigningKey::from_bytes(&[37; 32]);
        let blocked_redemption = invite_redemption(
            space,
            &admin,
            &token,
            &blocked_holder,
            SpaceRole::Developer,
            50,
        );
        assert!(
            !redeem(&mut authority, &blocked_redemption),
            "a grow-only revocation blocks later holders"
        );
        assert_eq!(
            authorize(&mut authority, &developer),
            developer.encode(),
            "invite revocation does not claw back an already committed grant"
        );

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
