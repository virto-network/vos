//! Canonical service role authority.
//!
//! This actor is an ordinary stateful PVM installed as its own root service.
//! It owns grants and revocation high-waters, verifies every mutation under
//! the space's genesis Ed25519 identity, and emits only an exact
//! invocation-scoped [`RoleAuthorizationClaim`] when the requested role is
//! currently live. The generic service's Accumulate receipt turns that reply
//! into the credential accepted by another root service.

use vos::prelude::*;
use vos::registry::{invite_signed_bytes, role_grant_supersedes};
use vos::service::{
    Origin, RoleAuthorityInviteRedemption, RoleAuthorityInviteRevocation, RoleAuthorityMutation,
    RoleAuthorizationClaim, ServiceWire, SpaceId, SubjectId,
};
use vos::storage::StorageMap;
use vos::{
    CapabilityId, IngressAccessGrant, IngressAccessStatus, RoleId, SpaceMemberRoles,
    SpaceRoleDefinition, default_space_roles,
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

#[derive(
    vos::rkyv::Archive, vos::rkyv::Serialize, vos::rkyv::Deserialize, Debug, Clone, PartialEq, Eq,
)]
#[rkyv(crate = vos::rkyv)]
struct RoleRow {
    definition: SpaceRoleDefinition,
    epoch: u64,
    deleted: bool,
}

#[cfg(feature = "migration-fixture")]
static MIGRATION_FIXTURE_MARKER: u8 = 0x79;

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
    let root = vos::service::SubjectId::of_authenticated_peer(&root_peer_id);
    let root_grantor_peer_id = root_peer_id.clone();
    Some(
        SpaceAuthority {
            space: space.0,
            authority_replication_id,
            root_peer_id,
            revoked_invites: Vec::new(),
            roles: default_space_roles(space)
                .into_iter()
                .map(|definition| RoleRow {
                    definition,
                    epoch: 1,
                    deleted: false,
                })
                .collect(),
            member_roles: Vec::new(),
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
            access_grants: StorageMap::default(),
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
    roles: Vec<RoleRow>,
    member_roles: Vec<SpaceMemberRoles>,
    grants: Vec<GrantRow>,
    /// Protocol-neutral ingress credentials, one private point row per
    /// subject. Bearer secrets never enter this actor or its durable state.
    #[storage]
    access_grants: StorageMap<[u8; 32], IngressAccessGrant>,
}

#[messages]
impl SpaceAuthority {
    /// The empty constructor is fail-closed. Production installation supplies
    /// the encoded genesis state from [`initial_state`].
    fn new() -> Self {
        // Keep the physical authority-upgrade rehearsal on a genuinely
        // different executable without changing its signed contract or state
        // semantics. Production release builds never enable this feature.
        #[cfg(feature = "migration-fixture")]
        // SAFETY: this is a read-only byte with static lifetime. Volatility is
        // intentional so the migration fixture remains in the emitted PVM.
        let _ = unsafe { core::ptr::read_volatile(&MIGRATION_FIXTURE_MARKER) };
        Self {
            space: [0; 32],
            authority_replication_id: [0; 32],
            root_peer_id: Vec::new(),
            revoked_invites: Vec::new(),
            roles: Vec::new(),
            member_roles: Vec::new(),
            grants: Vec::new(),
            access_grants: StorageMap::default(),
        }
    }

    /// Issue one ingress credential for an exact set of roles. A delegating
    /// member may assign only roles below their own power and whose
    /// capabilities are already in their effective set. The immutable root
    /// bypasses that ceiling. Exact retries are idempotent.
    #[msg]
    fn issue_access(
        &mut self,
        credential_id: [u8; 32],
        roles: Vec<[u8; 32]>,
        expires_at: u64,
        ctx: &mut Context<Self>,
    ) -> Vec<u8> {
        let Origin::Member(issuer) = ctx.origin() else {
            return Vec::new();
        };
        let mut roles = roles;
        roles.sort_unstable();
        roles.dedup();
        if credential_id == [0; 32]
            || expires_at == 0
            || roles.is_empty()
            || roles.len() > vos::MAX_MEMBER_ROLES
            || !self.can_delegate_roles(Origin::Member(issuer), &roles)
        {
            return Vec::new();
        }
        let subject = SubjectId::of_ingress_credential(&credential_id);
        let candidate = IngressAccessGrant {
            credential_id,
            subject: subject.0,
            roles: roles.clone(),
            expires_at,
            issuer: issuer.0,
            epoch: 1,
            revoked: false,
        };
        if let Some(existing) = self.access_grants.get(&subject.0) {
            if existing != candidate {
                return Vec::new();
            }
        } else {
            self.access_grants.insert(&subject.0, &candidate);
        }
        IngressAccessStatus {
            credential_id,
            subject: subject.0,
            roles,
            capabilities: self.effective_capabilities(Origin::Member(subject)),
            power: self
                .effective_power(Origin::Member(subject))
                .unwrap_or_default(),
            expires_at,
        }
        .encode()
    }

    /// Revoke an ingress credential. Revocation is monotone and exact retries
    /// succeed so CLI recovery never needs the bearer secret.
    #[msg]
    fn revoke_access(&mut self, credential_id: [u8; 32], ctx: &mut Context<Self>) -> bool {
        let Origin::Member(issuer) = ctx.origin() else {
            return false;
        };
        if !self.has_capability(
            Origin::Member(issuer),
            CapabilityId::named(vos::capability::SPACE_CREDENTIALS_MANAGE),
        ) {
            return false;
        }
        let subject = SubjectId::of_ingress_credential(&credential_id);
        let Some(mut row) = self.access_grants.get(&subject.0) else {
            return true;
        };
        if row.credential_id != credential_id {
            return false;
        }
        row.revoked = true;
        row.epoch = row.epoch.saturating_add(1);
        self.access_grants.insert(&subject.0, &row);
        true
    }

    /// Return the current authority decision for a credential ID. The host
    /// separately checks `expires_at` against its trusted admission clock.
    #[msg]
    fn authenticate_access(&self, credential_id: [u8; 32]) -> Vec<u8> {
        let subject = SubjectId::of_ingress_credential(&credential_id);
        let Some(row) = self.access_grants.get(&subject.0) else {
            return Vec::new();
        };
        if row.credential_id != credential_id
            || row.revoked
            || self
                .effective_power(Origin::Member(SubjectId(row.issuer)))
                .is_none()
        {
            return Vec::new();
        }
        IngressAccessStatus {
            credential_id,
            subject: row.subject,
            roles: row.roles,
            capabilities: self.effective_capabilities(Origin::Member(subject)),
            power: self
                .effective_power(Origin::Member(subject))
                .unwrap_or_default(),
            expires_at: row.expires_at,
        }
        .encode()
    }

    /// Page ingress credentials for administration without exposing bearer
    /// secrets. The cursor is the previous subject bytes; empty starts at the
    /// first row.
    #[msg]
    fn list_access(
        &self,
        after: Vec<u8>,
        budget: u32,
        ctx: &mut Context<Self>,
    ) -> Vec<IngressAccessGrant> {
        let Origin::Member(caller) = ctx.origin() else {
            return Vec::new();
        };
        if !self.has_capability(
            Origin::Member(caller),
            CapabilityId::named(vos::capability::SPACE_CREDENTIALS_MANAGE),
        ) {
            return Vec::new();
        }
        let start: [u8; 32] = after.as_slice().try_into().unwrap_or([0; 32]);
        let skip = (after.len() == 32).then_some(start);
        self.access_grants
            .iter_from(&start)
            .filter(move |(key, _)| skip != Some(*key))
            .map(|(_, row)| row)
            .take((budget.clamp(1, 128)) as usize)
            .collect()
    }

    /// List the editable role catalogue. Role IDs are stable within this
    /// space and definitions are returned in canonical ID order.
    #[msg]
    fn list_roles(&self) -> Vec<SpaceRoleDefinition> {
        let mut roles: Vec<_> = self
            .roles
            .iter()
            .filter(|row| !row.deleted)
            .map(|row| row.definition.clone())
            .collect();
        roles.sort_by_key(|role| role.id);
        roles
    }

    /// Create or replace one role definition. Non-root managers may define
    /// only roles below their own power and may not delegate capabilities
    /// they do not possess.
    #[msg]
    fn put_role(&mut self, definition: Vec<u8>, epoch: u64, ctx: &mut Context<Self>) -> bool {
        let Origin::Member(caller) = ctx.origin() else {
            return false;
        };
        let Some(definition) = SpaceRoleDefinition::try_decode(&definition) else {
            return false;
        };
        let caller = Origin::Member(caller);
        if epoch == 0
            || !self.valid_role_definition(&definition)
            || !self.can_define_role(caller, &definition)
        {
            return false;
        }
        if let Some(row) = self
            .roles
            .iter_mut()
            .find(|row| row.definition.id == definition.id)
        {
            if row.epoch == epoch && row.definition == definition && !row.deleted {
                return true;
            }
            if row.epoch >= epoch {
                return false;
            }
            row.definition = definition;
            row.epoch = epoch;
            row.deleted = false;
        } else if self.roles.len() < vos::MAX_SPACE_ROLES {
            self.roles.push(RoleRow {
                definition,
                epoch,
                deleted: false,
            });
        } else {
            return false;
        }
        true
    }

    #[msg]
    fn delete_role(&mut self, role: [u8; 32], epoch: u64, ctx: &mut Context<Self>) -> bool {
        let Origin::Member(caller) = ctx.origin() else {
            return false;
        };
        let Some(index) = self.roles.iter().position(|row| row.definition.id == role) else {
            return true;
        };
        let definition = self.roles[index].definition.clone();
        if epoch == 0
            || self.roles[index].epoch > epoch
            || !self.can_define_role(Origin::Member(caller), &definition)
        {
            return false;
        }
        self.roles[index].epoch = epoch;
        self.roles[index].deleted = true;
        true
    }

    /// Replace a member's complete role set. The operation is monotone by
    /// member epoch and records the exact delegating subject.
    #[msg]
    fn set_member_roles(
        &mut self,
        subject: [u8; 32],
        roles: Vec<[u8; 32]>,
        epoch: u64,
        ctx: &mut Context<Self>,
    ) -> bool {
        let Origin::Member(grantor) = ctx.origin() else {
            return false;
        };
        let mut roles = roles;
        roles.sort_unstable();
        roles.dedup();
        if subject == [0; 32]
            || subject == self.root_subject().0
            || epoch == 0
            || roles.is_empty()
            || roles.len() > vos::MAX_MEMBER_ROLES
            || !self.can_delegate_roles(Origin::Member(grantor), &roles)
        {
            return false;
        }
        let candidate = SpaceMemberRoles {
            subject,
            grantor: grantor.0,
            roles,
            epoch,
            revoked: false,
        };
        if let Some(row) = self
            .member_roles
            .iter_mut()
            .find(|row| row.subject == subject)
        {
            if *row == candidate {
                return true;
            }
            if row.epoch >= epoch {
                return false;
            }
            *row = candidate;
        } else {
            self.member_roles.push(candidate);
        }
        true
    }

    #[msg]
    fn revoke_member_roles(
        &mut self,
        subject: [u8; 32],
        epoch: u64,
        ctx: &mut Context<Self>,
    ) -> bool {
        let Origin::Member(caller) = ctx.origin() else {
            return false;
        };
        if !self.has_capability(
            Origin::Member(caller),
            CapabilityId::named(vos::capability::SPACE_MEMBERS_MANAGE),
        ) {
            return false;
        }
        let Some(row) = self
            .member_roles
            .iter_mut()
            .find(|row| row.subject == subject)
        else {
            return true;
        };
        if row.epoch > epoch || epoch == 0 {
            return false;
        }
        row.epoch = epoch;
        row.revoked = true;
        true
    }

    #[msg]
    fn list_member_roles(&self) -> Vec<SpaceMemberRoles> {
        let mut rows = self.member_roles.clone();
        rows.sort_by_key(|row| row.subject);
        rows
    }

    /// Apply one root-signed grant or revoke. Epochs are strictly monotonic
    /// per holder, making retries idempotent and stale signed operations inert.
    #[msg]
    fn mutate_role(&mut self, mutation: Vec<u8>, signature: Vec<u8>) -> bool {
        let Ok(mutation) = RoleAuthorityMutation::decode(&mutation) else {
            return false;
        };
        if mutation.space().0 != self.space
            || !self.verify_root_signature(&mutation.encode(), &signature)
        {
            return false;
        }
        match mutation {
            RoleAuthorityMutation::Grant {
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
            RoleAuthorityMutation::Revoke { holder, epoch, .. } => self.apply_revoke(holder, epoch),
        }
    }

    /// Apply an offline invite only after verifying the complete delegated
    /// chain: current admin → token → controlled node peer. Expiry is checked
    /// by the serving host before this deterministic method is admitted.
    #[msg]
    fn redeem_invite(&mut self, redemption: Vec<u8>) -> bool {
        let Ok(redemption) = RoleAuthorityInviteRedemption::decode(&redemption) else {
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
            &redemption.authority_replication_id,
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
    /// admin independently of the catalog registry and stores a sorted,
    /// grow-only token set, so replay and merge order cannot resurrect it.
    #[msg]
    fn revoke_invite(&mut self, revocation: Vec<u8>, signature: Vec<u8>) -> bool {
        let Ok(revocation) = RoleAuthorityInviteRevocation::decode(&revocation) else {
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
    /// `Value::Bytes`; [`RoleAuthorizationClaim::authority_reply`] binds the
    /// same frame when validating the committed receipt.
    #[msg]
    fn authorize_role(&self, claim: Vec<u8>) -> Vec<u8> {
        let Ok(claim) = RoleAuthorizationClaim::decode(&claim) else {
            return Vec::new();
        };
        if claim.space.0 != self.space || claim.audience.space.0 != self.space {
            return Vec::new();
        }
        let authorized = match (claim.role, claim.capability) {
            (Some(required), None) => self
                .effective_role(claim.holder)
                .is_some_and(|granted| granted >= required),
            (None, Some(required)) => self.has_capability(claim.holder, required),
            _ => false,
        };
        if !authorized {
            return Vec::new();
        }
        claim.encode()
    }

    fn root_origin(&self) -> Origin {
        Origin::Member(self.root_subject())
    }

    fn root_subject(&self) -> SubjectId {
        SubjectId::of_authenticated_peer(&self.root_peer_id)
    }

    fn role_definition(&self, id: &[u8; 32]) -> Option<&SpaceRoleDefinition> {
        self.roles
            .iter()
            .find(|row| !row.deleted && &row.definition.id == id)
            .map(|row| &row.definition)
    }

    fn valid_role_definition(&self, role: &SpaceRoleDefinition) -> bool {
        let name = role.name.as_bytes();
        !name.is_empty()
            && name.len() <= 64
            && name[0].is_ascii_lowercase()
            && name.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(byte)
            })
            && role.id == RoleId::named(SpaceId(self.space), &role.name).0
            && role.capabilities.len() <= vos::MAX_ROLE_CAPABILITIES
            && role.capabilities.windows(2).all(|pair| pair[0] < pair[1])
    }

    fn can_define_role(&self, caller: Origin, role: &SpaceRoleDefinition) -> bool {
        if caller == self.root_origin() {
            return true;
        }
        let Some(power) = self.effective_power(caller) else {
            return false;
        };
        let capabilities = self.effective_capabilities(caller);
        self.has_capability(
            caller,
            CapabilityId::named(vos::capability::SPACE_ROLES_MANAGE),
        ) && role.power < power
            && role
                .capabilities
                .iter()
                .all(|capability| capabilities.binary_search(capability).is_ok())
    }

    fn authority_for_roles(&self, roles: &[[u8; 32]]) -> Option<(u16, Vec<[u8; 32]>)> {
        let mut power = 0;
        let mut capabilities = Vec::new();
        for role in roles {
            let role = self.role_definition(role)?;
            power = power.max(role.power);
            capabilities.extend_from_slice(&role.capabilities);
        }
        capabilities.sort_unstable();
        capabilities.dedup();
        Some((power, capabilities))
    }

    fn effective_member_authority_inner(
        &self,
        subject: SubjectId,
        seen: &mut Vec<[u8; 32]>,
    ) -> Option<(u16, Vec<[u8; 32]>)> {
        if subject == self.root_subject() {
            let mut capabilities = Vec::new();
            for row in self.roles.iter().filter(|row| !row.deleted) {
                capabilities.extend_from_slice(&row.definition.capabilities);
            }
            capabilities.sort_unstable();
            capabilities.dedup();
            return Some((u16::MAX, capabilities));
        }
        if seen.contains(&subject.0) {
            return None;
        }
        seen.push(subject.0);

        let (roles, grantor) = if let Some(access) = self.access_grants.get(&subject.0) {
            if access.revoked || access.subject != subject.0 {
                return None;
            }
            (access.roles, SubjectId(access.issuer))
        } else if let Some(assignment) = self
            .member_roles
            .iter()
            .find(|row| row.subject == subject.0 && !row.revoked)
        {
            (assignment.roles.clone(), SubjectId(assignment.grantor))
        } else {
            return None;
        };
        let (grantor_power, grantor_capabilities) =
            self.effective_member_authority_inner(grantor, seen)?;
        let (power, capabilities) = self.authority_for_roles(&roles)?;
        (power < grantor_power
            && capabilities
                .iter()
                .all(|capability| grantor_capabilities.binary_search(capability).is_ok()))
        .then_some((power, capabilities))
    }

    fn effective_member_authority(&self, subject: SubjectId) -> Option<(u16, Vec<[u8; 32]>)> {
        self.effective_member_authority_inner(subject, &mut Vec::new())
    }

    fn effective_power(&self, holder: Origin) -> Option<u16> {
        if let Origin::Member(subject) = holder
            && let Some((power, _)) = self.effective_member_authority(subject)
        {
            return Some(power);
        }
        self.effective_role(holder).map(|role| match role {
            SpaceRole::Guest => 0,
            SpaceRole::Member => 100,
            SpaceRole::Developer => 200,
            SpaceRole::Admin => 300,
        })
    }

    fn effective_capabilities(&self, holder: Origin) -> Vec<[u8; 32]> {
        if let Origin::Member(subject) = holder
            && let Some((_, capabilities)) = self.effective_member_authority(subject)
        {
            return capabilities;
        }
        let mut capabilities = Vec::new();
        if let Some(role) = self.effective_role(holder) {
            let name = role.name();
            let id = RoleId::named(SpaceId(self.space), name).0;
            if let Some(role) = self.role_definition(&id) {
                capabilities.extend_from_slice(&role.capabilities);
            }
        }
        capabilities.sort_unstable();
        capabilities.dedup();
        capabilities
    }

    fn has_capability(&self, holder: Origin, capability: CapabilityId) -> bool {
        self.effective_capabilities(holder)
            .binary_search(&capability.0)
            .is_ok()
    }

    fn can_delegate_roles(&self, issuer: Origin, roles: &[[u8; 32]]) -> bool {
        if issuer == self.root_origin() {
            return roles
                .iter()
                .all(|role| self.role_definition(role).is_some());
        }
        let Some(power) = self.effective_power(issuer) else {
            return false;
        };
        let capabilities = self.effective_capabilities(issuer);
        self.has_capability(
            issuer,
            CapabilityId::named(vos::capability::SPACE_CREDENTIALS_MANAGE),
        ) && roles.iter().all(|role| {
            self.role_definition(role).is_some_and(|role| {
                role.power < power
                    && role
                        .capabilities
                        .iter()
                        .all(|capability| capabilities.binary_search(capability).is_ok())
            })
        })
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
        if let Some(row) = self
            .grants
            .iter()
            .find(|row| (row.holder_kind, row.holder) == holder)
        {
            if row.grant_epoch <= row.revoke_epoch {
                return None;
            }
            let role = SpaceRole::from_u8(row.role)?;
            let root = holder_key(self.root_origin())?;
            let grantor = (row.grantor_kind, row.grantor);
            if holder == root {
                return (grantor == root).then_some(role);
            }
            return (self.effective_role_inner(grantor, seen) == Some(SpaceRole::Admin))
                .then_some(role);
        }
        if holder.0 != 0 {
            return None;
        }
        let row = self.access_grants.get(&holder.1)?;
        if row.revoked || row.subject != holder.1 {
            return None;
        }
        let issuer = (0, row.issuer);
        self.effective_role_inner(issuer, seen)?;
        let power = row
            .roles
            .iter()
            .filter_map(|role| self.role_definition(role).map(|role| role.power))
            .max()?;
        Some(if power >= 300 {
            SpaceRole::Admin
        } else if power >= 200 {
            SpaceRole::Developer
        } else if power >= 100 {
            SpaceRole::Member
        } else {
            SpaceRole::Guest
        })
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
                role.as_u8(),
                row.grant_epoch,
                &row.grantor_peer_id,
                row.role,
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

fn holder_key(holder: vos::service::Origin) -> Option<(u8, [u8; 32])> {
    match holder {
        vos::service::Origin::Member(subject) => Some((0, subject.0)),
        vos::service::Origin::Actor(actor) => Some((1, actor.0)),
        vos::service::Origin::Anonymous | vos::service::Origin::System => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use vos::abi::service::ServiceId;
    use vos::service::{
        ActorId, DeploymentId, Hash, InvocationId, Origin, ProgramId, RootServiceId,
        ServiceIdentity, SubjectId,
    };
    use vos::{Decode, Message};

    fn root_peer(signing: &SigningKey) -> Vec<u8> {
        let mut peer = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        peer.extend_from_slice(signing.verifying_key().as_bytes());
        peer
    }

    fn claim(space: SpaceId, holder: Origin, role: SpaceRole) -> RoleAuthorizationClaim {
        RoleAuthorizationClaim {
            space,
            holder,
            role: Some(role),
            capability: None,
            audience: ServiceIdentity {
                space,
                root_service: RootServiceId([3; 32]),
                deployment: DeploymentId([4; 32]),
                service_program: ProgramId([5; 32]),
                platform: vos::service::PLATFORM_ID,
                execution_semantics: vos::service::EXECUTION_SEMANTICS_ID,
                gas_schedule: vos::service::GasSchedule::new(1_000_000_000, 5_000_000_000),
            },
            invocation: InvocationId([6; 32]),
            scope: Hash([17; 32]),
            target: ActorId([7; 32]),
            method: "restricted".into(),
            policy: Hash([8; 32]),
        }
    }

    fn capability_claim(
        space: SpaceId,
        holder: Origin,
        capability: CapabilityId,
    ) -> RoleAuthorizationClaim {
        let mut claim = claim(space, holder, SpaceRole::Guest);
        claim.role = None;
        claim.capability = Some(capability);
        claim
    }

    fn actor(space: SpaceId, signing: &SigningKey) -> SpaceAuthority {
        let bytes = initial_state(space, root_peer(signing), [90; 32]).unwrap();
        let mut authority = SpaceAuthority::decode(&bytes);
        <SpaceAuthority as vos::Actor>::__init_storage(&mut authority);
        authority
    }

    fn apply(
        actor: &mut SpaceAuthority,
        signing: &SigningKey,
        mutation: RoleAuthorityMutation,
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

    fn dispatch_as<M>(
        actor: &mut SpaceAuthority,
        origin: Origin,
        message: M,
    ) -> <SpaceAuthority as Message<M>>::Output
    where
        SpaceAuthority: Message<M>,
    {
        let mut context = Context::new(ServiceId(0));
        context.__set_origin(origin, None);
        vos::block_on(<SpaceAuthority as Message<M>>::handle(
            actor,
            message,
            &mut context,
        ))
    }

    fn authorize(actor: &mut SpaceAuthority, claim: &RoleAuthorizationClaim) -> Vec<u8> {
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
    ) -> RoleAuthorityInviteRedemption {
        let authority_replication_id = [90; 32];
        let token_pub = *token.verifying_key().as_bytes();
        let admin_peer_id = root_peer(admin);
        let holder_peer_id = root_peer(holder);
        let invite = invite_signed_bytes(
            &space.0,
            role.as_u8(),
            expires_at,
            &token_pub,
            &authority_replication_id,
        );
        let redeem =
            vos::registry::canonical_op_bytes("redeem_invite", &[&token_pub, &holder_peer_id]);
        RoleAuthorityInviteRedemption {
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

    fn redeem(actor: &mut SpaceAuthority, redemption: &RoleAuthorityInviteRedemption) -> bool {
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
    fn ingress_access_is_authority_owned_revocable_and_role_bounded() {
        let signing = SigningKey::from_bytes(&[91; 32]);
        let peer = root_peer(&signing);
        let space = SpaceId([92; 32]);
        let root = Origin::Member(SubjectId::of_authenticated_peer(&peer));
        let mut authority = actor(space, &signing);
        let role = |name| vec![RoleId::named(space, name).0];

        let admin_id = [93; 32];
        let admin_bytes = dispatch_as(
            &mut authority,
            root,
            IssueAccess {
                credential_id: admin_id,
                roles: role("admin"),
                expires_at: 2_000_000_000,
            },
        );
        let admin = IngressAccessStatus::try_decode(&admin_bytes).expect("root issues admin");
        let admin_origin = Origin::Member(SubjectId(admin.subject));

        let developer_id = [94; 32];
        let developer = dispatch_as(
            &mut authority,
            admin_origin,
            IssueAccess {
                credential_id: developer_id,
                roles: role("developer"),
                expires_at: 2_000_000_001,
            },
        );
        assert!(IngressAccessStatus::try_decode(&developer).is_some());
        assert!(
            dispatch_as(
                &mut authority,
                admin_origin,
                IssueAccess {
                    credential_id: [95; 32],
                    roles: role("admin"),
                    expires_at: 2_000_000_002,
                },
            )
            .is_empty(),
            "only the immutable root may issue Admin ingress access",
        );

        let authenticated = dispatch(
            &mut authority,
            AuthenticateAccess {
                credential_id: developer_id,
            },
        );
        let authenticated = IngressAccessStatus::try_decode(&authenticated)
            .expect("issued credential authenticates");
        assert_eq!(authenticated.roles, role("developer"));
        assert!(
            authenticated.has_capability(CapabilityId::named(vos::capability::AGENT_CREATE_LOCAL))
        );
        let developer_origin = Origin::Member(SubjectId(authenticated.subject));
        let allowed = capability_claim(
            space,
            developer_origin,
            CapabilityId::named(vos::capability::AGENT_CREATE_LOCAL),
        );
        assert_eq!(authorize(&mut authority, &allowed), allowed.encode());
        let denied = capability_claim(
            space,
            developer_origin,
            CapabilityId::named(vos::capability::AGENT_CREATE_SHARED),
        );
        assert!(authorize(&mut authority, &denied).is_empty());
        let developer_claim = claim(space, developer_origin, SpaceRole::Developer);
        assert_eq!(
            authorize(&mut authority, &developer_claim),
            developer_claim.encode(),
            "a credential delegated by an Admin bearer must authorize its role",
        );
        assert!(dispatch_as(
            &mut authority,
            admin_origin,
            RevokeAccess {
                credential_id: developer_id,
            },
        ));
        assert!(
            dispatch(
                &mut authority,
                AuthenticateAccess {
                    credential_id: developer_id,
                },
            )
            .is_empty(),
            "revocation is visible to the next authentication",
        );
    }

    #[test]
    fn custom_roles_delegate_only_lower_subset_authority() {
        let signing = SigningKey::from_bytes(&[101; 32]);
        let peer = root_peer(&signing);
        let space = SpaceId([102; 32]);
        let root = Origin::Member(SubjectId::of_authenticated_peer(&peer));
        let admin = SubjectId([103; 32]);
        let member = SubjectId([104; 32]);
        let mut authority = actor(space, &signing);

        assert!(dispatch_as(
            &mut authority,
            root,
            SetMemberRoles {
                subject: admin.0,
                roles: vec![RoleId::named(space, "admin").0],
                epoch: 1,
            },
        ));

        let writer = SpaceRoleDefinition {
            id: RoleId::named(space, "writer").0,
            name: "writer".into(),
            power: 150,
            capabilities: vec![CapabilityId::named(vos::capability::AGENT_INVOKE).0],
        };
        assert!(dispatch_as(
            &mut authority,
            Origin::Member(admin),
            PutRole {
                definition: writer.encode(),
                epoch: 1,
            },
        ));
        assert!(dispatch_as(
            &mut authority,
            Origin::Member(admin),
            SetMemberRoles {
                subject: member.0,
                roles: vec![writer.id],
                epoch: 1,
            },
        ));
        let allowed = capability_claim(
            space,
            Origin::Member(member),
            CapabilityId::named(vos::capability::AGENT_INVOKE),
        );
        assert_eq!(authorize(&mut authority, &allowed), allowed.encode());
        let denied = capability_claim(
            space,
            Origin::Member(member),
            CapabilityId::named(vos::capability::AGENT_CREATE_LOCAL),
        );
        assert!(authorize(&mut authority, &denied).is_empty());

        let escalation = SpaceRoleDefinition {
            id: RoleId::named(space, "owner").0,
            name: "owner".into(),
            power: 301,
            capabilities: writer.capabilities.clone(),
        };
        assert!(!dispatch_as(
            &mut authority,
            Origin::Member(admin),
            PutRole {
                definition: escalation.encode(),
                epoch: 1,
            },
        ));

        assert!(dispatch_as(
            &mut authority,
            root,
            RevokeMemberRoles {
                subject: admin.0,
                epoch: 2,
            },
        ));
        assert!(
            authorize(&mut authority, &allowed).is_empty(),
            "revoking the delegator invalidates descendant authority",
        );
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
            RoleAuthorityMutation::Grant {
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
    fn equal_epoch_role_conflicts_use_the_registry_total_order() {
        let signing = SigningKey::from_bytes(&[70; 32]);
        let space = SpaceId([71; 32]);
        let holder = Origin::Member(SubjectId([72; 32]));
        let apply_order = |roles: [SpaceRole; 2]| {
            let mut authority = actor(space, &signing);
            for role in roles {
                assert!(apply(
                    &mut authority,
                    &signing,
                    RoleAuthorityMutation::Grant {
                        space,
                        holder,
                        role,
                        epoch: 7,
                    },
                ));
            }
            let member = claim(space, holder, SpaceRole::Member);
            let developer = claim(space, holder, SpaceRole::Developer);
            (
                authorize(&mut authority, &member),
                authorize(&mut authority, &developer),
            )
        };
        let expected = apply_order([SpaceRole::Admin, SpaceRole::Member]);
        assert_eq!(expected, apply_order([SpaceRole::Member, SpaceRole::Admin]),);
        assert!(
            !expected.0.is_empty(),
            "the selected Member grant authorizes Member"
        );
        assert!(
            expected.1.is_empty(),
            "the lower role wins equal root/grantor/epoch evidence",
        );
    }

    #[test]
    fn revoke_and_stale_replay_fail_closed() {
        let signing = SigningKey::from_bytes(&[10; 32]);
        let attacker = SigningKey::from_bytes(&[11; 32]);
        let space = SpaceId([12; 32]);
        let holder = Origin::Actor(ActorId([13; 32]));
        let grant = RoleAuthorityMutation::Grant {
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
            RoleAuthorityMutation::Revoke {
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
            RoleAuthorityMutation::Grant {
                space,
                holder: admin_holder,
                role: SpaceRole::Admin,
                epoch: 2,
            },
        ));
        let root_grant = RoleAuthorityMutation::Grant {
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
        let mutation = RoleAuthorityMutation::Grant {
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
            RoleAuthorityMutation::Grant {
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

        let revocation = RoleAuthorityInviteRevocation {
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
            RoleAuthorityMutation::Revoke {
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
