//! Root-authorized enrollment of the actual retained local transport identity.
//! Preparation grants no membership; this runs only after supported System
//! startup, before ingress readiness. Observed conflicting slots and observer
//! promotion are refused. Existing add_node is a root-authorized upsert, not a
//! CAS; this helper does not serialize concurrent valid root roster changes.

use std::collections::BTreeSet;

use libp2p::PeerId;
use libp2p::identity::{KeyType, Keypair};
use vos::registry::{
    MEMBER_KIND_NODE, MemberRow, NODE_ROLE_OBSERVER, NODE_ROLE_VOTER, RegistryInvoker, RegistryRef,
    Status,
};

pub(super) async fn ensure_local_registry_node<I: RegistryInvoker>(
    registry: &RegistryRef,
    invoker: &mut I,
    space: &[u8; 32],
    operator: &Keypair,
    daemon: &Keypair,
    prefix: u16,
) -> anyhow::Result<bool> {
    anyhow::ensure!(
        *space != [0; 32]
            && operator.key_type() == KeyType::Ed25519
            && daemon.key_type() == KeyType::Ed25519,
        "registry enrollment requires the actual nonzero Space and Ed25519 root/node identities"
    );
    let peer = daemon.public().to_peer_id();
    anyhow::ensure!(
        vos::network::derive_node_prefix(&peer) == prefix,
        "registry enrollment node differs from the actual network prefix"
    );
    let root = operator.public().to_peer_id().to_bytes();
    anyhow::ensure!(
        registry.root(invoker).await? == root
            && registry.space_id(invoker).await?.as_slice() == space,
        "registry enrollment does not match the immutable Space/root anchors"
    );
    // The existing typed drain enforces page progress and total page/row/byte
    // budgets. No new unbounded get_nodes loop or authority roster is added.
    let members = registry.members_all(invoker).await?;
    if !enrollment_needed(&members, &peer, prefix)? {
        return Ok(false);
    }
    // The existing guest contract is an upsert, not an atomic absent-slot
    // operation. A separate valid root mutation can race this snapshot; the
    // mandatory postread still refuses any observed identity/role mismatch.
    let peer_bytes = peer.to_bytes();
    let auth = crate::commands::space::op_sign::op_auth(
        operator,
        space,
        "add_node",
        &[
            &(prefix as u32).to_le_bytes(),
            &peer_bytes,
            &[NODE_ROLE_VOTER],
        ],
    )?;
    let status = registry
        .add_node(invoker, prefix as u32, peer_bytes, NODE_ROLE_VOTER, auth)
        .await?;
    anyhow::ensure!(
        status == Status::Ok,
        "registry refused local node enrollment: {status}"
    );
    let members = registry.members_all(invoker).await?;
    anyhow::ensure!(
        !enrollment_needed(&members, &peer, prefix)?,
        "registry did not retain the exact full-PeerId local voter enrollment"
    );
    Ok(true)
}

fn enrollment_needed(members: &[MemberRow], peer: &PeerId, prefix: u16) -> anyhow::Result<bool> {
    let mut prefixes = BTreeSet::new();
    let mut peers = BTreeSet::new();
    let mut existing = false;
    for member in members
        .iter()
        .filter(|member| member.kind == MEMBER_KIND_NODE)
    {
        let enrolled = PeerId::from_bytes(&member.key)
            .map_err(|_| anyhow::anyhow!("registry node roster has a noncanonical full PeerId"))?;
        anyhow::ensure!(
            enrolled.to_bytes() == member.key
                && vos::registry::ed25519_pubkey_from_peer_id(&member.key).is_some()
                && vos::network::derive_node_prefix(&enrolled) == member.prefix
                && matches!(member.role, NODE_ROLE_VOTER | NODE_ROLE_OBSERVER)
                && member.proof_kind == 0
                && member.proof_data.is_empty()
                && prefixes.insert(member.prefix)
                && peers.insert(member.key.clone()),
            "registry node roster is malformed, duplicated or misbound to a compact prefix"
        );
        if member.prefix == prefix {
            anyhow::ensure!(
                enrolled == *peer && member.role == NODE_ROLE_VOTER,
                "local node slot is already owned by another identity or role; startup will not replace it"
            );
            existing = true;
        }
    }
    Ok(!existing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::abi::service::ServiceId;
    use vos::value::{Msg, TAG_DYNAMIC, Value};
    use vos::{Decode as _, Encode as _};

    const SPACE: [u8; 32] = [0x91; 32];

    fn keys() -> (Keypair, Keypair) {
        (
            Keypair::ed25519_from_bytes([0x92; 32]).unwrap(),
            Keypair::ed25519_from_bytes([0x93; 32]).unwrap(),
        )
    }

    fn node_member(peer: PeerId, role: u8) -> MemberRow {
        MemberRow {
            kind: MEMBER_KIND_NODE,
            key: peer.to_bytes(),
            prefix: vos::network::derive_node_prefix(&peer),
            role,
            proof_kind: 0,
            proof_data: Vec::new(),
        }
    }

    struct RegistryFixture {
        root: Vec<u8>,
        space: [u8; 32],
        members: Vec<MemberRow>,
        additions: Vec<Msg>,
        status: Status,
        retain: bool,
    }

    impl RegistryFixture {
        fn new(root: &Keypair) -> Self {
            Self {
                root: root.public().to_peer_id().to_bytes(),
                space: SPACE,
                members: Vec::new(),
                additions: Vec::new(),
                status: Status::Ok,
                retain: true,
            }
        }
    }

    impl RegistryInvoker for RegistryFixture {
        async fn invoke_registry(
            &mut self,
            target: ServiceId,
            payload: Vec<u8>,
        ) -> Result<Value, vos::actors::client::ClientError> {
            assert_eq!(target, ServiceId::REGISTRY);
            assert_eq!(payload[0], TAG_DYNAMIC);
            let request = Msg::try_decode(&payload[1..]).unwrap();
            match request.name.as_str() {
                "root" => Ok(Value::Bytes(self.root.clone())),
                "space_id" => Ok(Value::Bytes(self.space.to_vec())),
                "members" => {
                    let rows = if request.args.get_u8("after_kind") == Some(MEMBER_KIND_NODE) {
                        let mut rows = self.members.clone();
                        rows.sort_by_key(|member| member.prefix);
                        rows
                    } else {
                        Vec::new()
                    };
                    let more = !rows.is_empty();
                    Ok(Value::Bytes(
                        vos::registry::MemberPage {
                            members: rows,
                            next_kind: if more {
                                vos::registry::MEMBER_KIND_IDENTITY
                            } else {
                                MEMBER_KIND_NODE
                            },
                            next_key: Vec::new(),
                            more,
                        }
                        .encode(),
                    ))
                }
                "add_node" => {
                    // Verify the actual op_auth preimage/signature, not merely
                    // the fact that an add_node call occurred.
                    let prefix = request.args.get_u32("prefix").unwrap();
                    let peer = request.args.get_bytes("peer_id").unwrap();
                    let role = request.args.get_u8("role").unwrap();
                    let auth = request.args.get_bytes("auth").unwrap();
                    assert_eq!(auth.len(), self.root.len() + vos::registry::OP_SIG_LEN);
                    assert_eq!(&auth[..self.root.len()], self.root.as_slice());
                    let root = PeerId::from_bytes(&self.root).unwrap();
                    let public =
                        vos::registry::ed25519_pubkey_from_peer_id(&root.to_bytes()).unwrap();
                    let public = libp2p::identity::PublicKey::from(
                        libp2p::identity::ed25519::PublicKey::try_from_bytes(&public).unwrap(),
                    );
                    let signed = vos::registry::registry_mutation_signed_bytes(
                        &self.space,
                        "add_node",
                        &[&prefix.to_le_bytes(), &peer, &[role]],
                    );
                    assert!(public.verify(&signed, &auth[self.root.len()..]));
                    assert_eq!(role, NODE_ROLE_VOTER);
                    assert_eq!(
                        prefix,
                        vos::network::derive_node_prefix(&PeerId::from_bytes(&peer).unwrap())
                            as u32
                    );
                    self.additions.push(request);
                    if self.status == Status::Ok && self.retain {
                        self.members
                            .push(node_member(PeerId::from_bytes(&peer).unwrap(), role));
                    }
                    Ok(Value::Bytes(self.status.encode()))
                }
                method => panic!("unexpected registry invocation {method}"),
            }
        }
    }

    fn enroll(
        fixture: &mut RegistryFixture,
        root: &Keypair,
        daemon: &Keypair,
    ) -> anyhow::Result<bool> {
        vos::block_on(ensure_local_registry_node(
            &RegistryRef::at(ServiceId::REGISTRY),
            fixture,
            &SPACE,
            root,
            daemon,
            vos::network::derive_node_prefix(&daemon.public().to_peer_id()),
        ))
    }

    #[test]
    fn fresh_enrollment_signs_exact_existing_protocol_and_retry_does_not_mutate() {
        let (root, daemon) = keys();
        let mut fixture = RegistryFixture::new(&root);
        assert_eq!(enroll(&mut fixture, &root, &daemon).unwrap(), true);
        assert_eq!(fixture.additions.len(), 1);
        let row = node_member(daemon.public().to_peer_id(), NODE_ROLE_VOTER);
        assert_eq!(fixture.members, [row]);
        let before = fixture.members.clone();
        assert_eq!(enroll(&mut fixture, &root, &daemon).unwrap(), false);
        assert_eq!(
            fixture.additions.len(),
            1,
            "exact retained enrollment cannot emit another signed mutation"
        );
        assert_eq!(fixture.members, before);
    }

    #[test]
    fn conflicting_roles_and_malformed_rosters_refuse_before_any_signed_mutation() {
        let (root, daemon) = keys();
        let peer = daemon.public().to_peer_id();
        let canonical = node_member(peer, NODE_ROLE_VOTER);
        for case in 0..5 {
            let mut fixture = RegistryFixture::new(&root);
            let mut row = canonical.clone();
            match case {
                0 => row.role = NODE_ROLE_OBSERVER,
                1 => row.key = vec![0x94; 38],
                2 => row.prefix ^= 1,
                3 => row.proof_data = vec![1],
                4 => fixture.members.push(row.clone()),
                _ => unreachable!(),
            }
            fixture.members.push(row);
            let before = fixture.members.clone();
            assert!(enroll(&mut fixture, &root, &daemon).is_err(), "case {case}");
            assert!(fixture.additions.is_empty());
            assert_eq!(fixture.members, before);
        }
        let other = Keypair::ed25519_from_bytes([0x95; 32])
            .unwrap()
            .public()
            .to_peer_id();
        let mut conflict = node_member(other, NODE_ROLE_VOTER);
        conflict.prefix = canonical.prefix;
        let mut fixture = RegistryFixture::new(&root);
        fixture.members.push(conflict);
        assert!(enroll(&mut fixture, &root, &daemon).is_err());
        assert!(
            fixture.additions.is_empty(),
            "never overwrite a conflicting compact node slot"
        );
    }

    #[test]
    fn wrong_space_root_or_network_identity_never_changes_membership() {
        let (root, daemon) = keys();
        let mut fixture = RegistryFixture::new(&root);
        fixture.space = [0x96; 32];
        assert!(enroll(&mut fixture, &root, &daemon).is_err());
        assert!(fixture.additions.is_empty());
        fixture.space = SPACE;
        fixture.root = Keypair::ed25519_from_bytes([0x97; 32])
            .unwrap()
            .public()
            .to_peer_id()
            .to_bytes();
        assert!(enroll(&mut fixture, &root, &daemon).is_err());
        assert!(fixture.additions.is_empty());
        let mut fixture = RegistryFixture::new(&root);
        assert!(
            vos::block_on(ensure_local_registry_node(
                &RegistryRef::at(ServiceId::REGISTRY),
                &mut fixture,
                &SPACE,
                &root,
                &daemon,
                vos::network::derive_node_prefix(&daemon.public().to_peer_id()) ^ 1,
            ))
            .is_err()
        );
        assert!(fixture.additions.is_empty());
    }

    #[test]
    fn refused_or_unretained_admission_is_not_reported_as_ready() {
        let (root, daemon) = keys();
        let mut refused = RegistryFixture::new(&root);
        refused.status = Status::Forbidden;
        assert!(enroll(&mut refused, &root, &daemon).is_err());
        assert_eq!(refused.additions.len(), 1);
        assert!(refused.members.is_empty());
        let mut absent = RegistryFixture::new(&root);
        absent.retain = false;
        assert!(enroll(&mut absent, &root, &daemon).is_err());
        assert_eq!(absent.additions.len(), 1);
        assert!(absent.members.is_empty());
    }
}
