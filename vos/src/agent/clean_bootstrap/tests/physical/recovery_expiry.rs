//! Quorum expiry of one unseen delegated read with two durable physical owners.
//! Expiry is an applied metadata terminal, never a fabricated Invoke or ACK.

use super::common_checkpoint::{delegated_query, reopen_owner, restart_network};
use super::*;
use crate::agent::shared_host::SharedAgentPortableBackupLimits;

fn register_exact(owner: &MemoryBootstrapOwner, pending: &PendingAuthorityProjection) {
    let agent = HostAgentId(owner.pins.agent.0);
    let before_ordered = owner.ordered_index_for_test().unwrap();
    let manifest = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let registration = pending
        .registration(manifest.generation(), manifest.committee().id())
        .unwrap()
        .unwrap();
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        match owner.register_pending_projection(pending) {
            Ok(()) => true,
            Err(SharedAgentHostError::Unavailable) => false,
            Err(error) => panic!("exact registration retry failed: {error:?}"),
        }
    }));
    let manifest = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let slot = manifest.slot(registration.owner()).unwrap();
    assert_eq!(slot.registration(), &registration);
    assert!(slot.invoke().is_none() && slot.acknowledgement().is_none());
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered);
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_unseen_registered_read_expires_with_origin_offline_and_reopens() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(common_checkpoint::Exercise::ExpiredCustody),
    );
}

#[test]
#[ignore = "requires AUTHORITY_CANDIDATE_ELF and three authenticated loopback transports"]
fn candidate_expired_dependency_preserves_competing_durable_intent() {
    check_fixed_system_pending_cluster_with_checkpoint(
        true,
        None,
        false,
        Some(common_checkpoint::Exercise::ExpiredContendedCustody),
    );
}

pub(super) fn exercise_contended(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    networks: &mut Vec<Arc<Network>>,
) {
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let mut intents = Vec::new();
    let mut expires_at = 0;
    for index in 0..3 {
        let owner = owners[index].as_mut().unwrap();
        let mut query = delegated_query(owner, index, 0xea + index as u8);
        if index == leader {
            let recovery = query.recovery.as_mut().unwrap();
            recovery.expires_at = recovery.accepted_slot + 2;
            expires_at = recovery.expires_at;
            let key = SigningKey::from_bytes(&[[NODE_SEED, 0xd2, 0xd3][index]; 32]);
            let signature = key.sign(&query.signing_bytes()).to_bytes();
            let AuthorityIngressAuthentication::SshNodeAttestation {
                signature: actual, ..
            } = &mut query.authentication
            else {
                unreachable!()
            };
            *actual = signature;
        }
        let mut pending = owner.prepare_authority_projection(query).unwrap();
        owner
            .prepare_projection_recovery_registration(&mut pending)
            .unwrap();
        let (work, authorization) = pending.invocation().unwrap();
        if index == leader {
            owner
                ._network_host
                .reserve_projection_pair(agent, work, authorization, false)
                .unwrap();
        } else {
            owner
                ._network_host
                .reserve_forwarded_projection_pair(agent, work, authorization)
                .unwrap();
        }
        owner.record.pending_projection = Some(pending.clone());
        commit_bootstrap_record(&mut owner.record_store, &owner.record).unwrap();
        intents.push(pending);
    }
    let admitted = &intents[leader];
    register_exact(owners[leader].as_ref().unwrap(), admitted);
    for index in 0..3 {
        if index != leader {
            let owner = owners[index].as_ref().unwrap();
            let before = owner.record.encode();
            assert!(owner.register_pending_projection(&intents[index]).is_err());
            assert_eq!(owner.record.encode(), before);
            let AuthorityReadRequest::Projection(query) = &intents[index].query else {
                unreachable!()
            };
            assert!(query.recovery.unwrap().admits_at(expires_at));
        }
    }
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .store(expires_at, Ordering::Release);
    }
    drop(owners[leader].take());
    let mut live_networks: Vec<_> = networks.drain(..).map(Some).collect();
    stop_network(live_networks[leader].take().unwrap());
    let mut successor = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        successor = owners.iter().position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            })
        });
        successor.is_some()
    }));
    let successor = successor.unwrap();
    let owner = owners[successor].as_mut().unwrap();
    let before_record = owner.record.encode();
    let before_ordered = owner.ordered_index_for_test().unwrap();
    owner
        .recover_registered_projection_dependency(&intents[successor])
        .unwrap();
    assert_eq!(owner.record.encode(), before_record);
    assert_eq!(
        owner
            .record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(before_record)
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered);
    let manifest = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let expired = manifest
        .slot(HostNodeId(fixtures[leader].plan.pins.node.0))
        .unwrap();
    let terminal = expired.expiry().unwrap().clone();
    assert_eq!(
        expired.registration().work(),
        admitted.invocation().unwrap().0
    );
    assert!(expired.invoke().is_none() && expired.acknowledgement().is_none());
    assert!(terminal.certificate().signatures().len() >= 2);
    assert_eq!(terminal.certificate().claim().observed_slot(), expires_at);
    assert!(manifest.slot(HostNodeId(owner.pins.node.0)).is_none());
    assert_eq!(
        owner.committed_projection_response(admitted.invocation().unwrap().0),
        Err(SharedAgentHostError::ProjectionExpired)
    );

    // Only B's ordinary completion may clear its durable intent. Expiring A
    // changed metadata alone and did not borrow B's freshness or authority.
    assert!(owner.recover_pending_authority_projection().unwrap());
    assert!(owner.record.pending_projection.is_none());
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered + 2);
    let (work, _) = intents[successor].invocation().unwrap();
    let bytes = owner.committed_projection_response(work).unwrap().unwrap();
    let projection = AuthorityCredentialProjection::decode(&bytes).unwrap();
    let AuthorityReadRequest::Projection(expected) = &intents[successor].query else {
        unreachable!()
    };
    assert_eq!(&projection.query, expected);
    let after = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    assert_eq!(
        after
            .slot(HostNodeId(fixtures[leader].plan.pins.node.0))
            .unwrap()
            .expiry(),
        Some(&terminal)
    );
    assert!(
        after
            .slot(HostNodeId(owner.pins.node.0))
            .unwrap()
            .is_acknowledged()
    );
    let other = (0..3)
        .find(|index| *index != leader && *index != successor)
        .unwrap();
    assert_eq!(
        owners[other]
            .as_ref()
            .unwrap()
            .record
            .pending_projection
            .as_ref(),
        Some(&intents[other])
    );
    assert!(
        after
            .slot(HostNodeId(fixtures[other].plan.pins.node.0))
            .is_none()
    );
    *networks = live_networks.into_iter().flatten().collect();
}

pub(super) fn exercise(
    leader: usize,
    owners: &mut [Option<MemoryBootstrapOwner>],
    fixtures: &[PhysicalFixture],
    directories: &[TestDirectory],
    stores: &[(
        BootstrapMemoryStore,
        BootstrapMemoryStore,
        IssuerMemoryStore,
    )],
    providers: &[Arc<MemoryProvider>],
    networks: &mut Vec<Arc<Network>>,
    signer: &mut CountingSigner,
) {
    let agent = HostAgentId(fixtures[leader].plan.pins.agent.0);
    let origin = (leader + 1) % 3;
    let holder = (leader + 2) % 3;
    let query = delegated_query(owners[origin].as_ref().unwrap(), origin, 0xe8);
    let expires_at = query.recovery.unwrap().expires_at;
    let before_ordered = owners[leader]
        .as_ref()
        .unwrap()
        .ordered_index_for_test()
        .unwrap();
    let mut pending_records = Vec::new();
    for index in [origin, holder] {
        let owner = owners[index].as_mut().unwrap();
        let mut pending = owner.prepare_authority_projection(query.clone()).unwrap();
        owner
            .prepare_projection_recovery_registration(&mut pending)
            .unwrap();
        let (work, authorization) = pending.invocation().unwrap();
        owner
            ._network_host
            .reserve_forwarded_projection_pair(agent, work, authorization)
            .unwrap();
        owner.record.pending_projection = Some(pending.clone());
        commit_bootstrap_record(&mut owner.record_store, &owner.record).unwrap();
        register_exact(owner, &pending);
        pending_records.push(pending);
    }
    let (work, authorization) = pending_records[0].invocation().unwrap();
    let work = work.clone();
    let authorization = authorization.clone();
    assert_eq!(
        pending_records[1].invocation().unwrap(),
        (&work, &authorization)
    );
    assert!(
        owners[leader]
            .as_ref()
            .unwrap()
            .record
            .pending_projection
            .is_none()
    );
    let expected = owners[holder]
        .as_ref()
        .unwrap()
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    assert_eq!(expected.slots().len(), 2);
    for slot in expected.slots() {
        assert_eq!(slot.registration().work(), &work);
        assert_eq!(slot.registration().authorization(), &authorization);
        assert!(
            slot.invoke().is_none() && slot.acknowledgement().is_none() && slot.expiry().is_none()
        );
    }
    let request = expected.slots()[0]
        .registration()
        .request()
        .request_commitment();
    for owner in owners.iter().flatten() {
        assert!(wait_until(std::time::Duration::from_secs(20), || owner
            ._network_host
            .projection_recovery_manifest(agent)
            .is_ok_and(|manifest| manifest == expected)));
        assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered);
    }

    // Expiry is exclusive: no valid vote, metadata append, or local PAP clear
    // is possible one logical slot before the signed deadline.
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .store(expires_at - 1, Ordering::Release);
    }
    let source = owners[leader].as_ref().unwrap();
    let before_capacity = source.host.lock().unwrap().capacity(agent).unwrap();
    assert!(
        source
            .host
            .lock()
            .unwrap()
            .prepare_recovery_expiry(agent, request)
            .is_err()
    );
    assert_eq!(
        source.host.lock().unwrap().capacity(agent).unwrap(),
        before_capacity
    );
    assert_eq!(
        source
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap(),
        expected
    );
    let saved_origin = stores[origin]
        .1
        .clone()
        .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
        .unwrap()
        .unwrap();

    let mut live_networks: Vec<_> = std::mem::take(networks).into_iter().map(Some).collect();
    drop(owners[origin].take());
    stop_network(live_networks[origin].take().unwrap());
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .store(expires_at, Ordering::Release);
    }
    // With the origin offline, freeze the remaining follower's actual Raft
    // writer for one attempt. Even if it signs the expiry claim, it cannot
    // durably acknowledge the Raft append. Capture routing before the writer;
    // querying that worker afterwards could itself wait on this transaction.
    let mut single = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        single = owners.iter().position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            })
        });
        single.is_some()
    }));
    let single = single.unwrap();
    let blocked = (0..3)
        .find(|index| *index != origin && *index != single)
        .unwrap();
    let blocked_database = owners[blocked]
        .as_ref()
        .unwrap()
        .host
        .lock()
        .unwrap()
        .raft_database(agent)
        .unwrap();
    let saved_live: Vec<_> = owners
        .iter()
        .enumerate()
        .filter_map(|(index, owner)| owner.as_ref().map(|owner| (index, owner.record.encode())))
        .collect();
    let blocked_writer = blocked_database.begin_write().unwrap();
    let source = owners[single].as_ref().unwrap();
    assert_eq!(
        source
            ._network_host
            .expire_projection_recovery(agent, request),
        Err(SharedAgentHostError::Unavailable),
        "one available voter must not retire an admitted read"
    );
    assert_eq!(
        source
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap(),
        expected,
        "failed quorum must preserve all custody and the authenticated expiry floor"
    );
    assert_eq!(source.ordered_index_for_test().unwrap(), before_ordered);
    for (index, bytes) in saved_live {
        let owner = owners[index].as_ref().unwrap();
        assert_eq!(owner.record.encode(), bytes);
        assert_eq!(
            stores[index]
                .1
                .clone()
                .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                .unwrap(),
            Some(bytes)
        );
    }
    assert_eq!(
        stores[origin]
            .1
            .clone()
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(saved_origin.clone())
    );
    drop(blocked_writer);
    drop(blocked_database);
    // The surviving current leader drives recovery without an original-client
    // retry. Normally that is the PAP-free leader; if leadership changed, the
    // other holder may finish its own hold. Both must obtain two independent
    // signatures and apply ExpireRecovery before any local durable clear.
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        let Some(source) = owners.iter_mut().flatten().find(|owner| {
            owner
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false)
        }) else {
            return false;
        };
        match source.recover_pending_authority_projection() {
            Ok(_) => source
                ._network_host
                .projection_recovery_manifest(agent)
                .is_ok_and(|manifest| manifest.slots().iter().all(|slot| slot.expiry().is_some())),
            Err(SharedAgentHostError::Unavailable) => false,
            Err(error) => panic!("autonomous expiry failed: {error:?}"),
        }
    }));
    assert!(wait_until(std::time::Duration::from_secs(20), || owners
        [leader]
        .as_ref()
        .unwrap()
        ._network_host
        .projection_recovery_manifest(agent)
        .is_ok_and(|manifest| manifest
            .slots()
            .iter()
            .all(|slot| slot.expiry().is_some()))));
    let terminal_manifest = owners[leader]
        .as_ref()
        .unwrap()
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let terminal = terminal_manifest.slots()[0].expiry().unwrap();
    assert!(terminal.certificate().signatures().len() >= 2);
    assert_eq!(terminal.certificate().claim().expires_at(), expires_at);
    assert_eq!(terminal.certificate().claim().observed_slot(), expires_at);
    for slot in terminal_manifest.slots() {
        assert_eq!(slot.expiry(), Some(terminal));
        assert!(slot.is_terminal() && !slot.is_acknowledged());
        assert!(slot.invoke().is_none() && slot.acknowledgement().is_none());
    }
    assert_eq!(
        owners[leader]
            .as_ref()
            .unwrap()
            .ordered_index_for_test()
            .unwrap(),
        before_ordered
    );
    let owner = owners[holder].as_mut().unwrap();
    assert!(wait_until(std::time::Duration::from_secs(20), || owner
        ._network_host
        .projection_recovery_manifest(agent)
        .is_ok_and(|manifest| manifest == terminal_manifest)));
    assert_eq!(
        owner.invoke_authority_projection(query.clone()),
        Err(SharedAgentHostError::ProjectionExpired)
    );
    // The external retry may report the terminal before local lifecycle
    // cleanup. The recovery owner must subsequently durably clear that PAP.
    if owner.record.pending_projection.is_some() {
        assert!(owner.recover_pending_authority_projection().unwrap());
    }
    assert!(owner.record.pending_projection.is_none());
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered);
    assert_eq!(
        stores[origin]
            .1
            .clone()
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(saved_origin)
    );

    live_networks[origin] = Some(restart_network(origin));
    for index in [leader, holder] {
        live_networks[origin]
            .as_ref()
            .unwrap()
            .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
    }
    owners[origin] = Some(reopen_owner(
        &fixtures[origin],
        &directories[origin],
        &stores[origin],
        providers[origin].clone(),
        live_networks[origin].as_ref().unwrap().clone(),
        signer,
    ));
    let owner = owners[origin].as_mut().unwrap();
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        match owner.recover_pending_authority_projection() {
            Ok(_) | Err(SharedAgentHostError::ProjectionExpired) => {
                owner.record.pending_projection.is_none()
            }
            Err(SharedAgentHostError::Unavailable) => false,
            Err(error) => panic!("expired original PAP recovery failed: {error:?}"),
        }
    }));
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered);
    assert_eq!(
        owner.committed_projection_response(&work),
        Err(SharedAgentHostError::ProjectionExpired)
    );
    assert_eq!(
        stores[origin]
            .1
            .clone()
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(owner.record.encode())
    );
    assert_eq!(
        owner
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap(),
        terminal_manifest
    );

    // Fresh work after the quorum terminal is admitted normally, not under
    // the old signed deadline or a fabricated positive acknowledgement.
    let mut response = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        let Some((index, owner)) = owners.iter_mut().enumerate().find_map(|(index, owner)| {
            let owner = owner.as_mut()?;
            owner
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap_or(false)
                .then_some((index, owner))
        }) else {
            return false;
        };
        let fresh = delegated_query(owner, index, 0xe9);
        match owner.invoke_authority_projection(fresh.clone()) {
            Ok(bytes) => {
                response = Some((fresh, bytes));
                true
            }
            Err(SharedAgentHostError::Unavailable) => false,
            Err(error) => panic!("fresh read after expiry failed: {error:?}"),
        }
    }));
    let (fresh, bytes) = response.unwrap();
    let projection = AuthorityCredentialProjection::decode(&bytes).unwrap();
    assert_eq!(projection.query, fresh);
    assert_ne!(projection.principal, PrincipalId::ZERO);
    for owner in owners.iter().flatten() {
        assert!(wait_until(std::time::Duration::from_secs(20), || owner
            .ordered_index_for_test()
            .is_ok_and(|index| index > before_ordered)));
    }

    // A different follower drives the expiry request RPC itself; the leader
    // has no pending PAP and does not run autonomous recovery first.
    let follower = owners
        .iter()
        .position(|owner| {
            !owner
                .as_ref()
                .unwrap()
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap()
        })
        .unwrap();
    let owner = owners[follower].as_mut().unwrap();
    let query = delegated_query(owner, follower, 0xee);
    let mut pending = owner.prepare_authority_projection(query.clone()).unwrap();
    owner
        .prepare_projection_recovery_registration(&mut pending)
        .unwrap();
    let (work, authorization) = pending.invocation().unwrap();
    let work = work.clone();
    owner
        ._network_host
        .reserve_forwarded_projection_pair(agent, &work, authorization)
        .unwrap();
    owner.record.pending_projection = Some(pending.clone());
    commit_bootstrap_record(&mut owner.record_store, &owner.record).unwrap();
    register_exact(owner, &pending);
    let before_ordered = owner.ordered_index_for_test().unwrap();
    for fixture in fixtures {
        fixture
            .logical_slot
            .as_ref()
            .unwrap()
            .store(query.recovery.unwrap().expires_at, Ordering::Release);
    }
    assert!(
        !owner
            ._network_host
            .bootstrap_is_local_leader(agent)
            .unwrap()
    );
    let before_record = owner.record.encode();
    let admitted = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let request = admitted
        .slot(HostNodeId(owner.pins.node.0))
        .unwrap()
        .registration()
        .request()
        .request_commitment();
    let mut applied_terminal = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        assert!(
            !owner
                ._network_host
                .bootstrap_is_local_leader(agent)
                .unwrap(),
            "expiry qualification must continue through the follower RPC"
        );
        match owner
            ._network_host
            .expire_projection_recovery(agent, request)
        {
            Ok(terminal) => {
                applied_terminal = Some(terminal);
                true
            }
            Err(SharedAgentHostError::Unavailable) => {
                assert_eq!(owner.record.encode(), before_record);
                assert_eq!(
                    owner
                        .record_store
                        .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                        .unwrap(),
                    Some(before_record.clone())
                );
                assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered);
                false
            }
            Err(error) => panic!("follower expiry RPC failed: {error:?}"),
        }
    }));
    // This cut is after local metadata application but before bootstrap PAP
    // retirement. Transport expiry never clears the owner's durable record.
    assert_eq!(owner.record.pending_projection.as_ref(), Some(&pending));
    assert_eq!(owner.record.encode(), before_record);
    assert_eq!(
        owner
            .record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(before_record)
    );
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered);
    let manifest = owner
        ._network_host
        .projection_recovery_manifest(agent)
        .unwrap();
    let expired = manifest.slot(HostNodeId(owner.pins.node.0)).unwrap();
    assert_eq!(expired.registration().query(), &query);
    assert!(expired.invoke().is_none() && expired.acknowledgement().is_none());
    assert_eq!(expired.expiry(), applied_terminal.as_ref());
    assert!(expired.expiry().unwrap().certificate().signatures().len() >= 2);
    let archived = expired.clone();
    let saved_pending = owner.record.encode();
    let offline_host = owner.host.clone();
    drop(owners[follower].take());
    stop_network(live_networks[follower].take().unwrap());

    // Unlike the first origin's normal log catch-up above, this holder now
    // remains detached through a certified checkpoint transfer. One unrelated
    // fresh read makes the donor boundary strictly newer than its applied
    // expiry; importing an equal uninstalled cursor must not be a shortcut.
    let mut donor = None;
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        donor = owners.iter().position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            })
        });
        donor.is_some()
    }));
    let fresh_query = {
        let index = donor.unwrap();
        delegated_query(owners[index].as_ref().unwrap(), index, 0xef)
    };
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        let Some(current) = owners.iter().position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            })
        }) else {
            return false;
        };
        match owners[current]
            .as_mut()
            .unwrap()
            .invoke_peer_authority_projection(
                fresh_query.clone(),
                false,
                fixtures[donor.unwrap()].plan.pins.node,
            ) {
            Ok(bytes) => {
                assert_eq!(
                    AuthorityCredentialProjection::decode(&bytes).unwrap().query,
                    fresh_query
                );
                true
            }
            Err(SharedAgentHostError::Unavailable) => false,
            Err(error) => panic!("fresh donor query before expiry checkpoint failed: {error:?}"),
        }
    }));
    assert!(wait_until(std::time::Duration::from_secs(30), || {
        donor = owners.iter().position(|owner| {
            owner.as_ref().is_some_and(|owner| {
                owner
                    ._network_host
                    .bootstrap_is_local_leader(agent)
                    .unwrap_or(false)
            })
        });
        donor.is_some()
    }));
    let donor = donor.unwrap();
    let source = owners[donor].as_mut().unwrap();
    assert!(source.record.pending_projection.is_none());
    assert_eq!(source.ordered_index_for_test().unwrap(), before_ordered + 2);
    let checkpoint = source
        .prepare_authority_projection(delegated_query(source, donor, 0xf0))
        .unwrap();
    let (checkpoint_work, checkpoint_auth) = checkpoint.invocation().unwrap();
    let committee = source.pins.replicas.clone();
    let checkpoint_record = source.record.encode();
    let checkpoint_manifest = source
        .host
        .lock()
        .unwrap()
        .recovery_manifest(agent)
        .unwrap();
    let mut certificate = None;
    // Collection uses the existing bounded peer wait and may observe an
    // unavailable voter while it catches up. Each retry independently collects
    // a genuine quorum for the freshly reconstructed boundary; no failed vote
    // is retained, and the exact expired custody and detached PAP must survive.
    assert!(
        wait_until(std::time::Duration::from_secs(30), || {
            match source
                ._network_host
                .certified_common_checkpoint_for_admission(
                    agent,
                    checkpoint_work,
                    checkpoint_auth,
                    &committee,
                    fixtures[donor].merge.as_ref(),
                ) {
                Ok(certified) => {
                    certificate = Some(certified);
                    true
                }
                Err(SharedAgentHostError::Unavailable) => {
                    assert_eq!(source.record.encode(), checkpoint_record);
                    assert!(source.record.pending_projection.is_none());
                    assert_eq!(source.ordered_index_for_test().unwrap(), before_ordered + 2);
                    let mut host = source.host.lock().unwrap();
                    assert_eq!(host.recovery_manifest(agent).unwrap(), checkpoint_manifest);
                    assert_eq!(
                        host.recovery_expiry_floor(agent).unwrap(),
                        manifest.expiry_floor()
                    );
                    assert_eq!(
                        host.recovery_expiry_terminal(agent, request).unwrap(),
                        applied_terminal
                    );
                    assert_eq!(
                        stores[follower]
                            .1
                            .clone()
                            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
                            .unwrap(),
                        Some(saved_pending.clone())
                    );
                    false
                }
                Err(error) => panic!("expiry checkpoint collection failed: {error:?}"),
            }
        }),
        "expiry checkpoint must obtain a genuine quorum within the retry bound"
    );
    let certificate = certificate.unwrap();
    assert_eq!(certificate.signatures().len(), 2);
    assert!(
        certificate
            .signatures()
            .iter()
            .all(|signature| { signature.signer().0 != fixtures[follower].plan.pins.node.0 })
    );
    let limits = SharedAgentPortableBackupLimits {
        max_objects: 4096,
        max_blobs: 4096,
        max_index_nodes: 4096,
        max_bytes: 64 * 1024 * 1024,
    };
    let (bytes, certified_manifest) = {
        let mut host = source.host.lock().unwrap();
        let certified = host.recovery_manifest(agent).unwrap();
        assert_eq!(
            certified.slot(archived.registration().owner()),
            Some(&archived)
        );
        assert_eq!(certified.expiry_floor(), manifest.expiry_floor());
        assert_eq!(
            host.recovery_expiry_terminal(agent, request).unwrap(),
            applied_terminal
        );
        (
            host.export_common_checkpoint(agent, limits).unwrap(),
            certified,
        )
    };
    assert_eq!(source.ordered_index_for_test().unwrap(), before_ordered + 2);
    assert_eq!(
        source.committed_projection_response(&work),
        Err(SharedAgentHostError::ProjectionExpired)
    );
    {
        let mut destination = offline_host.lock().unwrap();
        destination
            .restore_common_checkpoint(&bytes, limits)
            .unwrap();
        assert_eq!(
            destination.recovery_manifest(agent).unwrap(),
            certified_manifest
        );
        assert_eq!(
            destination.recovery_expiry_floor(agent).unwrap(),
            manifest.expiry_floor()
        );
        assert_eq!(
            destination
                .recovery_expiry_terminal(agent, request)
                .unwrap(),
            applied_terminal
        );
        assert_eq!(
            destination.journal_position(agent).unwrap().ordered_index,
            before_ordered + 2
        );
    }
    assert_eq!(
        stores[follower]
            .1
            .clone()
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(saved_pending.clone()),
        "certified import must not clear the detached owner's exact PAP"
    );
    drop(offline_host);
    live_networks[follower] = Some(restart_network(follower));
    for index in 0..3 {
        if index != follower {
            live_networks[follower]
                .as_ref()
                .unwrap()
                .connect(live_networks[index].as_ref().unwrap().listen_addrs()[0].clone());
        }
    }
    owners[follower] = Some(reopen_owner(
        &fixtures[follower],
        &directories[follower],
        &stores[follower],
        providers[follower].clone(),
        live_networks[follower].as_ref().unwrap().clone(),
        signer,
    ));
    let owner = owners[follower].as_mut().unwrap();
    let mut cleared = CleanSystemAgentBootstrapRecord::decode(&saved_pending).unwrap();
    cleared.pending_projection = None;
    assert_eq!(owner.record, cleared);
    assert_eq!(owner.ordered_index_for_test().unwrap(), before_ordered + 2);
    assert_eq!(
        owner
            ._network_host
            .projection_recovery_manifest(agent)
            .unwrap(),
        certified_manifest
    );
    assert_eq!(
        owner.committed_projection_response(&work),
        Err(SharedAgentHostError::ProjectionExpired)
    );
    assert_eq!(
        owner
            .record_store
            .load(MAX_CLEAN_SYSTEM_AGENT_BOOTSTRAP_BYTES)
            .unwrap(),
        Some(owner.record.encode())
    );
    *networks = live_networks.into_iter().map(Option::unwrap).collect();
}
