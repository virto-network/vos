//! Public Clerk slices through real locked startup, HTTP, signed Authority
//! decisions and retained CLI delivery. The separate Shared leader-loss slice
//! measures bounded exact recovery; neither slice is load qualification.

use super::*;
use crate::commands::space as commands;
use std::net::{SocketAddr, TcpListener};
use vos::agent::genesis::AgentGenesisArchiveRecord;
use vos::agent::local_lifecycle::SharedInstallDisposition;
use vos::agent::package_admission::AdmittedActorPackage;
use vos::agent::sdk::method_policy::{ActorMethodPolicyArtifact, AuthorizationPolicySelector};
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{
    InvocationOrigin, InvocationRoleClaims, LaneSet, ManagementReply, RuntimeOutcome, StateLane,
};
use vos::agent::supervisor::{AgentRouteKey, AgentSupervisorLimits};
use vos::agent::supervisor_adapters::{AgentInvocationIntent, AgentTargetedPreparationRequest};
use vos::service::ServiceWire as _;
use vos::{Decode as _, Encode as _};
#[path = "member_operation_capacity_tests.rs"]
mod operation_capacity;
pub(super) use operation_capacity::{RetainedCapacity, exercise as exercise_capacity};

pub(super) struct RetainedWorkflow {
    install_root: PathBuf,
    install_request: Vec<u8>,
    install_response: Vec<u8>,
    actor: ActorId,
    authorization_root: PathBuf,
    application_root: PathBuf,
    invocation_request: Vec<u8>,
    first_response: Vec<u8>,
    journal: [u8; 16],
}

#[allow(clippy::too_many_arguments)]
pub(super) fn exercise(
    nodes: &mut [VosNode],
    networks: &[Arc<Network>],
    data: &[PathBuf],
    operator: &Keypair,
    daemons: &[Keypair],
    enrollments: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    space: SpaceId,
    authority: AuthorityActorTarget,
    inputs: &StartupTestInputs,
    record: &AgentGenesisArchiveRecord,
    restart: bool,
    leader_loss: bool,
    owner_recovery_started: Option<std::time::Instant>,
    retained: &mut Option<RetainedWorkflow>,
) {
    let started = std::time::Instant::now();
    let locator = record.provision().proposal().locator();
    let agent = AgentId(locator.agent.0);
    let node_public = raw_public_key(&daemons[0]).unwrap();
    let identity = commands::clean_identity::CleanOperatorIdentitySigner::new(operator).unwrap();
    if restart {
        let previous = retained
            .as_ref()
            .expect("initial public workflow completed its loss seam");
        let address = listen(&mut nodes[0], "public-clerk-reopened");
        resume_after_reopen(
            nodes,
            &data[0],
            address,
            operator,
            space,
            node_public,
            agent,
            previous,
            owner_recovery_started.expect("reopen timer starts before locked constructors"),
        );
        return;
    }
    assert!(retained.is_none());
    let package_path = PathBuf::from(
        std::env::var_os("CLERK_AGENT_PACKAGE").expect("genuinely built signed Clerk package"),
    );
    let package =
        vos::agent::package_admission::admit_actor_package(&std::fs::read(&package_path).unwrap())
            .unwrap();
    assert_eq!(package.manifest().name, "clerk-ledger");
    assert_eq!(package.requirements().lanes, LaneSet::of(StateLane::Linear));
    let policy = ActorMethodPolicyArtifact::decode(package.method_policy_bytes()).unwrap();
    let bootstrap = policy
        .methods
        .iter()
        .find(|method| method.name == "bootstrap")
        .unwrap();
    let AuthorizationPolicySelector::ActorRole(operator_role) = bootstrap.authorization_policy
    else {
        panic!("real Clerk bootstrap must require its signed actor role")
    };

    // Use ordinary retirement/reopen, not an election override. The original
    // online issuer comes back after a genuine peer leader already exists.
    let original = std::mem::replace(&mut nodes[0], VosNode::new());
    original.shutdown();
    original
        .collect_checked()
        .expect("healthy issuer retirement");
    let leader = peer_leader(networks, enrollments, record);
    let (node, lifecycle) = open_clean_system_lifecycle_with_roster_policy(
        networks[0].clone(),
        &data[0],
        space.0,
        operator,
        &daemons[0],
        commands::local_config::LocalAgentStorage::Image,
        &data[0].join("host.lock"),
        None,
        false,
        Some(inputs),
    )
    .unwrap();
    assert_eq!(node, enrollments[0].node);
    nodes[0]
        .start_clean_local_agent_production(
            node,
            lifecycle,
            Box::new(OperatorAuthorityProjectionAuthenticator::new(operator.clone()).unwrap()),
            AgentSupervisorLimits::default(),
            PROJECTION_ROUTE_QUEUE_CAPACITY,
            PROJECTION_RECONCILE_INTERVAL,
        )
        .unwrap();
    returned_follower(networks, enrollments, record, leader);
    let address = listen(&mut nodes[0], "public-clerk-origin-follower");
    let mut args = commands::shared_operation::InstallSharedArgs {
        space: "explicit-public-workflow".into(),
        agent: hex::encode(agent.0),
        package: Some(package_path),
        name: Some("clerk-ledger".into()),
        constructor_data: None,
        http: None,
        resume: false,
    };
    let mut retained_install = None;
    let disposition = super::member_handoff::retry_exact("real CLI nonleader Shared Install", || {
        let result = commands::shared_operation::install_shared_for_test(
            &data[0],
            address,
            operator,
            space,
            node_public,
            agent,
            &args,
        );
        // An unavailable reply leaves the ordinary CLI reservation pending.
        // Resume that operation, retaining its nonce and every signed SIQ1
        // byte, rather than requiring the first transport attempt to succeed.
        args.resume = true;
        let root = retained_operation(&data[0], space, &identity, result.is_ok());
        let mut request = commands::clean_store::CleanSharedInstallFile::open_or_create(
            root.join("request"),
        )
        .unwrap();
        if let Some(bytes) = request.load_request().unwrap() {
            match &retained_install {
                Some((previous_root, previous_bytes)) => {
                    assert_eq!(&root, previous_root);
                    assert_eq!(&bytes, previous_bytes);
                }
                None => retained_install = Some((root, bytes)),
            }
        }
        result
    });
    let SharedInstallDisposition::Applied(ack) = disposition else {
        panic!("real public Clerk Install did not apply: {disposition:?}")
    };
    let ManagementReply::Installed(entry) = &ack.application else {
        panic!("public Install returned a different signed terminal")
    };
    assert_eq!(entry.deployment, package.deployment());
    assert_eq!(entry.program, package.program());
    let actor = entry.actor;
    eprintln!(
        "public_clerk_workflow phase=nonleader_install origin={:?} peer_leader={leader:?} elapsed_ms={}",
        enrollments[0].node,
        started.elapsed().as_millis(),
    );
    returned_follower(networks, enrollments, record, leader);
    let install_root = current_operation(&data[0], space, &identity);
    let mut installation =
        commands::clean_store::CleanSharedInstallFile::open_or_create(install_root.join("request"))
            .unwrap();
    let install_request = installation.load_request().unwrap().unwrap();
    let install_response = installation.load_response().unwrap().unwrap();
    let submission =
        vos::agent::local_lifecycle::SharedInstallSubmission::decode(&install_request).unwrap();
    assert!(submission.call().authenticated_node.is_none());
    assert_eq!(submission.call().managed.agent, agent);
    assert_eq!(submission.call().principal, identity.principal());
    assert_eq!(
        submission.call().managed.transition_producer,
        ProducerId::of_public_key(&node_public)
    );
    assert!(matches!(
        submission.decode_response(&install_response).unwrap(),
        SharedInstallDisposition::Applied(_)
    ));
    drop(installation);

    let operation = vos::agent::sdk::authority::AuthorityAdminOperation::SetActorRole {
        principal: identity.principal(),
        agent,
        actor,
        deployment: package.deployment(),
        role: operator_role,
        granted: true,
    };
    let admin_baseline = admin_claim(&data[0], authority, &identity).unwrap();
    assert!(!matches!(
        admin_baseline,
        Some((_, commands::clean_store::CredentialReservationStatus::Pending))
    ));
    let mut retained_admin = None;
    let (_, _, status) = super::member_handoff::retry_exact(
        "real Authority Clerk operator role grant",
        || {
            let result = commands::admin_operation::execute(
                &data[0],
                address,
                operator,
                authority,
                enrollments[0].node,
                retained_admin.is_none().then_some(&operation),
            );
            retain_admin_role_grant(
                &data[0],
                authority,
                enrollments[0].node,
                &identity,
                &operation,
                admin_baseline,
                &mut retained_admin,
            )?;
            if result.is_ok() {
                anyhow::ensure!(retained_admin.is_some(), "role grant has no new admin claim");
            }
            result
        },
    );
    assert_eq!(
        status,
        commands::clean_store::CredentialReservationStatus::Completed
    );
    let journal = [0xd1; 16];
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend(
        vos::value::Msg::new("bootstrap")
            .with("journal_id", journal.to_vec())
            .with("registrar_pubkey", identity.raw_public_key().to_vec())
            .with("code", 1u32)
            .encode(),
    );
    let intent = intent(
        space,
        agent,
        actor,
        &identity,
        &package,
        "bootstrap",
        message,
        InvocationRoleClaims {
            space: None,
            actor: Some(operator_role),
        },
        0xe1,
    );
    let (authorization_root, _) = commands::local_operation::authorize(
        &data[0],
        address,
        operator,
        space,
        node_public,
        Some(&intent),
    )
    .expect("real Authority bootstrap issuance");
    let application_root = authorization_root.parent().unwrap().join("application");
    let mut application =
        commands::clean_store::CleanInvocationFile::open_or_create(&application_root).unwrap();
    let invocation_request = application.load_request().unwrap().unwrap();
    assert!(application.load_response().unwrap().is_none());
    assert!(application.load_progress().unwrap().is_none());
    drop(application);
    let request = commands::local_invocation::validate_request(&invocation_request).unwrap();
    assert_eq!(request.work().invocation, intent.intent().invocation());
    assert!(matches!(
        request.authorization(),
        vos::agent::sdk::InvocationAuthorization::AuthorityReceipt(_)
    ));
    let first_response = if leader_loss {
        exercise_leader_loss(
            nodes,
            networks,
            data,
            operator,
            daemons,
            enrollments,
            space,
            inputs,
            record,
            address,
            actor,
            &package,
            &application_root,
            &invocation_request,
        )
    } else {
        super::member_handoff::retry_exact("public Clerk bootstrap", || {
            commands::local_create::post_binary(
                address,
                "/__agents/invoke",
                200,
                &invocation_request,
                commands::local_invocation::MAX_RESPONSE_BYTES,
            )
        })
    };
    assert_reply(
        &invocation_request,
        &first_response,
        vos::value::Value::Bytes(vec![0]),
    );
    // Simulate losing the successful response before the client's durable
    // publication. Do not ACK: the following all-owner restart must recover
    // this exact first result, rather than asking a retired invocation to run.
    let mut application =
        commands::clean_store::CleanInvocationFile::open_or_create(&application_root).unwrap();
    assert_eq!(
        application.load_request().unwrap().unwrap(),
        invocation_request
    );
    assert!(application.load_response().unwrap().is_none());
    assert!(application.load_progress().unwrap().is_none());
    eprintln!(
        "public_clerk_workflow phase=successful_response_not_published elapsed_ms={}",
        started.elapsed().as_millis()
    );
    *retained = Some(RetainedWorkflow {
        install_root,
        install_request,
        install_response,
        actor,
        authorization_root,
        application_root,
        invocation_request,
        first_response,
        journal,
    });
    for node in nodes {
        assert!(!node.shutdown_handle().load(Ordering::Acquire));
    }
}

pub(super) fn listen(node: &mut VosNode, name: &str) -> SocketAddr {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap();
    drop(probe);
    node.add_http_ingress(vos::ingress::HttpIngressConfig {
        name: name.into(),
        listen: address,
        tls: None,
        max_connections: 8,
    })
    .unwrap();
    address
}

fn stop_member(nodes: &mut [VosNode], index: usize) {
    let previous = std::mem::replace(&mut nodes[index], VosNode::new());
    previous.shutdown();
    previous
        .collect_checked()
        .expect("checked ordinary Shared member retirement");
}

#[allow(clippy::too_many_arguments)]
fn reopen_member(
    nodes: &mut [VosNode],
    networks: &[Arc<Network>],
    data: &[PathBuf],
    operator: &Keypair,
    daemons: &[Keypair],
    members: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    space: SpaceId,
    inputs: &StartupTestInputs,
    index: usize,
) -> SocketAddr {
    let (node, lifecycle) = open_clean_system_lifecycle_with_roster_policy(
        networks[index].clone(),
        &data[index],
        space.0,
        operator,
        &daemons[index],
        commands::local_config::LocalAgentStorage::Image,
        &data[index].join("host.lock"),
        None,
        false,
        Some(inputs),
    )
    .expect("normal locked startup of the retired Shared member");
    assert_eq!(node, members[index].node);
    nodes[index]
        .start_clean_local_agent_production(
            node,
            lifecycle,
            Box::new(OperatorAuthorityProjectionAuthenticator::new(operator.clone()).unwrap()),
            AgentSupervisorLimits::default(),
            PROJECTION_ROUTE_QUEUE_CAPACITY,
            PROJECTION_RECONCILE_INTERVAL,
        )
        .expect("real production attachment of the returning Shared member");
    listen(&mut nodes[index], "public-clerk-returned-leader")
}

fn shared_leader(
    networks: &[Arc<Network>],
    members: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    record: &AgentGenesisArchiveRecord,
    live_indices: &[usize],
    deadline: std::time::Instant,
) -> usize {
    assert!(live_indices.len() >= 2);
    let bytes = record.encode();
    loop {
        let mut statuses = Vec::new();
        for &target in live_indices {
            assert!(
                std::time::Instant::now() < deadline,
                "actual Shared leader observation exceeded its existing phase bound"
            );
            let source = *live_indices.iter().find(|&&index| index != target).unwrap();
            if let Ok(Some(status)) = networks[source]
                .shared_member_raft_status_fixture(&bytes, members[target].node)
            {
                statuses.push((target, status));
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "actual Shared leader observation completed after its existing phase bound"
        );
        let leaders: Vec<_> = statuses
            .iter()
            .filter(|(_, (_, leader, _))| *leader)
            .map(|(index, _)| *index)
            .collect();
        if statuses.len() == live_indices.len() && leaders.len() == 1 {
            let leader = leaders[0];
            if statuses.iter().all(|(_, (follower, actual_leader, hint))| {
                (*follower || *actual_leader) && *hint == Some(members[leader].node)
            }) {
                return leader;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[allow(clippy::too_many_arguments)]
fn wait_shared_routes(
    nodes: &[VosNode],
    live_indices: &[usize],
    space: SpaceId,
    agent: AgentId,
    actor: ActorId,
    package: &AdmittedActorPackage,
    deadline: std::time::Instant,
) {
    let route = AgentRouteKey::new(space, agent, actor).unwrap();
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "live Shared actor routes did not recover within their existing phase bound"
        );
        assert!(live_indices.iter().all(|&index| !nodes[index]
            .shutdown_handle()
            .load(Ordering::Acquire)));
        let ready = live_indices.iter().all(|&index| {
            nodes[index]
                .clean_agent_supervisor()
                .and_then(|supervisor| supervisor.snapshot(route).ok())
                .is_some_and(|snapshot| {
                    snapshot.profile() == vos::agent::sdk::AgentProfile::Shared
                        && snapshot.actor_program() == package.program()
                        && snapshot.actor_deployment() == package.deployment()
                })
        });
        if ready {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[allow(clippy::too_many_arguments)]
fn exercise_leader_loss(
    nodes: &mut [VosNode],
    networks: &[Arc<Network>],
    data: &[PathBuf],
    operator: &Keypair,
    daemons: &[Keypair],
    members: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    space: SpaceId,
    inputs: &StartupTestInputs,
    record: &AgentGenesisArchiveRecord,
    mut address: SocketAddr,
    actor: ActorId,
    package: &AdmittedActorPackage,
    application_root: &Path,
    request: &[u8],
) -> Vec<u8> {
    let all = [0, 1, 2];
    let agent = AgentId(record.provision().proposal().locator().agent.0);
    let mut first_response = None;
    for (cut, phase) in ["before_first_invoke", "after_commit_before_ack"]
        .into_iter()
        .enumerate()
    {
        // Establish three live, independently published actor routes before
        // each fault. If the issuer became Shared leader, ordinary retirement
        // and normal reopen move it behind an actually elected peer first.
        let setup_deadline = std::time::Instant::now() + Duration::from_secs(120);
        wait_shared_routes(nodes, &all, space, agent, actor, package, setup_deadline);
        let mut leader = shared_leader(networks, members, record, &all, setup_deadline);
        if leader == 0 {
            stop_member(nodes, 0);
            shared_leader(networks, members, record, &[1, 2], setup_deadline);
            address = reopen_member(
                nodes, networks, data, operator, daemons, members, space, inputs, 0,
            );
            wait_shared_routes(nodes, &all, space, agent, actor, package, setup_deadline);
            leader = shared_leader(networks, members, record, &all, setup_deadline);
        }
        assert_ne!(
            leader, 0,
            "original management issuer must stay online during the fault"
        );
        assert_pending_application(application_root, request);
        assert_eq!(first_response.is_some(), cut == 1);
        let live: Vec<_> = all.into_iter().filter(|&index| index != leader).collect();
        let loss_started = std::time::Instant::now();
        let deadline = loss_started + Duration::from_secs(30);
        stop_member(nodes, leader);
        // Observe this ordinary Shared generation only. Its election is
        // independent of the System leader used by Authority observations.
        shared_leader(networks, members, record, &live, deadline);
        let response = super::member_handoff::retry_exact_until(phase, deadline, || {
            commands::local_create::post_binary(
                address,
                "/__agents/invoke",
                200,
                request,
                commands::local_invocation::MAX_RESPONSE_BYTES,
            )
        });
        assert_reply(request, &response, vos::value::Value::Bytes(vec![0]));
        if let Some(first) = &first_response {
            assert!(
                &response == first,
                "leader loss changed the exact committed pre-ACK result"
            );
        } else {
            first_response = Some(response);
        }
        assert!(loss_started.elapsed() <= Duration::from_secs(30));
        eprintln!(
            "public_shared_leader_loss phase={phase} recovery_ms={}",
            loss_started.elapsed().as_millis(),
        );
        assert!(!nodes[0].shutdown_handle().load(Ordering::Acquire));

        // Return this one owner before any next fault. Include its real locked
        // constructor and attachment in the separately recorded reopen phase;
        // it must independently return the unchanged body/result before ACK.
        let reopen_started = std::time::Instant::now();
        let reopen_deadline = reopen_started + Duration::from_secs(30);
        let returned = reopen_member(
            nodes, networks, data, operator, daemons, members, space, inputs, leader,
        );
        wait_shared_routes(nodes, &all, space, agent, actor, package, reopen_deadline);
        shared_leader(networks, members, record, &all, reopen_deadline);
        let repeated = super::member_handoff::retry_exact_until(
            "returning Shared leader exact pre-ACK result",
            reopen_deadline,
            || {
                commands::local_create::post_binary(
                    returned,
                    "/__agents/invoke",
                    200,
                    request,
                    commands::local_invocation::MAX_RESPONSE_BYTES,
                )
            },
        );
        assert!(
            &repeated == first_response.as_ref().unwrap(),
            "returning Shared owner changed the original request's exact result"
        );
        assert_reply(request, &repeated, vos::value::Value::Bytes(vec![0]));
        assert_pending_application(application_root, request);
        assert!(reopen_started.elapsed() <= Duration::from_secs(30));
        eprintln!(
            "public_shared_leader_loss phase=returning_owner_exact_result cut={cut} reopen_ms={}",
            reopen_started.elapsed().as_millis(),
        );
    }
    first_response.unwrap()
}

fn assert_pending_application(application_root: &Path, request: &[u8]) {
    let mut application =
        commands::clean_store::CleanInvocationFile::open_or_create(application_root).unwrap();
    assert!(
        application.load_request().unwrap().as_deref() == Some(request),
        "leader arrangement changed the retained client request"
    );
    assert!(application.load_response().unwrap().is_none());
    assert!(application.load_progress().unwrap().is_none());
}

pub(super) fn peer_leader(
    networks: &[Arc<Network>],
    members: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    record: &AgentGenesisArchiveRecord,
) -> vos::agent::sdk::NodeId {
    let bytes = record.encode();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        for (source, target) in [(2, 1), (1, 2)] {
            match networks[source].shared_member_raft_status_fixture(&bytes, members[target].node) {
                Ok(Some((false, true, Some(leader)))) if leader == members[target].node => {
                    return leader;
                }
                Ok(_) => {}
                Err(error) => eprintln!("public Clerk peer status retry: {error}"),
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "actual peer ordinary-Agent election did not complete"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(super) fn returned_follower(
    networks: &[Arc<Network>],
    members: &[vos::agent::sdk::private::NodeEncryptionEnrollment],
    record: &AgentGenesisArchiveRecord,
    leader: vos::agent::sdk::NodeId,
) {
    let bytes = record.encode();
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        match networks[1].shared_member_raft_status_fixture(&bytes, members[0].node) {
            Ok(Some((true, false, Some(observed)))) if observed == leader => return,
            Ok(_) => {}
            Err(error) => eprintln!("public Clerk returning issuer status retry: {error}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "returned original issuer was not a real follower of the peer leader"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn admin_claim(
    data: &Path,
    authority: AuthorityActorTarget,
    identity: &commands::clean_identity::CleanOperatorIdentitySigner<'_>,
) -> anyhow::Result<
    Option<(
        vos::agent::sdk::Hash,
        commands::clean_store::CredentialReservationStatus,
    )>,
> {
    let root = data.join("admin-client");
    commands::clean_store::ensure_private_directory(&root)?;
    let claims = root.join("credentials");
    commands::clean_store::ensure_private_directory(&claims)?;
    let mut reservation = commands::clean_store::CleanAdminCredentialReservation::open_or_create(
        &claims,
        authority.space,
        identity.credential(),
    )?;
    Ok(reservation.current()?)
}

struct RetainedAdminRoleGrant {
    nonce: vos::agent::sdk::Hash,
    draft: Vec<u8>,
    preparation: Option<Vec<u8>>,
    submission: Option<Vec<u8>>,
    response: Option<Vec<u8>>,
}

#[allow(clippy::too_many_arguments)]
fn retain_admin_role_grant(
    data: &Path,
    authority: AuthorityActorTarget,
    node: vos::agent::sdk::NodeId,
    identity: &commands::clean_identity::CleanOperatorIdentitySigner<'_>,
    operation: &vos::agent::sdk::authority::AuthorityAdminOperation,
    baseline: Option<(
        vos::agent::sdk::Hash,
        commands::clean_store::CredentialReservationStatus,
    )>,
    retained: &mut Option<RetainedAdminRoleGrant>,
) -> anyhow::Result<()> {
    let current = admin_claim(data, authority, identity)?;
    if current == baseline {
        // Credential discovery precedes draft retention and claim publication.
        // No new mutation exists yet, and the previous claim is not resumable
        // as this role grant, even when it was already completed.
        anyhow::ensure!(retained.is_none(), "new admin claim disappeared");
        return Ok(());
    }
    let (nonce, status) = current.ok_or_else(|| anyhow::anyhow!("admin claim disappeared"))?;
    anyhow::ensure!(
        baseline.is_none_or(|(previous, _)| previous != nonce),
        "previous admin claim changed without a new operation"
    );
    let root = data.join("admin-client/requests").join(hex::encode(nonce.0));
    let mut preparation = commands::clean_store::CleanOperationClientFile::open_admin_preparation(
        root.join("preparation"),
    )?;
    let draft_bytes = preparation
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("new admin claim has no retained draft"))?;
    let draft = vos::agent::sdk::authority::AuthorityAdminCall::decode(&draft_bytes)
        .map_err(|_| anyhow::anyhow!("invalid retained admin draft"))?;
    anyhow::ensure!(
        draft.authority == authority
            && draft.authenticated_node == node
            && draft.administrator == identity.principal()
            && draft.credential == identity.credential()
            && draft.credential_public_key == identity.raw_public_key()
            && draft.observed_slot == 0
            && &draft.operation == operation
            && draft.verify_with(&commands::local_create::CredentialVerifier).is_ok(),
        "new admin claim differs from the exact role grant"
    );
    let preparation_bytes = preparation.load_response()?;
    drop(preparation);
    let mut delivery = commands::clean_store::CleanOperationClientFile::open_admin_submission(
        root.join("submission"),
    )?;
    let submission_bytes = delivery.load_request()?;
    let response = delivery.load_response()?;
    if let Some(bytes) = &submission_bytes {
        let submission = vos::agent::clean_bootstrap::NativeAuthorityAdminSubmission::decode(bytes)
            .map_err(|_| anyhow::anyhow!("invalid retained admin submission"))?;
        let prepared = submission
            .preparation()
            .encode()
            .map_err(|_| anyhow::anyhow!("invalid retained admin preparation"))?;
        anyhow::ensure!(
            preparation_bytes.as_deref() == Some(prepared.as_slice()),
            "admin submission lost its exact retained preparation"
        );
        let mut expected = submission
            .preparation()
            .call_to_sign(&draft)
            .map_err(|_| anyhow::anyhow!("admin submission differs from retained draft"))?;
        expected.signature = submission.call().signature;
        anyhow::ensure!(
            &expected == submission.call(),
            "admin submission differs from retained draft"
        );
    }
    if status != commands::clean_store::CredentialReservationStatus::Pending {
        anyhow::ensure!(
            submission_bytes.is_some() && response.is_some(),
            "terminal admin claim lost retained delivery evidence"
        );
    }
    let snapshot = RetainedAdminRoleGrant {
        nonce,
        draft: draft_bytes,
        preparation: preparation_bytes,
        submission: submission_bytes,
        response,
    };
    if let Some(previous) = retained {
        anyhow::ensure!(
            previous.nonce == snapshot.nonce && previous.draft == snapshot.draft,
            "role grant changed its retained operation or draft"
        );
        for (before, after) in [
            (&previous.preparation, &snapshot.preparation),
            (&previous.submission, &snapshot.submission),
            (&previous.response, &snapshot.response),
        ] {
            if let Some(bytes) = before {
                anyhow::ensure!(
                    after.as_deref() == Some(bytes.as_slice()),
                    "role grant changed previously retained evidence"
                );
            }
        }
    }
    *retained = Some(snapshot);
    Ok(())
}

#[test]
fn role_grant_retry_requires_a_new_claim_bound_to_the_complete_operation() {
    use commands::clean_store::{
        CleanAdminCredentialReservation, CleanOperationClientFile, CredentialReservationStatus,
    };
    use vos::agent::sdk::authority::{AuthorityAdminCall, AuthorityAdminOperation};
    use vos::agent::sdk::{DeploymentId, Hash, InvocationId, NodeId, RoleId};

    let fixture = commands::clean_store::tests::Fixture::new("role-grant-retry");
    let (operator, authority, _, _) = commands::local_create::tests::fixture();
    let identity = commands::clean_identity::CleanOperatorIdentitySigner::new(&operator).unwrap();
    let node = NodeId([0x91; 32]);
    let operation = AuthorityAdminOperation::SetActorRole {
        principal: identity.principal(),
        agent: AgentId([0x92; 32]),
        actor: ActorId([0x93; 32]),
        deployment: DeploymentId([0x94; 32]),
        role: RoleId([0x95; 32]),
        granted: true,
    };
    let mut draft = AuthorityAdminCall {
        invocation: InvocationId::ZERO,
        authority,
        administrator: identity.principal(),
        credential: identity.credential(),
        request_sequence: std::num::NonZeroU64::new(1).unwrap(),
        credential_public_key: identity.raw_public_key(),
        authenticated_node: node,
        observed_slot: 0,
        expected_generation: std::num::NonZeroU64::new(1).unwrap(),
        operation: operation.clone(),
        signature: [0; 64],
    };
    draft.invocation = draft.expected_invocation();
    draft.signature = operator.sign(&draft.signing_bytes()).unwrap().try_into().unwrap();
    let baseline = admin_claim(&fixture.parent, authority, &identity).unwrap();
    assert!(baseline.is_none());
    let nonce = Hash([0x96; 32]);
    let root = fixture.parent.join("admin-client/requests").join(hex::encode(nonce.0));
    commands::clean_store::ensure_private_directory(&fixture.parent.join("admin-client/requests"))
        .unwrap();
    commands::clean_store::ensure_private_directory(&root).unwrap();
    let mut preparation = CleanOperationClientFile::open_admin_preparation(root.join("preparation"))
        .unwrap();
    preparation.publish_request(&draft.encode().unwrap()).unwrap();
    drop(preparation);
    let mut retained = None;
    // A retained discovery or draft does not publish a credential claim.
    retain_admin_role_grant(
        &fixture.parent, authority, node, &identity, &operation, baseline, &mut retained,
    )
    .unwrap();
    assert!(retained.is_none());
    let mut reservation = CleanAdminCredentialReservation::open_or_create(
        &fixture.parent.join("admin-client/credentials"), authority.space, identity.credential(),
    )
    .unwrap();
    assert_eq!(reservation.reserve(nonce, &draft).unwrap(), CredentialReservationStatus::Pending);
    drop(reservation);
    retain_admin_role_grant(
        &fixture.parent, authority, node, &identity, &operation, baseline, &mut retained,
    )
    .unwrap();
    assert_eq!(retained.as_ref().unwrap().nonce, nonce);
    assert_eq!(retained.as_ref().unwrap().draft, draft.encode().unwrap());
    let mut wrong_operation = operation.clone();
    let AuthorityAdminOperation::SetActorRole { granted, .. } = &mut wrong_operation else {
        unreachable!()
    };
    *granted = false;
    assert!(retain_admin_role_grant(
        &fixture.parent, authority, node, &identity, &wrong_operation, baseline, &mut retained,
    ).is_err());
    assert!(retain_admin_role_grant(
        &fixture.parent, authority, NodeId([0x97; 32]), &identity, &operation, baseline, &mut retained,
    ).is_err());
    // A changed phase on the old nonce cannot establish a new role grant.
    assert!(retain_admin_role_grant(
        &fixture.parent, authority, node, &identity, &operation,
        Some((nonce, CredentialReservationStatus::Completed)), &mut None,
    ).is_err());
    retain_admin_role_grant(
        &fixture.parent, authority, node, &identity, &operation, baseline, &mut retained,
    )
    .unwrap();
}

pub(super) fn current_operation(
    data: &Path,
    space: SpaceId,
    identity: &commands::clean_identity::CleanOperatorIdentitySigner<'_>,
) -> PathBuf {
    retained_operation(data, space, identity, true)
}

fn retained_operation(
    data: &Path,
    space: SpaceId,
    identity: &commands::clean_identity::CleanOperatorIdentitySigner<'_>,
    require_completed: bool,
) -> PathBuf {
    let mut reservation = commands::clean_store::CleanCredentialReservation::open_or_create(
        &data.join("agent-client/credentials"),
        space,
        identity.credential(),
    )
    .unwrap();
    let (nonce, status) = reservation.current().unwrap().unwrap();
    if require_completed {
        assert_eq!(
            status,
            commands::clean_store::CredentialReservationStatus::Completed
        );
    }
    data.join("agent-client/operations").join(format!(
        "{}-{}",
        hex::encode(identity.credential().0),
        hex::encode(nonce.0),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn intent(
    space: SpaceId,
    agent: AgentId,
    actor: ActorId,
    operator: &commands::clean_identity::CleanOperatorIdentitySigner<'_>,
    package: &AdmittedActorPackage,
    method: &str,
    message: Vec<u8>,
    roles: InvocationRoleClaims,
    nonce: u8,
) -> AgentTargetedPreparationRequest {
    let policy = ActorMethodPolicyArtifact::decode(package.method_policy_bytes()).unwrap();
    let mode = policy
        .methods
        .iter()
        .find(|candidate| candidate.name == method)
        .unwrap()
        .mode;
    AgentTargetedPreparationRequest::new(
        AgentRouteKey::new(space, agent, actor).unwrap(),
        AgentInvocationIntent::new(
            InvocationId([nonce; 32]),
            mode,
            InvocationOrigin {
                principal: Some(operator.principal()),
                credential: Some(operator.credential()),
                ..InvocationOrigin::anonymous()
            },
            roles,
            message,
            vos::agent::execution::MAX_EXECUTION_GAS,
            false,
        )
        .unwrap(),
    )
    .unwrap()
}

pub(super) fn assert_reply(request: &[u8], bytes: &[u8], expected: vos::value::Value) {
    let response = commands::local_invocation::verify_response(request, bytes).unwrap();
    let vos::agent::supervisor_adapters::AgentInvocationResponse::Direct {
        outcome: RuntimeOutcome::Completed(Ok(reply)),
        ..
    } = response
    else {
        panic!("real public Clerk invocation did not complete successfully: {response:?}")
    };
    assert_eq!(vos::value::Value::decode(&reply.reply), expected);
}

#[allow(clippy::too_many_arguments)]
fn resume_after_reopen(
    nodes: &[VosNode],
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    agent: AgentId,
    previous: &RetainedWorkflow,
    started: std::time::Instant,
) {
    // This measures locked-owner reopen with the existing transports alive.
    // The caller starts it before every constructor and production attachment.
    let deadline = started + Duration::from_secs(30);
    let (_, install_response) =
        super::member_handoff::retry_exact_until("reopened public Install exact retry", deadline, || {
            commands::local_create::post_shared_install_response(address, &previous.install_request)
        });
    assert_eq!(install_response, previous.install_response);
    let mut installed = commands::clean_store::CleanSharedInstallFile::open_or_create(
        previous.install_root.join("request"),
    )
    .unwrap();
    assert_eq!(
        installed.load_request().unwrap().unwrap(),
        previous.install_request
    );
    assert_eq!(
        installed.load_response().unwrap().unwrap(),
        previous.install_response
    );
    drop(installed);
    // Before applying the pending bootstrap, the credential still names that
    // operation, not Install. Do not reinterpret it through another command.
    // The retained SIQ1/SIR1 pair above independently proves the exact terminal.
    let mut application =
        commands::clean_store::CleanInvocationFile::open_or_create(&previous.application_root)
            .unwrap();
    assert_eq!(
        application.load_request().unwrap().unwrap(),
        previous.invocation_request
    );
    assert!(application.load_response().unwrap().is_none());
    drop(application);
    let repeated = super::member_handoff::retry_exact_until(
        "reopened lost bootstrap response",
        deadline,
        || {
            commands::local_create::post_binary(
                address,
                "/__agents/invoke",
                200,
                &previous.invocation_request,
                commands::local_invocation::MAX_RESPONSE_BYTES,
            )
        },
    );
    assert_eq!(repeated, previous.first_response);
    assert_reply(
        &previous.invocation_request,
        &repeated,
        vos::value::Value::Bytes(vec![0]),
    );
    assert!(std::time::Instant::now() < deadline);
    commands::local_invocation::submit(&previous.application_root, None, address).unwrap();
    assert!(std::time::Instant::now() <= deadline);
    let (authorization_root, _) = commands::local_operation::authorize_with_application(
        data,
        address,
        operator,
        space,
        node_public,
        None,
        true,
    )
    .expect("real CLI exact bootstrap application and ACK resume");
    assert!(std::time::Instant::now() <= deadline);
    assert_eq!(authorization_root, previous.authorization_root);
    let mut application =
        commands::clean_store::CleanInvocationFile::open_or_create(&previous.application_root)
            .unwrap();
    let response = application.load_response().unwrap().unwrap();
    let progress = application.load_progress().unwrap().unwrap();
    assert_eq!(response, previous.first_response);
    assert!(
        commands::invocation_progress::Progress::decode(
            &progress,
            &previous.invocation_request,
            &response,
        )
        .unwrap()
        .is_retired(&previous.invocation_request, &response)
        .unwrap()
    );
    let package_path = PathBuf::from(std::env::var_os("CLERK_AGENT_PACKAGE").unwrap());
    let package =
        vos::agent::package_admission::admit_actor_package(&std::fs::read(package_path).unwrap())
            .unwrap();
    wait_shared_routes(
        nodes,
        &[0, 1, 2],
        space,
        agent,
        previous.actor,
        &package,
        deadline,
    );
    assert!(
        started.elapsed() <= Duration::from_secs(30),
        "whole locked-owner constructor/attachment/handoff/exact result, ACK and required route recovery exceeded 30s"
    );
    let recovery_ms = started.elapsed().as_millis();
    eprintln!(
        "public_clerk_workflow phase=exact_reopen_result_and_ack scope=locked_owner_reopen recovery_ms={recovery_ms}"
    );
    drop(application);
    let identity = commands::clean_identity::CleanOperatorIdentitySigner::new(operator).unwrap();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend(vos::value::Msg::new("journal_id").encode());
    let query = intent(
        space,
        agent,
        previous.actor,
        &identity,
        &package,
        "journal_id",
        message,
        InvocationRoleClaims::none(),
        0xe2,
    );
    let (root, _) = commands::local_operation::authorize_with_application(
        data,
        address,
        operator,
        space,
        node_public,
        Some(&query),
        true,
    )
    .expect("real public Clerk state query after all-owner reopen");
    let mut application = commands::clean_store::CleanInvocationFile::open_or_create(
        root.parent().unwrap().join("application"),
    )
    .unwrap();
    assert_reply(
        &application.load_request().unwrap().unwrap(),
        &application.load_response().unwrap().unwrap(),
        vos::value::Value::Bytes(previous.journal.to_vec()),
    );
    eprintln!(
        "public_clerk_workflow phase=persisted_journal_read scope=locked_owner_reopen recovery_ms={recovery_ms} probe_inclusive_ms={}",
        started.elapsed().as_millis()
    );
}
