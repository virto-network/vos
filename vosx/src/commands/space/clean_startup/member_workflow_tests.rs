//! Candidate public Clerk vertical slice through real locked startup, HTTP,
//! signed Authority decisions and retained CLI delivery. This is not load,
//! release-artifact, or the end-to-end recovery-deadline qualification.

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
            &data[0],
            address,
            operator,
            space,
            node_public,
            agent,
            previous,
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
        let root = current_operation(&data[0], space, &identity);
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
    let (_, _, status) = commands::admin_operation::execute(
        &data[0],
        address,
        operator,
        authority,
        enrollments[0].node,
        Some(&operation),
    )
    .expect("real Authority Clerk operator role grant");
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
    let first_response = super::member_handoff::retry_exact("public Clerk bootstrap", || {
        commands::local_create::post_binary(
            address,
            "/__agents/invoke",
            200,
            &invocation_request,
            commands::local_invocation::MAX_RESPONSE_BYTES,
        )
    });
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

pub(super) fn current_operation(
    data: &Path,
    space: SpaceId,
    identity: &commands::clean_identity::CleanOperatorIdentitySigner<'_>,
) -> PathBuf {
    let mut reservation = commands::clean_store::CleanCredentialReservation::open_or_create(
        &data.join("agent-client/credentials"),
        space,
        identity.credential(),
    )
    .unwrap();
    let (nonce, status) = reservation.current().unwrap().unwrap();
    assert_eq!(
        status,
        commands::clean_store::CredentialReservationStatus::Completed
    );
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
    data: &Path,
    address: SocketAddr,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    agent: AgentId,
    previous: &RetainedWorkflow,
) {
    let started = std::time::Instant::now();
    let (_, install_response) =
        super::member_handoff::retry_exact("reopened public Install exact retry", || {
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
    let repeated = super::member_handoff::retry_exact("reopened lost bootstrap response", || {
        commands::local_create::post_binary(
            address,
            "/__agents/invoke",
            200,
            &previous.invocation_request,
            commands::local_invocation::MAX_RESPONSE_BYTES,
        )
    });
    assert_eq!(repeated, previous.first_response);
    assert_reply(
        &previous.invocation_request,
        &repeated,
        vos::value::Value::Bytes(vec![0]),
    );
    commands::local_invocation::submit(&previous.application_root, None, address).unwrap();
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
    eprintln!(
        "public_clerk_workflow phase=exact_reopen_result_and_ack elapsed_ms={}",
        started.elapsed().as_millis()
    );
    drop(application);
    let identity = commands::clean_identity::CleanOperatorIdentitySigner::new(operator).unwrap();
    let package_path = PathBuf::from(std::env::var_os("CLERK_AGENT_PACKAGE").unwrap());
    let package =
        vos::agent::package_admission::admit_actor_package(&std::fs::read(package_path).unwrap())
            .unwrap();
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
        "public_clerk_workflow phase=persisted_journal_read elapsed_ms={}",
        started.elapsed().as_millis()
    );
}
