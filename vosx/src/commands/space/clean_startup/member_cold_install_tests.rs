//! Pending Shared Install recovery through the actual locked startup and public
//! client retry. Candidate guests/test roster policy are not packaged-release,
//! daemon-crash, load, or hardware qualification.

use super::*;
use crate::commands::space as commands;
use vos::Encode as _;
use vos::agent::genesis::AgentGenesisArchiveRecord;
use vos::agent::local_lifecycle::{SharedInstallDisposition, SharedInstallSubmission};
use vos::agent::sdk::{InvocationRoleClaims, ManagementReply};
use vos::agent::shared_host::SharedAgentHostError;

pub(super) struct RetainedColdInstall {
    request_root: PathBuf,
    request: Vec<u8>,
    response: Option<Vec<u8>>,
}

pub(super) struct Inputs<'a> {
    pub nodes: &'a mut [VosNode],
    pub networks: &'a [Arc<Network>],
    pub data: &'a [PathBuf],
    pub operator: &'a Keypair,
    pub daemons: &'a [Keypair],
    pub enrollments: &'a [vos::agent::sdk::private::NodeEncryptionEnrollment],
    pub space: SpaceId,
    pub authority: AuthorityActorTarget,
    pub startup: &'a StartupTestInputs,
    pub archive: &'a AgentGenesisArchiveRecord,
}

impl Inputs<'_> {
    fn open_origin(&self) -> (vos::agent::sdk::NodeId, CleanProductionLifecycle) {
        open_clean_system_lifecycle_with_inputs(
            self.networks[0].clone(),
            &self.data[0],
            self.space.0,
            self.operator,
            &self.daemons[0],
            commands::local_config::LocalAgentStorage::Image,
            &self.data[0].join("host.lock"),
            None,
            Some(self.startup),
        )
        .expect("same locked persisted owner startup")
    }

    fn start_origin(&mut self) {
        let (node, lifecycle) = self.open_origin();
        assert_eq!(node, self.enrollments[0].node);
        self.nodes[0]
            .start_clean_local_agent_production(
                node,
                lifecycle,
                Box::new(
                    OperatorAuthorityProjectionAuthenticator::new(self.operator.clone()).unwrap(),
                ),
                AgentSupervisorLimits::default(),
                PROJECTION_ROUTE_QUEUE_CAPACITY,
                PROJECTION_RECONCILE_INTERVAL,
            )
            .expect("ordinary released owner/route attachment");
    }
}

pub(super) fn exercise(
    mut ctx: Inputs<'_>,
    restart: bool,
    returning: bool,
    recovery_started: std::time::Instant,
    retained: &mut Option<RetainedColdInstall>,
) {
    if restart {
        finish(
            &mut ctx,
            retained
                .as_mut()
                .expect("actual receipt-stage cut retained"),
            recovery_started,
        );
        return;
    }
    assert!(retained.is_none());
    let package_path =
        PathBuf::from(std::env::var_os("CLERK_AGENT_PACKAGE").expect("real signed Clerk package"));
    let package =
        vos::agent::package_admission::admit_actor_package(&std::fs::read(package_path).unwrap())
            .unwrap();
    assert_eq!(package.manifest().name, "clerk-ledger");
    let agent = AgentId(ctx.archive.provision().proposal().locator().agent.0);
    let address = member_workflow::listen(&mut ctx.nodes[0], "cold-install-signing");
    let (request_root, submission) = commands::shared_operation::retain_install_for_test(
        &ctx.data[0],
        address,
        ctx.operator,
        ctx.space,
        raw_public_key(&ctx.daemons[0]).unwrap(),
        agent,
        package,
    )
    .expect("actual CLI discovery, signing, reservation and immutable SIQ1 publication");
    assert!(submission.call().authenticated_node.is_none());
    assert_eq!(submission.call().authority, ctx.authority);
    let request = submission.encode();

    // Fault setup alone calls native completion. After this cut, recovery is
    // exclusively the locked constructor, production attachment and public retry.
    let original = std::mem::replace(&mut ctx.nodes[0], VosNode::new());
    original.shutdown();
    original
        .collect_checked()
        .expect("issuer lease retirement before fault setup");
    let leader = member_workflow::peer_leader(ctx.networks, ctx.enrollments, ctx.archive);
    let (_, mut lifecycle) = ctx.open_origin();
    member_workflow::returned_follower(ctx.networks, ctx.enrollments, ctx.archive, leader);
    lifecycle
        .prepare_shared_install(
            submission.install().clone(),
            submission.call().clone(),
            submission.package(),
        )
        .expect("retain the original actual signed Install");
    let ordinary_root = ctx.data[0]
        .join(SHARED_AGENT_HOST_DIRECTORY)
        .join(format!("{}.agent", hex::encode(agent.0)));
    // This is only the journal directory. Term/vote/heartbeat/LeaderNoop
    // metadata lives in the separate authority-root *.shared-raft.redb;
    // its foundation apply path does not publish journal state. No actor
    // request or ordinary projection/checkpoint is issued before this cut.
    let unapplied = journal_files(&ordinary_root);
    let issuer_root = ctx.data[0]
        .join(commands::clean_store::SHARED_LIFECYCLE_DIRECTORY)
        .join(hex::encode(agent.0));
    let fault = commands::clean_store::SharedManagementStageFault::issuer(&issuer_root, 2);
    let setup_deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        let result =
            lifecycle.complete_shared_install(ctx.archive.provision().proposal().locator());
        if fault.fired() {
            assert!(matches!(result, Err(SharedAgentHostError::Unavailable)));
            break;
        }
        assert!(
            matches!(result, Err(SharedAgentHostError::Unavailable)),
            "pre-cut completion must remain transient, not apply or reinterpret failure: {result:?}",
        );
        assert!(
            std::time::Instant::now() < setup_deadline,
            "real issuer receipt cut not reached"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(issuer_root.join("shared-management.issuer.next").is_file());
    assert_eq!(
        journal_files(&ordinary_root),
        unapplied,
        "signed receipt cut precedes actor Install"
    );
    let mut client =
        commands::clean_store::CleanSharedInstallFile::open_or_create(&request_root).unwrap();
    assert_eq!(client.load_request().unwrap().unwrap(), request);
    assert!(client.load_response().unwrap().is_none());
    drop(client);
    drop(fault);
    drop(lifecycle);
    let mut saved = RetainedColdInstall {
        request_root,
        request,
        response: None,
    };
    if returning {
        // Warm peers continue running. No explicit recover/finalize/ACK call is
        // allowed: constructor must recover pending Install before publication.
        let started = std::time::Instant::now();
        ctx.start_origin();
        member_workflow::returned_follower(ctx.networks, ctx.enrollments, ctx.archive, leader);
        finish(&mut ctx, &mut saved, started);
        member_workflow::returned_follower(ctx.networks, ctx.enrollments, ctx.archive, leader);
    }
    // In all-cold mode the parent drops both warm peers next, then opens all
    // three locked owners concurrently from this exact pending state.
    *retained = Some(saved);
}

fn finish(ctx: &mut Inputs<'_>, saved: &mut RetainedColdInstall, started: std::time::Instant) {
    let deadline = started + Duration::from_secs(30);
    let submission = SharedInstallSubmission::decode(&saved.request).unwrap();
    let agent = submission.call().managed.agent;
    let actor = submission.install().entry.actor;
    let address = member_workflow::listen(&mut ctx.nodes[0], "cold-install-public-recovered");
    let args = commands::shared_operation::InstallSharedArgs {
        space: "explicit-cold-install".into(),
        agent: hex::encode(agent.0),
        package: None,
        name: None,
        constructor_data: None,
        http: None,
        resume: true,
    };
    let disposition = loop {
        // Fixture-only exact public retry: production keeps its typed fatal
        // classifications. Flattened CLI errors are never completion evidence;
        // the absolute elapsed assertion still rejects nested-wait overruns.
        assert!(
            std::time::Instant::now() < deadline,
            "whole pending Install recovery exceeded 30s"
        );
        // Once a usable query completes, its credential reservation supersedes
        // the finished Install. Retry that prior terminal directly, not via the
        // CLI current-operation selector for an unrelated later reservation.
        let result = if saved.response.is_some() {
            commands::local_create::post_shared_install_response(address, &saved.request).and_then(
                |(status, bytes)| {
                    anyhow::ensure!(status == 201, "completed Install retry must remain Applied");
                    submission
                        .decode_response(&bytes)
                        .map_err(|error| anyhow::anyhow!("exact completed SIR1: {error:?}"))
                },
            )
        } else {
            commands::shared_operation::install_shared_for_test(
                &ctx.data[0],
                address,
                ctx.operator,
                ctx.space,
                raw_public_key(&ctx.daemons[0]).unwrap(),
                agent,
                &args,
            )
        };
        match result {
            Ok(result) => break result,
            Err(error) => {
                eprintln!("exact pending public SIQ1 retry: {error:#}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    let SharedInstallDisposition::Applied(ack) = disposition else {
        panic!("pending valid Install recovered a different terminal: {disposition:?}");
    };
    let ManagementReply::Installed(entry) = &ack.application else {
        panic!("pending Install returned a different management application");
    };
    assert_eq!(entry.actor, actor);
    assert_eq!(entry.program, submission.package().program());
    assert_eq!(entry.deployment, submission.package().deployment());
    let mut client =
        commands::clean_store::CleanSharedInstallFile::open_or_create(&saved.request_root).unwrap();
    assert_eq!(client.load_request().unwrap().unwrap(), saved.request);
    let response = client.load_response().unwrap().unwrap();
    assert!(matches!(
        submission.decode_response(&response).unwrap(),
        SharedInstallDisposition::Applied(_)
    ));
    if let Some(previous) = &saved.response {
        assert_eq!(&response, previous);
    }
    drop(client);
    let (status, exact) =
        commands::local_create::post_shared_install_response(address, &saved.request)
            .expect("exact public SIQ1 retry after terminal");
    assert_eq!(status, 201);
    assert_eq!(
        exact, response,
        "exact signed SIR1 survives retry and all-owner reopen"
    );
    let route = vos::agent::supervisor::AgentRouteKey::new(ctx.space, agent, actor).unwrap();
    let ready = loop {
        if let Some(supervisor) = ctx.nodes[0].clean_agent_supervisor() {
            if let Ok(snapshot) = supervisor.snapshot(route) {
                break snapshot;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "exact actor route not independently ready in 30s"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(ready.actor_program(), submission.package().program());
    assert_eq!(ready.actor_deployment(), submission.package().deployment());
    assert_eq!(
        ready.runtime_deployment(),
        submission.call().managed.runtime_deployment
    );
    assert_eq!(ready.profile(), vos::agent::sdk::AgentProfile::Shared);
    assert!(
        started.elapsed() <= Duration::from_secs(30),
        "whole constructor/attachment/exact original SIR1 recovery: {:?}",
        started.elapsed()
    );
    let recovery_ms = started.elapsed().as_millis();
    eprintln!(
        "cold_pending_shared_install phase=exact_terminal_and_ready_route recovery_ms={recovery_ms}"
    );

    // A genuine signed journal_id read of the fresh unbootstrapped Clerk
    // (empty bytes) is a separate serving probe: no bootstrap/role grant is
    // invented as part of recovery or substituted by directory-only evidence.
    let identity =
        commands::clean_identity::CleanOperatorIdentitySigner::new(ctx.operator).unwrap();
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend(vos::value::Msg::new("journal_id").encode());
    let intent = member_workflow::intent(
        ctx.space,
        agent,
        actor,
        &identity,
        submission.package(),
        "journal_id",
        message,
        InvocationRoleClaims::none(),
        if saved.response.is_none() { 0xe8 } else { 0xe9 },
    );
    let (root, _) = commands::local_operation::authorize_with_application(
        &ctx.data[0],
        address,
        ctx.operator,
        ctx.space,
        raw_public_key(&ctx.daemons[0]).unwrap(),
        Some(&intent),
        true,
    )
    .expect("fresh public Clerk query and normal CLI ACK after startup recovery");
    let mut application = commands::clean_store::CleanInvocationFile::open_or_create(
        root.parent().unwrap().join("application"),
    )
    .unwrap();
    member_workflow::assert_reply(
        &application.load_request().unwrap().unwrap(),
        &application.load_response().unwrap().unwrap(),
        vos::value::Value::Bytes(Vec::new()),
    );
    eprintln!(
        "cold_pending_shared_install phase=public_usable recovery_ms={recovery_ms} probe_inclusive_ms={}",
        started.elapsed().as_millis()
    );
    for node in ctx.nodes.iter() {
        assert!(!node.shutdown_handle().load(Ordering::Acquire));
    }
    saved.response = Some(response);
}
