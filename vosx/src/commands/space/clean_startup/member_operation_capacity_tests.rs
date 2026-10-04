//! Genuine cumulative native-authorize qualification, not a signing fixture or
//! throughput/load qualification. The final cycle measures scoped <=30s locked
//! owner reopen and exact archived native-result recovery. Uses Root's normal
//! public credential and actual Clerk query Invokes/positive ACKs. Transports
//! remain running; whole-process and every-member readiness are separate gates.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use vos::Encode as _;
use vos::agent::clean_bootstrap::NativeAuthorityOperationDecision;
use vos::agent::local_lifecycle::AuthorityOperationSubmission;
use vos::agent::sdk::Hash;
use vos::agent::sdk::wire::CanonicalWire as _;

const OPERATIONS: u64 = 257;

pub(in super::super) struct RetainedCapacity {
    request_root: PathBuf,
    application_root: PathBuf,
    authorization_request: Vec<u8>,
    authorization_response: Vec<u8>,
    application_request: Vec<u8>,
    application_response: Vec<u8>,
    application_progress: Vec<u8>,
    completed: usize,
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn exercise(
    nodes: &mut [VosNode],
    data: &Path,
    operator: &Keypair,
    space: SpaceId,
    node_public: [u8; 32],
    workflow: &RetainedWorkflow,
    recovery_started: Option<std::time::Instant>,
    retained: &mut Option<RetainedCapacity>,
) {
    let started = std::time::Instant::now();
    let address = listen(&mut nodes[0], "public-native-operation-capacity");
    if let Some(first) = retained.as_ref() {
        let recovery_started = recovery_started.expect("capacity reopen includes constructor start");
        let deadline = recovery_started + Duration::from_secs(30);
        assert!(
            std::time::Instant::now() < deadline,
            "whole capacity reopen exceeded 30s before archived retry"
        );
        assert!(first.completed > 256);
        assert_archived(data, first);
        let before = native_snapshot(data, first);
        assert_native_retry(address, first, Some(deadline));
        assert_eq!(native_snapshot(data, first), before);
        assert_client_retained(first);
        assert!(
            std::time::Instant::now() <= deadline,
            "whole constructor/attachment/readiness/archived result recovery exceeded 30s"
        );
        eprintln!(
            "public_native_capacity phase=locked_reopen_exact_native_result completed={} elapsed_ms={} whole_reopen_ms={}",
            first.completed,
            started.elapsed().as_millis(),
            recovery_started.elapsed().as_millis()
        );
        for node in nodes {
            assert!(!node.shutdown_handle().load(Ordering::Acquire));
        }
        return;
    }
    let identity = commands::clean_identity::CleanOperatorIdentitySigner::new(operator).unwrap();
    let package = vos::agent::package_admission::admit_actor_package(
        &std::fs::read(std::env::var_os("CLERK_AGENT_PACKAGE").unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(package.manifest().name, "clerk-ledger");
    let agent = vos::agent::supervisor_adapters::AgentInvocationRequest::decode(
        &workflow.invocation_request,
    )
    .unwrap()
    .work()
    .agent;
    let mut seen_actor = BTreeSet::new();
    let mut seen_authorization = BTreeSet::new();
    let mut completed = Vec::new();
    let mut first = None;
    let mut latest = None;
    for number in 1..=OPERATIONS {
        let mut message = vec![vos::value::TAG_DYNAMIC];
        message.extend(vos::value::Msg::new("journal_id").encode());
        // Reuse existing real package/policy preparation, replacing only the
        // test nonce with a full unique ID (the original u8 helper has 256 IDs).
        let template = intent(
            space,
            agent,
            workflow.actor,
            &identity,
            &package,
            "journal_id",
            message,
            InvocationRoleClaims::none(),
            0xef,
        );
        let invocation = InvocationId(
            Hash::digest(
                b"vos/test/native-operation-capacity/v1",
                &[&space.0, &agent.0, &workflow.actor.0, &number.to_le_bytes()],
            )
            .0,
        );
        assert!(seen_actor.insert(invocation));
        let old = template.intent();
        let intent = AgentTargetedPreparationRequest::new(
            template.target(),
            AgentInvocationIntent::new(
                invocation,
                old.mode(),
                old.origin(),
                old.roles(),
                old.message().to_vec(),
                old.gas(),
                old.recovery_only(),
            )
            .unwrap(),
        )
        .unwrap();
        let (request_root, authorization_response) = super::super::member_handoff::retry_exact(
            "public native capacity authorize/apply/ACK",
            || {
                commands::local_operation::authorize_with_application(
                    data,
                    address,
                    operator,
                    space,
                    node_public,
                    Some(&intent),
                    true,
                )
            },
        );
        let mut authorization =
            commands::clean_store::CleanOperationClientFile::open_or_create(&request_root).unwrap();
        let authorization_request = authorization.load_request().unwrap().unwrap();
        assert_eq!(
            authorization.load_response().unwrap().unwrap(),
            authorization_response
        );
        drop(authorization);
        let submission = AuthorityOperationSubmission::decode(&authorization_request).unwrap();
        assert!(submission.call().authenticated_node().is_none());
        assert_eq!(submission.call().principal, identity.principal());
        assert_eq!(submission.call().credential, identity.credential());
        let NativeAuthorityOperationDecision::Issued(issued) =
            submission.decode_response(&authorization_response).unwrap()
        else {
            panic!("genuine capacity operation was not issued");
        };
        assert_eq!(
            issued.issuance_ack.authorization_invocation,
            submission.call().invocation
        );
        assert!(seen_authorization.insert(submission.call().invocation));
        let application_root = request_root.parent().unwrap().join("application");
        let mut application =
            commands::clean_store::CleanInvocationFile::open_or_create(&application_root).unwrap();
        let application_request = application.load_request().unwrap().unwrap();
        let application_response = application.load_response().unwrap().unwrap();
        let application_progress = application.load_progress().unwrap().unwrap();
        let actual = commands::local_invocation::validate_request(&application_request).unwrap();
        assert_eq!(actual.work().invocation, invocation);
        assert_reply(
            &application_request,
            &application_response,
            vos::value::Value::Bytes(workflow.journal.to_vec()),
        );
        assert!(
            commands::invocation_progress::Progress::decode(
                &application_progress,
                &application_request,
                &application_response
            )
            .unwrap()
            .is_retired(&application_request, &application_response)
            .unwrap()
        );
        drop(application);
        let mut reservation = commands::clean_store::CleanCredentialReservation::open_or_create(
            &data.join("agent-client/credentials"),
            space,
            identity.credential(),
        )
        .unwrap();
        assert_eq!(
            reservation.current().unwrap(),
            Some((
                Hash(invocation.0),
                commands::clean_store::CredentialReservationStatus::Completed
            ))
        );
        drop(reservation);
        // Count only verified issuance + actual Clerk result + positive ACK and
        // completed reservation, not attempted iterations or synthetic signatures.
        completed.push((invocation, submission.call().invocation));
        assert_hot_bound(data);
        if first.is_none() {
            first = Some(RetainedCapacity {
                request_root,
                application_root,
                authorization_request: authorization_request.clone(),
                authorization_response: authorization_response.clone(),
                application_request,
                application_response,
                application_progress,
                completed: 0,
            });
        }
        latest = Some((authorization_request, authorization_response));
        if number == 1 || number % 32 == 0 || number == OPERATIONS {
            eprintln!(
                "public_native_capacity phase=completed completed={} elapsed_ms={}",
                completed.len(),
                started.elapsed().as_millis()
            );
        }
    }
    assert_eq!(completed.len(), OPERATIONS as usize);
    assert_eq!(seen_actor.len(), completed.len());
    assert_eq!(seen_authorization.len(), completed.len());
    let mut first = first.unwrap();
    first.completed = completed.len();
    // Settle the existing bounded compaction on an exact latest request before
    // measuring older retry immutability. This adds no new native operation.
    let (request, response) = latest.unwrap();
    let repeated =
        super::super::member_handoff::retry_exact("settled latest native result", || {
            commands::local_create::post_binary(
                address,
                "/__agents/authorize",
                200,
                &request,
                AuthorityOperationSubmission::MAX_RESPONSE_BYTES,
            )
        });
    assert_eq!(repeated, response);
    assert_archived(data, &first);
    let before = native_snapshot(data, &first);
    assert_native_retry(address, &first, None);
    assert_eq!(native_snapshot(data, &first), before);
    assert_client_retained(&first);
    eprintln!(
        "public_native_capacity phase=old_native_result_after_compaction completed={} elapsed_ms={}",
        first.completed,
        started.elapsed().as_millis()
    );
    *retained = Some(first);
    for node in nodes {
        assert!(!node.shutdown_handle().load(Ordering::Acquire));
    }
}

fn native_ids(first: &RetainedCapacity) -> [InvocationId; 2] {
    let submission = AuthorityOperationSubmission::decode(&first.authorization_request).unwrap();
    let NativeAuthorityOperationDecision::Issued(issued) = submission
        .decode_response(&first.authorization_response)
        .unwrap()
    else {
        unreachable!()
    };
    [
        submission.call().invocation,
        issued.issuance_ack.acknowledgement_invocation,
    ]
}

fn assert_archived(data: &Path, first: &RetainedCapacity) {
    let ids = native_ids(first);
    for id in ids {
        assert!(
            !data
                .join(OPERATION_JOURNAL_DIRECTORY)
                .join(hex::encode(id.0))
                .exists(),
            "first native pair remained hot after >256 genuine completions"
        );
        for name in ["authorization", "acknowledgement", "retirement"] {
            let path = data
                .join(OPERATION_TERMINALS_DIRECTORY)
                .join(hex::encode(id.0))
                .join(name);
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert!(metadata.is_file() && !metadata.file_type().is_symlink());
        }
    }
    // Only the bounded active namespace is enumerated. Growing archives are
    // checked by the first pair's two exact keys, never a corpus-wide scan.
    assert_hot_bound(data);
}

fn assert_hot_bound(data: &Path) {
    let active = hot_records(data);
    assert!(
        active.len() <= 4,
        "terminal/pending hot set grew with cumulative successes"
    );
}

fn hot_records(data: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut records = BTreeMap::new();
    for entry in std::fs::read_dir(data.join(OPERATION_JOURNAL_DIRECTORY)).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if name == "lock" {
            continue;
        }
        assert_eq!(
            name.len(),
            64,
            "unexpected active or unreconciled native journal file"
        );
        assert_eq!(hex::decode(&name).unwrap().len(), 32);
        assert!(entry.file_type().unwrap().is_file());
        records.insert(entry.path(), std::fs::read(entry.path()).unwrap());
    }
    records
}

fn native_snapshot(data: &Path, first: &RetainedCapacity) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = hot_records(data);
    for (directory, name) in [
        (
            OPERATION_IMAGES_DIRECTORY,
            "authority-operation.coordinator",
        ),
        (OPERATION_IMAGES_DIRECTORY, "authority-operation.issuer"),
        (
            OPERATION_COMPLETIONS_DIRECTORY,
            "authority-operation.completions",
        ),
        (
            OPERATION_RETIREMENTS_DIRECTORY,
            "authority-operation.retirements",
        ),
    ] {
        let path = data.join(directory).join(name);
        files.insert(path.clone(), std::fs::read(path).unwrap());
    }
    for id in native_ids(first) {
        for name in ["authorization", "acknowledgement", "retirement"] {
            let path = data
                .join(OPERATION_TERMINALS_DIRECTORY)
                .join(hex::encode(id.0))
                .join(name);
            files.insert(path.clone(), std::fs::read(path).unwrap());
        }
    }
    files
}

fn assert_native_retry(
    address: SocketAddr,
    first: &RetainedCapacity,
    deadline: Option<std::time::Instant>,
) {
    let submission = AuthorityOperationSubmission::decode(&first.authorization_request).unwrap();
    let prepared = super::super::member_handoff::retry_exact_until(
        "old native context HTTP retry",
        deadline.unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(120)),
        || {
            commands::local_create::post_binary(
                address,
                "/__agents/prepare-authorization",
                200,
                &submission.call().encode().unwrap(),
                AuthorityOperationSubmission::MAX_ENCODED_BYTES,
            )
        },
    );
    assert_eq!(prepared, first.authorization_request);
    let response = super::super::member_handoff::retry_exact_until(
        "old archived native result HTTP retry",
        deadline.unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(120)),
        || {
            commands::local_create::post_binary(
                address,
                "/__agents/authorize",
                200,
                &first.authorization_request,
                AuthorityOperationSubmission::MAX_RESPONSE_BYTES,
            )
        },
    );
    assert_eq!(response, first.authorization_response);
    assert!(matches!(
        submission.decode_response(&response).unwrap(),
        NativeAuthorityOperationDecision::Issued(_)
    ));
}

fn assert_client_retained(first: &RetainedCapacity) {
    let mut authorization =
        commands::clean_store::CleanOperationClientFile::open_or_create(&first.request_root)
            .unwrap();
    assert_eq!(
        authorization.load_request().unwrap().unwrap(),
        first.authorization_request
    );
    assert_eq!(
        authorization.load_response().unwrap().unwrap(),
        first.authorization_response
    );
    drop(authorization);
    let mut application =
        commands::clean_store::CleanInvocationFile::open_or_create(&first.application_root)
            .unwrap();
    assert_eq!(
        application.load_request().unwrap().unwrap(),
        first.application_request
    );
    assert_eq!(
        application.load_response().unwrap().unwrap(),
        first.application_response
    );
    assert_eq!(
        application.load_progress().unwrap().unwrap(),
        first.application_progress
    );
}
