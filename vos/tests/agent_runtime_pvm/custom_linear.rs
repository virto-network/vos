//! Exact-input backend qualification of the normal custom-linear guest, not
//! the scripted host-recovery fixture. No standard-runtime state decoder or
//! native implementation is used as an execution oracle.

use super::*;
use sdk::recovery::{
    ManagementHistoryEntry, management_history_commitment, management_history_reply_matches,
};
use vos_pvm::PvmBackend;

fn identity_hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Comparison {
    runtime: AdmittedRuntimePackage,
    reference: PreparedProgram,
    native: PreparedProgram,
}

impl Comparison {
    fn new() -> Self {
        let path = std::env::var_os("AGENT_CUSTOM_RUNTIME_ELF")
            .expect("set AGENT_CUSTOM_RUNTIME_ELF to a freshly built normal custom-linear ELF (without scripted-fixture)");
        let elf = std::fs::read(&path).expect("read explicit normal custom-linear ELF");
        let pvm = vos_pvm_compiler::link_elf_spi(&elf).expect("link normal custom-linear guest");
        assert_eq!(pvm, vos_pvm_compiler::link_elf_spi(&elf).unwrap());
        vos_pvm::spi::validate_refine_host_calls(&pvm).unwrap();
        let envelope = sign_package(PackageEnvelope {
            manifest: PackageManifest::AgentRuntime(AgentRuntimePackageManifest {
                name: "custom-linear-differential".into(),
                external_state_limits: None,
                outer_program: BlobRef::of_bytes(&pvm),
                contract: RuntimePackageContract::canonical(),
                capabilities: RuntimeCapabilities {
                    lanes: LaneSet::of(StateLane::Linear),
                    scheduling: true,
                    proof_systems: sdk::ProofSystemSet::EMPTY,
                    max_actors: 1,
                },
                signing: package_signing(),
            }),
            artifacts: vec![artifact(&pvm)],
        });
        let runtime = admit_runtime_package(&envelope.encode().unwrap()).unwrap();
        assert_eq!(runtime.program(), ProgramId::of_pvm(&pvm));
        assert_ne!(runtime.program().0, STANDARD_RUNTIME_PROGRAM_ID.0);
        eprintln!(
            "custom_runtime_qualification elf={path:?} elf_hash={} elf_bytes={} program={} package_hash={} package_bytes={}",
            identity_hex(BlobRef::of_bytes(&elf).hash.as_bytes()),
            elf.len(),
            identity_hex(runtime.program().as_bytes()),
            identity_hex(runtime.package_ref().hash.as_bytes()),
            runtime.package_ref().len
        );
        Self {
            runtime,
            reference: PreparedProgram::new_with_backend(&pvm, PvmBackend::ForceInterpreter)
                .unwrap(),
            native: PreparedProgram::new_with_backend(&pvm, PvmBackend::ForceRecompiler).unwrap(),
        }
    }

    fn apply(&self, label: &str, work: RuntimeWork) -> RuntimeTransition {
        // Encode once; both fresh machines receive this exact admitted scope,
        // signed material, prior state, observation, input and gas budget.
        let input = work.encode().unwrap();
        assert_eq!(RuntimeWork::decode(&input).unwrap(), work);
        let reference =
            RefineContext::load_prepared(&self.reference, &input, GAS, MemoryModel::Auto)
                .unwrap()
                .try_run()
                .expect("reference execution");
        let native = RefineContext::load_prepared(&self.native, &input, GAS, MemoryModel::Auto)
            .unwrap()
            .try_run()
            .expect("native execution, with no interpreter fallback");
        assert_eq!(native.exit, reference.exit, "{label}: exit");
        assert_eq!(native.gas_used, reference.gas_used, "{label}: gas");
        assert_eq!(native.pc, reference.pc, "{label}: PC");
        assert_eq!(native.registers, reference.registers, "{label}: registers");
        assert_eq!(
            native.memory().page_perms(),
            reference.memory().page_perms(),
            "{label}: permissions"
        );
        assert_eq!(
            reference.exit,
            ExitReason::Halt,
            "{label}: guest must return its canonical transition"
        );
        let reference_bytes = reference
            .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
            .unwrap();
        let native_bytes = native
            .output_bounded(RuntimeTransition::MAX_ENCODED_BYTES)
            .unwrap();
        assert_eq!(
            native_bytes, reference_bytes,
            "{label}: complete transition bytes"
        );
        let expected = RuntimeTransition::decode(&reference_bytes).unwrap();
        let actual = RuntimeTransition::decode(&native_bytes).unwrap();
        assert_eq!(
            actual.encode().unwrap(),
            native_bytes,
            "{label}: canonical output"
        );
        assert_eq!(actual, expected, "{label}: typed transition");
        for (reference, native) in [
            (&expected.state.control, &actual.state.control),
            (&expected.state.linear, &actual.state.linear),
            (&expected.state.merge, &actual.state.merge),
            (&expected.state.local, &actual.state.local),
        ] {
            assert_eq!(
                BlobRef::of_bytes(reference),
                BlobRef::of_bytes(native),
                "{label}: opaque component commitment"
            );
        }
        let public_io = sdk::runtime_transition_public_io(&input, &native_bytes);
        assert_eq!(
            public_io,
            sdk::runtime_transition_public_io(&input, &reference_bytes)
        );
        eprintln!(
            "custom_backend_comparison operation={label} input_bytes={} output_bytes={} gas_used={} public_io={}",
            input.len(),
            native_bytes.len(),
            native.gas_used,
            identity_hex(public_io.as_bytes())
        );
        actual
    }
}

fn management(
    descriptor: &AgentDescriptor,
    state: RuntimeState,
    request: ManagementRequest,
    authority: Option<AuthorityReceipt>,
    observed_slot: u64,
) -> RuntimeWork {
    RuntimeWork::Manage {
        context: RuntimeExecutionContext::Direct,
        space: descriptor.identity.space,
        agent: descriptor.identity.agent,
        runtime_deployment: descriptor.identity.runtime_deployment,
        state,
        request: Box::new(request),
        authority: authority.map(Box::new),
        observed_slot,
    }
}

fn invoke(
    state: RuntimeState,
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
    observed_slot: u64,
) -> RuntimeWork {
    RuntimeWork::Invoke {
        context: RuntimeExecutionContext::Direct,
        state,
        invocation: Box::new(work.clone()),
        authorization: Box::new(authorization.clone()),
        observed_slot,
    }
}

fn acknowledge(
    state: RuntimeState,
    work: &InvocationWork,
    authorization: &InvocationAuthorization,
) -> RuntimeWork {
    RuntimeWork::Acknowledge {
        context: RuntimeExecutionContext::Direct,
        state,
        invocation: Box::new(sdk::InvocationRetirement::from_work(work)),
        authorization: Box::new(authorization.clone()),
    }
}

fn public(work: &InvocationWork, slot: u64) -> InvocationAuthorization {
    InvocationAuthorization::PublicPreflight(sdk::PublicPreflight::for_work(work, slot))
}

fn counter_value(transition: &RuntimeTransition) -> u64 {
    let RuntimeOutcome::Completed(Ok(reply)) = &transition.outcome else {
        panic!(
            "expected completed custom counter: {:?}",
            transition.outcome
        );
    };
    assert_eq!(reply.status, InvocationStatus::Done);
    u64::from_le_bytes(reply.reply.as_slice().try_into().unwrap())
}

#[test]
#[ignore = "requires AGENT_CUSTOM_RUNTIME_ELF freshly built without scripted-fixture; runs both physical backends"]
fn normal_custom_linear_exact_backend_lifecycle_and_recovery() {
    let comparison = Comparison::new();
    let actor = admitted_actor_program(static_actor_program());
    // These are runtime/profile semantics with fresh physical guest instances,
    // not a three-node Shared quorum or filesystem recovery qualification.
    for (profile, discriminator) in [(AgentProfile::Local, 0xa1), (AgentProfile::Shared, 0xa2)] {
        let mut descriptor = descriptor(&comparison.runtime, discriminator);
        descriptor.identity.profile = profile;
        descriptor.validate().unwrap();
        actor.require_runtime(profile, &comparison.runtime).unwrap();
        eprintln!("custom_backend_profile={profile:?}");
        let create = ManagementRequest::Create(Box::new(descriptor.clone()));
        let create_receipt = management_receipt(&descriptor, &create, 1, 1, 3);
        let created = comparison.apply(
            "create",
            management(
                &descriptor,
                RuntimeState::default(),
                create.clone(),
                Some(create_receipt.clone()),
                1,
            ),
        );
        assert_eq!(
            created.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Created(descriptor.identity.clone())))
        );
        assert!(
            created.state.control.starts_with(b"VCLCTL01"),
            "normal custom control layout"
        );
        assert!(
            created.state.linear.starts_with(b"VCLLIN01"),
            "normal custom Linear layout"
        );
        assert_eq!(
            comparison.apply(
                "create-restart-retry",
                management(
                    &descriptor,
                    restart(&created).state,
                    create.clone(),
                    Some(create_receipt.clone()),
                    99
                )
            ),
            created
        );

        let install = install_request(&descriptor, &actor);
        let install_receipt = management_receipt(&descriptor, &install, 2, 2, 3);
        let installed = comparison.apply(
            "install",
            management(
                &descriptor,
                restart(&created).state,
                install.clone(),
                Some(install_receipt.clone()),
                2,
            ),
        );
        let ManagementRequest::Install(installation) = &install else {
            unreachable!()
        };
        assert_eq!(
            installed.outcome,
            RuntimeOutcome::Management(Ok(ManagementReply::Installed(installation.entry.clone())))
        );
        assert_eq!(
            comparison.apply(
                "install-restart-retry",
                management(
                    &descriptor,
                    restart(&installed).state,
                    install.clone(),
                    Some(install_receipt.clone()),
                    99
                )
            ),
            installed
        );
        let directory = comparison.apply(
            "directory",
            management(
                &descriptor,
                restart(&installed).state,
                ManagementRequest::InspectActors {
                    after: None,
                    limit: 1,
                },
                None,
                0,
            ),
        );
        assert_eq!(directory.state, installed.state);
        let RuntimeOutcome::Management(Ok(ManagementReply::Actors(page))) = directory.outcome
        else {
            panic!("expected public actor directory");
        };
        assert_eq!(page.entries.len(), 1);
        let record = &page.entries[0];
        assert_eq!(record.entry, installation.entry);
        assert_eq!(record.install_request, installation.lineage_commitment());
        let RuntimeOutcome::Management(create_result) = &created.outcome else {
            unreachable!()
        };
        let RuntimeOutcome::Management(install_result) = &installed.outcome else {
            unreachable!()
        };
        let history = management_history_commitment(
            0,
            [
                ManagementHistoryEntry {
                    authority: create_receipt.commitment(),
                    request: create.replay_commitment(),
                    epoch: 1,
                    sequence: 1,
                    observed_slot: 1,
                    result: create_result,
                },
                ManagementHistoryEntry {
                    authority: install_receipt.commitment(),
                    request: install.replay_commitment(),
                    epoch: 1,
                    sequence: 2,
                    observed_slot: 2,
                    result: install_result,
                },
            ],
        )
        .unwrap();
        let recovered = comparison.apply(
            "management-history",
            management(
                &descriptor,
                restart(&installed).state,
                ManagementRequest::InspectManagementHistory,
                None,
                0,
            ),
        );
        assert!(management_history_reply_matches(
            &installed.state,
            history,
            &recovered
        ));

        let mut work = actor_invocation(&descriptor, record, &actor, 0xb1);
        // The example runtime owns this counter directly. Its published command
        // contract is an eight-byte positive delta, with no inner actor inputs.
        work.message = 5u64.to_le_bytes().to_vec();
        work.availability.clear();
        work.gas = 10;
        let authorization = public(&work, 5);
        let completed = comparison.apply(
            "invoke",
            invoke(installed.state.clone(), &work, &authorization, 5),
        );
        assert_eq!(counter_value(&completed), 5);
        assert_eq!(
            comparison.apply(
                "invoke-restart-retry",
                invoke(restart(&completed).state, &work, &authorization, 99)
            ),
            completed,
            "retry must not run the delta twice"
        );
        let acknowledged = comparison.apply(
            "ack",
            acknowledge(restart(&completed).state, &work, &authorization),
        );
        assert!(matches!(
            acknowledged.outcome,
            RuntimeOutcome::Acknowledged(Ok(_))
        ));
        let repeated_ack = comparison.apply(
            "ack-restart-retry",
            acknowledge(restart(&acknowledged).state, &work, &authorization),
        );
        assert_eq!(repeated_ack.state, acknowledged.state);
        assert_eq!(
            repeated_ack.outcome,
            RuntimeOutcome::Acknowledged(Err(InvocationError::NotFound))
        );
        let mut recovery_only = work.clone();
        recovery_only.recovery_only = true;
        let recovery_authorization = public(&recovery_only, 99);
        let retired = comparison.apply(
            "retired-recovery-only",
            invoke(
                restart(&acknowledged).state,
                &recovery_only,
                &recovery_authorization,
                99,
            ),
        );
        assert_eq!(retired.state, acknowledged.state);
        assert_eq!(
            retired.outcome,
            RuntimeOutcome::Completed(Err(InvocationError::NotFound))
        );

        // Exercise durable scheduling using the example's published one-shot
        // message: tag, id, due slot, priority, Once cadence, positive delta.
        let mut schedule = work.clone();
        schedule.invocation = InvocationId([0xb2; 32]);
        schedule.message = vec![1];
        schedule.message.extend_from_slice(&[0xc1; 32]);
        schedule.message.extend_from_slice(&10u64.to_le_bytes());
        schedule.message.extend_from_slice(&[2, 0]);
        schedule.message.extend_from_slice(&3u64.to_le_bytes());
        let schedule_auth = public(&schedule, 6);
        let scheduled = comparison.apply(
            "schedule",
            invoke(acknowledged.state, &schedule, &schedule_auth, 6),
        );
        assert_eq!(counter_value(&scheduled), 5);
        let scheduled_ack = comparison.apply(
            "schedule-ack",
            acknowledge(scheduled.state, &schedule, &schedule_auth),
        );
        let mut tick = work;
        tick.invocation = InvocationId([0xb3; 32]);
        tick.message = vec![3];
        let tick_auth = public(&tick, 10);
        let fired = comparison.apply(
            "timer-after-restart",
            invoke(restart(&scheduled_ack).state, &tick, &tick_auth, 10),
        );
        assert_eq!(counter_value(&fired), 8);
        assert_eq!(
            comparison.apply(
                "timer-retained-retry",
                invoke(restart(&fired).state, &tick, &tick_auth, 99)
            ),
            fired
        );
        let fired_ack = comparison.apply("timer-ack", acknowledge(fired.state, &tick, &tick_auth));
        tick.invocation = InvocationId([0xb4; 32]);
        let later_auth = public(&tick, 11);
        let later = comparison.apply(
            "timer-not-repeated",
            invoke(restart(&fired_ack).state, &tick, &later_auth, 11),
        );
        assert_eq!(counter_value(&later), 8);
        let history_after = comparison.apply(
            "history-after-invoke-ack-restart",
            management(
                &descriptor,
                restart(&later).state,
                ManagementRequest::InspectManagementHistory,
                None,
                0,
            ),
        );
        assert!(management_history_reply_matches(
            &later.state,
            history,
            &history_after
        ));
    }
}
