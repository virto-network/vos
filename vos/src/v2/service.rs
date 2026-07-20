//! One generic service program with Gray Paper Refine/Accumulate entries.

use core::marker::PhantomData;

use super::{
    AccumulateError, AccumulationOutcome, AccumulationValidator, InMemoryServiceState, Refine,
    RefineError, RefineImportsV2, ServiceFunction, TransitionV2, WorkEnvelopeV2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDispatchOutputV2 {
    Refined(TransitionV2),
    Accumulated(AccumulationOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDispatchError {
    UnknownEntryIc(u32),
    UnexpectedTransition,
    MissingTransition,
    Refine(RefineError),
    Accumulate(AccumulateError),
}

impl core::fmt::Display for ServiceDispatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VOS service dispatch failed: {self:?}")
    }
}

impl core::error::Error for ServiceDispatchError {}

/// Local conformance harness for the same generic program deployed as
/// `vos-service.pvm`. JAM enters Refine at IC 0 and Accumulate at IC 5 while
/// `phi[7]`/`phi[8]` carry the standard argument window. Refine receives only
/// immutable inputs; the service store is reachable only in Accumulate.
pub struct JamServiceV2<R, V> {
    refiner: PhantomData<fn() -> R>,
    validator: V,
    state: InMemoryServiceState,
}

impl<R, V> JamServiceV2<R, V> {
    pub fn new(validator: V, state: InMemoryServiceState) -> Self {
        Self {
            refiner: PhantomData,
            validator,
            state,
        }
    }

    pub fn state(&self) -> &InMemoryServiceState {
        &self.state
    }
}

impl<R: Refine, V: AccumulationValidator> JamServiceV2<R, V> {
    pub fn dispatch_entry_ic(
        &mut self,
        entry_ic: u32,
        work: &WorkEnvelopeV2,
        imports: &RefineImportsV2,
        transition: Option<&TransitionV2>,
    ) -> Result<ServiceDispatchOutputV2, ServiceDispatchError> {
        match ServiceFunction::from_entry_ic(entry_ic) {
            Some(ServiceFunction::Refine) => {
                if transition.is_some() {
                    return Err(ServiceDispatchError::UnexpectedTransition);
                }
                imports
                    .validate_for(work)
                    .map_err(ServiceDispatchError::Refine)?;
                R::refine(work, imports)
                    .map(ServiceDispatchOutputV2::Refined)
                    .map_err(ServiceDispatchError::Refine)
            }
            Some(ServiceFunction::Accumulate) => {
                let transition = transition.ok_or(ServiceDispatchError::MissingTransition)?;
                self.state
                    .accumulate(work, transition, &self.validator)
                    .map(ServiceDispatchOutputV2::Accumulated)
                    .map_err(ServiceDispatchError::Accumulate)
            }
            None => Err(ServiceDispatchError::UnknownEntryIc(entry_ic)),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;
    use crate::v2::{
        ActorId, AuthorizationEvidenceV2, ConsistencyBaseV2, ConsistencyModeV2, DeploymentId,
        GasAccountingV2, Hash, InvocationId, Origin, ProgramId, RootServiceId, ServiceIdentityV2,
        WorkEnvelopeV2,
    };

    struct Echo;

    impl Refine for Echo {
        fn refine(work: &WorkEnvelopeV2, _: &RefineImportsV2) -> Result<TransitionV2, RefineError> {
            Ok(TransitionV2 {
                service: work.service.clone(),
                consumed_input: work.input_id(),
                target_program: work.target_program,
                base: work.base.clone(),
                writes: vec![],
                crdt_change: None,
                continuations: vec![],
                inbox: vec![],
                outbox: vec![],
                reply: None,
                exported_blobs: vec![],
                gas: GasAccountingV2::default(),
                proof: None,
            })
        }
    }

    #[test]
    fn gp_entries_keep_refine_stateless() {
        let identity = ServiceIdentityV2 {
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: crate::v2::ABI_VERSION,
            execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
        };
        let actor = ActorId([4; 32]);
        let actor_pvm = vec![5, 6, 7];
        let program = ProgramId::of_pvm(&actor_pvm);
        let actor_state_bytes = b"actor-state".to_vec();
        let actor_state = crate::v2::BlobRefV2::of_bytes(&actor_state_bytes);
        let mut state = InMemoryServiceState::new(identity.clone(), ConsistencyModeV2::Local);
        state.install_actor(actor, program);
        state.make_blob_available(actor_state.hash);
        let work = WorkEnvelopeV2 {
            service: identity,
            invocation: InvocationId([6; 32]),
            workflow_step: 0,
            target: actor,
            target_program: program,
            method: "tick".to_string(),
            arguments: vec![],
            origin: Origin::Anonymous,
            authorization: AuthorizationEvidenceV2::Public,
            causal_parent: None,
            parent_call: None,
            consistency: ConsistencyModeV2::Local,
            base: state.current_base(),
            imported_actors: vec![crate::v2::ImportedActorV2 {
                actor,
                program,
                state: actor_state.clone(),
                continuation: None,
            }],
            imported_blobs: vec![],
            proof_requested: false,
        };
        let imports = RefineImportsV2 {
            programs: vec![crate::v2::ImportedProgramV2 {
                program,
                pvm: actor_pvm,
            }],
            blobs: vec![crate::v2::ImportedBlobV2 {
                reference: actor_state,
                bytes: actor_state_bytes,
            }],
        };
        let mut service = JamServiceV2::<Echo, _>::new(crate::v2::AllowPublic, state);
        let revision = service.state().revision();
        let transition = match service
            .dispatch_entry_ic(crate::v2::REFINE_ENTRY_IC, &work, &imports, None)
            .unwrap()
        {
            ServiceDispatchOutputV2::Refined(transition) => transition,
            _ => panic!("wrong logical function"),
        };
        assert_eq!(service.state().revision(), revision);
        let outcome = service
            .dispatch_entry_ic(
                crate::v2::ACCUMULATE_ENTRY_IC,
                &work,
                &imports,
                Some(&transition),
            )
            .unwrap();
        assert!(matches!(outcome, ServiceDispatchOutputV2::Accumulated(_)));
        assert_eq!(service.state().revision(), revision + 1);
        assert_eq!(
            service.dispatch_entry_ic(1, &work, &imports, None),
            Err(ServiceDispatchError::UnknownEntryIc(1)),
        );
        assert_ne!(service.state().state_root(), Hash::ZERO);
        assert!(matches!(work.base, ConsistencyBaseV2::Linear { .. }));
    }
}
