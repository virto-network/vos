//! One physical service entrypoint with logical Refine/Accumulate selection.

use super::{
    AccumulateError, AccumulationOutcome, AccumulationValidator, InMemoryServiceState, Refine,
    RefineError, ServiceFunction, TransitionV2, WorkEnvelopeV2,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDispatchOutputV2 {
    Refined(TransitionV2),
    Accumulated(AccumulationOutcome),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceDispatchError {
    UnknownFunction(u64),
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

/// Local conformance harness for the same logical service entrypoint deployed
/// as `vos-service.pvm`. The selector is the value JAM places in `phi[7]`.
/// Refine receives only immutable inputs; the service store is reachable only
/// in the Accumulate branch.
pub struct JamServiceV2<R, V> {
    refiner: R,
    validator: V,
    state: InMemoryServiceState,
}

impl<R, V> JamServiceV2<R, V> {
    pub fn new(refiner: R, validator: V, state: InMemoryServiceState) -> Self {
        Self {
            refiner,
            validator,
            state,
        }
    }

    pub fn state(&self) -> &InMemoryServiceState {
        &self.state
    }
}

impl<R: Refine, V: AccumulationValidator> JamServiceV2<R, V> {
    pub fn dispatch_phi7(
        &mut self,
        phi7: u64,
        work: &WorkEnvelopeV2,
        imports: &R::Imports,
        transition: Option<&TransitionV2>,
    ) -> Result<ServiceDispatchOutputV2, ServiceDispatchError> {
        match ServiceFunction::from_phi7(phi7) {
            Some(ServiceFunction::Refine) => {
                if transition.is_some() {
                    return Err(ServiceDispatchError::UnexpectedTransition);
                }
                self.refiner
                    .refine(work, imports)
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
            None => Err(ServiceDispatchError::UnknownFunction(phi7)),
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

    #[derive(Clone)]
    struct Echo;

    impl Refine for Echo {
        type Imports = ();

        fn refine(
            &self,
            work: &WorkEnvelopeV2,
            _: &Self::Imports,
        ) -> Result<TransitionV2, RefineError> {
            Ok(TransitionV2 {
                service: work.service.clone(),
                consumed_input: work.invocation,
                target_program: work.target_program,
                base: work.base.clone(),
                writes: vec![],
                crdt_operations: vec![],
                resulting_crdt_heads: vec![],
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
    fn physical_selector_keeps_refine_stateless() {
        let identity = ServiceIdentityV2 {
            root_service: RootServiceId([1; 32]),
            deployment: DeploymentId([2; 32]),
            service_program: ProgramId([3; 32]),
            service_abi: crate::v2::ABI_VERSION,
            execution_semantics: crate::v2::EXECUTION_SEMANTICS_ID,
        };
        let actor = ActorId([4; 32]);
        let program = ProgramId([5; 32]);
        let mut state = InMemoryServiceState::new(identity.clone(), ConsistencyModeV2::Local);
        state.install_actor(actor, program);
        let work = WorkEnvelopeV2 {
            service: identity,
            invocation: InvocationId([6; 32]),
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
            imported_actors: vec![],
            imported_blobs: vec![],
            proof_requested: false,
        };
        let mut service = JamServiceV2::new(Echo, crate::v2::AllowPublic, state);
        let revision = service.state().revision();
        let transition = match service.dispatch_phi7(0, &work, &(), None).unwrap() {
            ServiceDispatchOutputV2::Refined(transition) => transition,
            _ => panic!("wrong logical function"),
        };
        assert_eq!(service.state().revision(), revision);
        let outcome = service
            .dispatch_phi7(1, &work, &(), Some(&transition))
            .unwrap();
        assert!(matches!(outcome, ServiceDispatchOutputV2::Accumulated(_)));
        assert_eq!(service.state().revision(), revision + 1);
        assert_eq!(
            service.dispatch_phi7(7, &work, &(), None),
            Err(ServiceDispatchError::UnknownFunction(7)),
        );
        assert_ne!(service.state().state_root(), Hash::ZERO);
        assert!(matches!(work.base, ConsistencyBaseV2::Linear { .. }));
    }
}
