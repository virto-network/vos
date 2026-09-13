//! Durable exact input for native management coordination, before policy runs.
//! A signed credential call is not policy approval or genesis finality.

use super::clean_authority_issuer::{
    AuthorizedCleanManagementDecision, CleanManagementIssuerError, CleanManagementIssuerRejection,
    CleanManagementIssuerStore, CleanManagementReceiptSigner, DurableCleanManagementIssuer,
};
use crate::agent_sdk::authority::{
    AuthorityActorTarget, AuthorityCredentialCall, AuthorityCredentialVerifier, ManagedAgentTarget,
};
use crate::agent_sdk::wire::CanonicalWire as _;
use crate::agent_sdk::{
    InvocationAuthorization, InvocationOrigin, InvocationRoleClaims, ManagementRequest, MethodMode,
    RuntimeExecutionContext, RuntimeState, RuntimeWork,
};
use crate::service::wire::{DecodeError, Decoder, Encoder, ServiceWire};

pub(crate) const MAX_INTENT_BYTES: usize = 64
    + crate::agent_sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
    + crate::agent_sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES
    + 2 * crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CleanManagementIntent {
    request: ManagementRequest,
    call: AuthorityCredentialCall,
    authorization_work: Option<RuntimeWork>,
    finalization_work: Option<RuntimeWork>,
}

impl CleanManagementIntent {
    pub(crate) fn new<V: AuthorityCredentialVerifier>(
        authority: AuthorityActorTarget,
        managed: ManagedAgentTarget,
        request: ManagementRequest,
        call: AuthorityCredentialCall,
        verifier: &V,
    ) -> Result<Self, DecodeError> {
        let intent = Self {
            request,
            call,
            authorization_work: None,
            finalization_work: None,
        };
        intent.verify(authority, managed, verifier)?;
        Ok(intent)
    }

    /// Reverify on recovery against independently selected routes. Persisting
    /// the caller's own target does not make that target authoritative.
    pub(crate) fn verify<V: AuthorityCredentialVerifier>(
        &self,
        authority: AuthorityActorTarget,
        managed: ManagedAgentTarget,
        verifier: &V,
    ) -> Result<(), DecodeError> {
        self.validate()?;
        if self.call.authority != authority
            || self.call.managed != managed
            || self.call.verify_with(verifier).is_err()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(())
    }

    pub(crate) fn request(&self) -> &ManagementRequest {
        &self.request
    }
    pub(crate) fn call(&self) -> &AuthorityCredentialCall {
        &self.call
    }

    pub(crate) fn authorization_message(&self) -> Vec<u8> {
        use crate::actors::codec::Encode as _;
        let mut bytes = vec![crate::actors::value::TAG_DYNAMIC];
        bytes.extend(
            crate::actors::value::Msg::new("authorize")
                .with(
                    "call",
                    crate::actors::value::Value::Bytes(self.call.encode().unwrap_or_default()),
                )
                .encode(),
        );
        bytes
    }

    pub(crate) fn authorization_origin(&self) -> InvocationOrigin {
        InvocationOrigin {
            principal: Some(self.call.principal),
            transport_node: self.call.authenticated_node,
            credential: Some(self.call.credential),
            actor: None,
            capability: None,
        }
    }

    pub(crate) fn finalization_message(
        ack: &crate::agent_sdk::authority::ManagementApplicationAck,
    ) -> Vec<u8> {
        use crate::actors::codec::Encode as _;
        let mut bytes = vec![crate::actors::value::TAG_DYNAMIC];
        bytes.extend(
            crate::actors::value::Msg::new("finalize")
                .with(
                    "ack",
                    crate::actors::value::Value::Bytes(ack.encode().unwrap_or_default()),
                )
                .encode(),
        );
        bytes
    }

    fn validate(&self) -> Result<(), DecodeError> {
        if !self.request.is_valid()
            || self.call.encode().is_err()
            || !self.call.plan.matches_request(&self.request)
            || matches!(
                self.request,
                ManagementRequest::InspectActors { .. }
                    | ManagementRequest::InspectResources
                    | ManagementRequest::PrivateControl { .. }
            )
        {
            return Err(DecodeError::NonCanonical);
        }
        if let ManagementRequest::Create(descriptor) = &self.request {
            let target = self.call.managed;
            if descriptor.authority != self.call.authority.binding
                || descriptor.identity.space != target.space
                || descriptor.identity.agent != target.agent
                || descriptor.identity.owner != target.owner
                || descriptor.identity.profile != target.profile
                || descriptor.identity.runtime_deployment != target.runtime_deployment
                || descriptor.identity.transition_producer != target.transition_producer
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        if self.finalization_work.is_some() && self.authorization_work.is_none() {
            return Err(DecodeError::NonCanonical);
        }
        for (work, finalization) in self
            .authorization_work
            .iter()
            .map(|work| (work, false))
            .chain(self.finalization_work.iter().map(|work| (work, true)))
        {
            let RuntimeWork::Invoke {
                context,
                state,
                invocation,
                authorization,
                observed_slot,
            } = work
            else {
                return Err(DecodeError::NonCanonical);
            };
            let (expected_invocation, expected_origin, expected_message) = if finalization {
                use crate::actors::codec::Decode as _;
                use crate::agent_sdk::authority::{ManagementApplicationAck, ManagementApproval};
                let message = crate::actors::value::Msg::try_decode(
                    invocation
                        .message
                        .get(1..)
                        .ok_or(DecodeError::NonCanonical)?,
                )
                .ok_or(DecodeError::NonCanonical)?;
                let Some(crate::actors::value::Value::Bytes(bytes)) = message.args.get("ack")
                else {
                    return Err(DecodeError::NonCanonical);
                };
                let ack = ManagementApplicationAck::decode(bytes)
                    .map_err(|_| DecodeError::NonCanonical)?;
                if ack.authority != self.call.authority
                    || ack.managed != self.call.managed
                    || ack.authorization_invocation != self.call.invocation
                    || ack.acknowledgement_invocation
                        != ManagementApproval::derive_acknowledgement_invocation(&self.call)
                    || ack.credential_call != self.call.commitment()
                    || ack.request != self.request.commitment()
                    || ack.applied_at > *observed_slot
                {
                    return Err(DecodeError::NonCanonical);
                }
                (
                    ack.acknowledgement_invocation,
                    InvocationOrigin::anonymous(),
                    Self::finalization_message(&ack),
                )
            } else {
                (
                    self.call.invocation,
                    self.authorization_origin(),
                    self.authorization_message(),
                )
            };
            let target = self.call.authority;
            if *context != RuntimeExecutionContext::Direct
                || *state != RuntimeState::default()
                || !invocation.validate()
                || invocation.space != target.space
                || invocation.agent != target.system_agent
                || invocation.runtime_deployment != target.system_runtime_deployment
                || invocation.actor != target.binding.issuer.actor
                || invocation.deployment != target.binding.issuer.deployment
                || invocation.program != target.binding.issuer.program
                || invocation.invocation != expected_invocation
                || invocation.mode != MethodMode::Linear
                || invocation.origin != expected_origin
                || invocation.roles != InvocationRoleClaims::none()
                || invocation.message != expected_message
                || invocation.recovery_only
                || **authorization
                    != InvocationAuthorization::PublicPreflight(
                        crate::agent_sdk::PublicPreflight::for_work(invocation, *observed_slot),
                    )
                || work.encode().is_err()
            {
                return Err(DecodeError::NonCanonical);
            }
        }
        Ok(())
    }
}

impl ServiceWire for CleanManagementIntent {
    const MAGIC: [u8; 4] = *b"CMI3";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.request.encode().unwrap_or_default());
        encoder.bytes(&self.call.encode().unwrap_or_default());
        encoder.bool(self.authorization_work.is_some());
        if let Some(work) = &self.authorization_work {
            encoder.bytes(&work.encode().unwrap_or_default());
        }
        encoder.bool(self.finalization_work.is_some());
        if let Some(work) = &self.finalization_work {
            encoder.bytes(&work.encode().unwrap_or_default());
        }
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let request_bytes = decoder.bytes_ref()?;
        if request_bytes.len() > crate::agent_sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let call_bytes = decoder.bytes_ref()?;
        if call_bytes.len() > crate::agent_sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES {
            return Err(DecodeError::LimitExceeded);
        }
        let intent = Self {
            request: ManagementRequest::decode(request_bytes)
                .map_err(|_| DecodeError::NonCanonical)?,
            call: AuthorityCredentialCall::decode(call_bytes)
                .map_err(|_| DecodeError::NonCanonical)?,
            authorization_work: if decoder.bool()? {
                let bytes = decoder.bytes_ref()?;
                if bytes.len() > crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                Some(RuntimeWork::decode(bytes).map_err(|_| DecodeError::NonCanonical)?)
            } else {
                None
            },
            finalization_work: if decoder.bool()? {
                let bytes = decoder.bytes_ref()?;
                if bytes.len() > crate::agent_sdk::wire::MAX_RUNTIME_WORK_WIRE_BYTES {
                    return Err(DecodeError::LimitExceeded);
                }
                Some(RuntimeWork::decode(bytes).map_err(|_| DecodeError::NonCanonical)?)
            } else {
                None
            },
        };
        intent.validate()?;
        Ok(intent)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IntentSlotError<E> {
    Storage(E),
    Invalid,
    Conflict,
    Poisoned,
}

/// Dedicated single-writer intent store. It must not share its physical image
/// with the issuer even though both use the same atomic whole-image contract.
pub(crate) struct CleanManagementIntentSlot<B> {
    store: B,
    intent: Option<CleanManagementIntent>,
    poisoned: bool,
}

impl<B: CleanManagementIssuerStore> CleanManagementIntentSlot<B> {
    /// The native coordinator may call this only for the exact result of the
    /// configured authority actor's authenticated, durably applied invocation.
    /// A decoded approval or a policy preview is not that evidence.
    pub(crate) fn issue_from_authenticated_approval<
        I: CleanManagementIssuerStore,
        S: CleanManagementReceiptSigner,
        V: AuthorityCredentialVerifier,
    >(
        &self,
        authority: AuthorityActorTarget,
        managed: ManagedAgentTarget,
        approval: &crate::agent_sdk::authority::ManagementApproval,
        verifier: &V,
        issuer: &mut DurableCleanManagementIssuer<I>,
        signer: &mut S,
    ) -> Result<
        crate::agent_sdk::authority::AuthorityReceipt,
        CleanManagementIssuerError<I::Error, S::Error>,
    > {
        let invalid = || {
            CleanManagementIssuerError::Rejected(CleanManagementIssuerRejection::InvalidObservation)
        };
        if self.poisoned {
            return Err(invalid());
        }
        let intent = self.intent.as_ref().ok_or_else(invalid)?;
        intent
            .verify(authority, managed, verifier)
            .map_err(|_| invalid())?;
        let decision = AuthorizedCleanManagementDecision::from_approval(
            authority,
            managed,
            intent.request(),
            intent.call(),
            approval,
            verifier,
        )
        .map_err(|_| invalid())?;
        issuer.issue(&decision, signer)
    }

    pub(crate) fn open(mut store: B) -> Result<Self, IntentSlotError<B::Error>> {
        let intent = store
            .load()
            .map_err(IntentSlotError::Storage)?
            .map(|bytes| {
                if bytes.len() > MAX_INTENT_BYTES {
                    return Err(IntentSlotError::Invalid);
                }
                CleanManagementIntent::decode(&bytes).map_err(|_| IntentSlotError::Invalid)
            })
            .transpose()?;
        Ok(Self {
            store,
            intent,
            poisoned: false,
        })
    }

    pub(crate) fn intent(&self) -> Option<&CleanManagementIntent> {
        self.intent.as_ref()
    }

    pub(crate) fn authorization_work(
        &self,
    ) -> Result<Option<&RuntimeWork>, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        Ok(self
            .intent
            .as_ref()
            .and_then(|intent| intent.authorization_work.as_ref()))
    }

    /// Persist the exact physically prepared envelope before dispatch. A
    /// retry must reuse it, including its original preflight observation.
    pub(crate) fn pledge_authorization_work(
        &mut self,
        work: RuntimeWork,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        self.pledge_work(work, false)
    }

    pub(crate) fn finalization_work(
        &self,
    ) -> Result<Option<&RuntimeWork>, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        Ok(self
            .intent
            .as_ref()
            .and_then(|intent| intent.finalization_work.as_ref()))
    }

    pub(crate) fn pledge_finalization_work(
        &mut self,
        work: RuntimeWork,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        self.pledge_work(work, true)
    }

    fn pledge_work(
        &mut self,
        work: RuntimeWork,
        finalization: bool,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let mut intent = self.intent.clone().ok_or(IntentSlotError::Invalid)?;
        let pending = if finalization {
            &mut intent.finalization_work
        } else {
            &mut intent.authorization_work
        };
        if let Some(existing) = pending {
            return if *existing == work {
                Ok(false)
            } else {
                Err(IntentSlotError::Conflict)
            };
        }
        *pending = Some(work);
        intent.validate().map_err(|_| IntentSlotError::Invalid)?;
        let bytes = intent.encode();
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(IntentSlotError::Storage(error));
        }
        self.intent = Some(intent);
        Ok(true)
    }

    /// Commit before invoking authority policy or allocating any receipt.
    /// An ambiguous write poisons this instance; only a real reopen may retry.
    pub(crate) fn pledge(
        &mut self,
        intent: CleanManagementIntent,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        intent.validate().map_err(|_| IntentSlotError::Invalid)?;
        if let Some(existing) = &self.intent {
            return if existing.request == intent.request && existing.call == intent.call {
                Ok(false)
            } else {
                Err(IntentSlotError::Conflict)
            };
        }
        let bytes = intent.encode();
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(IntentSlotError::Storage(error));
        }
        self.intent = Some(intent);
        Ok(true)
    }
}
