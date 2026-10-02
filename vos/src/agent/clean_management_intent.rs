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

pub(crate) const MAX_INTENT_BYTES: usize =
    super::clean_authority_issuer::MAX_CLEAN_MANAGEMENT_INTENT_IMAGE_BYTES;

/// Durable next-Install input, never policy approval. Keep the previous signed
/// request so startup can authenticate either side of the intent replacement.
pub(crate) struct SharedInstallHandoff {
    pub(crate) previous: CleanManagementIntent,
    pub(crate) next: CleanManagementIntent,
    pub(crate) package: super::package_admission::AdmittedActorPackage,
    /// Exact signed denial and the last applied request, not a fabricated
    /// application terminal for the refused request.
    pub(crate) denial: Option<(Vec<u8>, CleanManagementIntent)>,
}

impl SharedInstallHandoff {
    pub(crate) fn new(
        previous: &CleanManagementIntent,
        next: &CleanManagementIntent,
        package: &super::package_admission::AdmittedActorPackage,
    ) -> Result<Self, DecodeError> {
        let bare = |intent: &CleanManagementIntent| {
            CleanManagementIntent::new(
                intent.call().authority,
                intent.call().managed,
                intent.request().clone(),
                intent.call().clone(),
                &super::clean_bootstrap::RawCredentialVerifier,
            )
        };
        let previous = bare(previous)?;
        let next = bare(next)?;
        let ManagementRequest::Install(install) = next.request() else {
            return Err(DecodeError::NonCanonical);
        };
        if !matches!(previous.request(), ManagementRequest::Install(_))
            || next.call().managed.profile != crate::agent_sdk::AgentProfile::Shared
            || previous.call().managed != next.call().managed
            || previous.call().authority != next.call().authority
            || previous.call() == next.call()
            || install.package != *package.package_ref()
            || install.entry.deployment != package.deployment()
            || install.entry.program != package.program()
            || install.producer != package.producer()
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self {
            previous,
            next,
            package: package.clone(),
            denial: None,
        })
    }

    pub(crate) fn with_denial(
        mut self,
        certificate: Vec<u8>,
        finalized: &CleanManagementIntent,
    ) -> Result<Self, DecodeError> {
        verify_denial_record(&certificate, self.previous.request(), self.previous.call())?;
        let finalized = CleanManagementIntent::new(
            self.previous.call().authority,
            self.previous.call().managed,
            finalized.request().clone(),
            finalized.call().clone(),
            &super::clean_bootstrap::RawCredentialVerifier,
        )?;
        if !matches!(
            finalized.request(),
            ManagementRequest::Create(_) | ManagementRequest::Install(_)
        ) || finalized.call() == self.previous.call()
            || finalized.call() == self.next.call()
        {
            return Err(DecodeError::NonCanonical);
        }
        self.denial = Some((certificate, finalized));
        Ok(self)
    }

    pub(crate) fn finalized_predecessor(&self) -> &CleanManagementIntent {
        self.denial
            .as_ref()
            .map_or(&self.previous, |(_, intent)| intent)
    }

    pub(crate) fn matches(
        intent: &CleanManagementIntent,
        expected: &CleanManagementIntent,
    ) -> bool {
        intent.request() == expected.request() && intent.call() == expected.call()
    }
}

impl ServiceWire for SharedInstallHandoff {
    const MAGIC: [u8; 4] = *b"SIH1";

    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.bytes(&self.previous.encode());
        encoder.bytes(&self.next.encode());
        encoder.bytes(self.package.exact_bytes());
        // Existing application handoffs keep their exact SIH1 bytes. Old
        // readers reject the tagged denial extension as trailing data.
        if let Some((certificate, finalized)) = &self.denial {
            encoder.u8(1);
            encoder.bytes(certificate);
            encoder.bytes(&finalized.encode());
        }
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let previous = decoder.bytes_ref()?;
        let next = decoder.bytes_ref()?;
        let package = decoder.bytes_ref()?;
        let bare_limit = 64
            + crate::agent_sdk::wire::MAX_MANAGEMENT_REQUEST_WIRE_BYTES
            + crate::agent_sdk::wire::MAX_AUTHORITY_CREDENTIAL_CALL_WIRE_BYTES;
        if previous.len() > bare_limit
            || next.len() > bare_limit
            || package.len() > crate::agent_sdk::package::MAX_PACKAGE_ENCODED_BYTES
        {
            return Err(DecodeError::LimitExceeded);
        }
        let previous = CleanManagementIntent::decode(previous)?;
        let next = CleanManagementIntent::decode(next)?;
        if previous.authorization_work().is_some()
            || previous.finalization_work().is_some()
            || next.authorization_work().is_some()
            || next.finalization_work().is_some()
        {
            return Err(DecodeError::NonCanonical);
        }
        let package = super::package_admission::admit_actor_package(package)
            .map_err(|_| DecodeError::NonCanonical)?;
        let record = Self::new(&previous, &next, &package)?;
        if decoder.exhausted() {
            return Ok(record);
        }
        if decoder.u8()? != 1 {
            return Err(DecodeError::InvalidTag);
        }
        let certificate = decoder.bytes_ref()?;
        let finalized = decoder.bytes_ref()?;
        if certificate.len() > MAX_INTENT_BYTES || finalized.len() > bare_limit {
            return Err(DecodeError::LimitExceeded);
        }
        let finalized = CleanManagementIntent::decode(finalized)?;
        if finalized.authorization_work().is_some() || finalized.finalization_work().is_some() {
            return Err(DecodeError::NonCanonical);
        }
        record.with_denial(certificate.to_vec(), &finalized)
    }
}

/// Host-owned pre-dispatch position, not a credential approval. Recovery must
/// authenticate it against the independently opened system journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ManagementJournalAnchor {
    pub(crate) genesis: super::journal::AgentJournalGenesisId,
    pub(crate) admission: super::genesis::AgentGenesisAdmissionId,
    pub(crate) runtime: crate::service::Hash,
    pub(crate) ordered: super::journal::OrderedBase,
}

impl ManagementJournalAnchor {
    fn validate(&self) -> Result<(), DecodeError> {
        if self.genesis == super::journal::AgentJournalGenesisId::ZERO
            || self.admission == super::genesis::AgentGenesisAdmissionId::ZERO
            || self.runtime == crate::service::Hash::ZERO
        {
            return Err(DecodeError::NonCanonical);
        }
        self.ordered.validate()
    }
}

impl ServiceWire for ManagementJournalAnchor {
    const MAGIC: [u8; 4] = *b"MJA1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        let mut encoder = Encoder(output);
        encoder.fixed(&self.genesis.0);
        encoder.fixed(self.admission.as_bytes());
        encoder.fixed(&self.runtime.0);
        encoder.u64(self.ordered.index);
        encoder.bool(self.ordered.head.is_some());
        if let Some(head) = self.ordered.head {
            encoder.fixed(&head.0);
        }
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let result = Self {
            genesis: super::journal::AgentJournalGenesisId(decoder.fixed()?),
            admission: super::genesis::AgentGenesisAdmissionId::from_bytes(decoder.fixed()?),
            runtime: crate::service::Hash(decoder.fixed()?),
            ordered: super::journal::OrderedBase {
                index: decoder.u64()?,
                head: if decoder.bool()? {
                    Some(super::journal::OrderedEntryId(decoder.fixed()?))
                } else {
                    None
                },
            },
        };
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CleanManagementIntent {
    request: ManagementRequest,
    call: AuthorityCredentialCall,
    authorization_work: Option<RuntimeWork>,
    finalization_work: Option<RuntimeWork>,
    authorization_anchor: Option<ManagementJournalAnchor>,
    finalization_anchor: Option<ManagementJournalAnchor>,
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
            authorization_anchor: None,
            finalization_anchor: None,
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

    pub(crate) fn authorization_work(&self) -> Option<&RuntimeWork> {
        self.authorization_work.as_ref()
    }

    pub(crate) fn finalization_work(&self) -> Option<&RuntimeWork> {
        self.finalization_work.as_ref()
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
        Self::finalization_message_bytes(&ack.encode().unwrap_or_default())
    }

    pub(crate) fn failure_finalization_message(
        failure: &crate::agent_sdk::authority::ManagementApplicationFailure,
    ) -> Vec<u8> {
        Self::finalization_message_bytes(&failure.encode().unwrap_or_default())
    }

    fn finalization_message_bytes(ack: &[u8]) -> Vec<u8> {
        use crate::actors::codec::Encode as _;
        let mut bytes = vec![crate::actors::value::TAG_DYNAMIC];
        bytes.extend(
            crate::actors::value::Msg::new("finalize")
                .with("ack", crate::actors::value::Value::Bytes(ack.to_vec()))
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
                    | ManagementRequest::InspectManagementHistory
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
        if self.authorization_work.is_some() != self.authorization_anchor.is_some()
            || self.finalization_work.is_some() != self.finalization_anchor.is_some()
        {
            return Err(DecodeError::NonCanonical);
        }
        for anchor in self
            .authorization_anchor
            .iter()
            .chain(self.finalization_anchor.iter())
        {
            anchor.validate()?;
        }
        if let (Some(first), Some(last)) = (&self.authorization_anchor, &self.finalization_anchor) {
            if first.genesis != last.genesis
                || first.admission != last.admission
                || first.runtime != last.runtime
                || first.ordered.index > last.ordered.index
                || (first.ordered.index == last.ordered.index
                    && first.ordered.head != last.ordered.head)
            {
                return Err(DecodeError::NonCanonical);
            }
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
                use crate::agent_sdk::authority::ManagementApplicationFailure;
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
                let invocation = if bytes.starts_with(b"MAF1") {
                    {
                        let failure = ManagementApplicationFailure::decode(bytes)
                            .map_err(|_| DecodeError::NonCanonical)?;
                        if !matches!(self.request, ManagementRequest::Install(_))
                            || !matches!(
                                self.call.managed.profile,
                                crate::agent_sdk::AgentProfile::Local
                                    | crate::agent_sdk::AgentProfile::Shared
                            )
                            || failure.authority != self.call.authority
                            || failure.managed != self.call.managed
                            || failure.authorization_invocation != self.call.invocation
                            || failure.acknowledgement_invocation
                                != ManagementApproval::derive_acknowledgement_invocation(&self.call)
                            || failure.credential_call != self.call.commitment()
                            || failure.request != self.request.commitment()
                            || failure.failed_at > *observed_slot
                        {
                            return Err(DecodeError::NonCanonical);
                        }
                        failure.acknowledgement_invocation
                    }
                } else {
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
                    ack.acknowledgement_invocation
                };
                (
                    invocation,
                    InvocationOrigin::anonymous(),
                    Self::finalization_message_bytes(bytes),
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
    const MAGIC: [u8; 4] = *b"CMI4";
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
        for anchor in [&self.authorization_anchor, &self.finalization_anchor] {
            encoder.bool(anchor.is_some());
            if let Some(anchor) = anchor {
                encoder.bytes(&anchor.encode());
            }
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
            authorization_anchor: if decoder.bool()? {
                Some(ManagementJournalAnchor::decode(decoder.bytes_ref()?)?)
            } else {
                None
            },
            finalization_anchor: if decoder.bool()? {
                Some(ManagementJournalAnchor::decode(decoder.bytes_ref()?)?)
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

/// Host-owned completion marker, written only while the live retirement gate
/// proves both positive journal acknowledgements. The full signed intent and
/// finalization envelope remain available for exact application retry.
struct RetiredManagementIntent(CleanManagementIntent);

/// Signed only after canonical denial replay and a positive runtime ACK.
/// Signature covers the entire previously pledged intent, including its anchor.
struct DeniedManagementIntent(CleanManagementIntent, [u8; 64]);

/// Verify a host retirement certificate against independently retained input,
/// never against the certificate's self-asserted Authority or request alone.
pub(crate) fn verify_denial_record(
    bytes: &[u8],
    request: &ManagementRequest,
    call: &AuthorityCredentialCall,
) -> Result<(), DecodeError> {
    if bytes.len() > MAX_INTENT_BYTES {
        return Err(DecodeError::LimitExceeded);
    }
    let denied = DeniedManagementIntent::decode(bytes)?;
    if denied.0.request() != request || denied.0.call() != call {
        return Err(DecodeError::NonCanonical);
    }
    denied.0.verify(
        call.authority,
        call.managed,
        &super::clean_bootstrap::RawCredentialVerifier,
    )
}

fn denial_retirement_signing_bytes(intent: &CleanManagementIntent) -> Vec<u8> {
    let mut bytes = b"vos/agent/management-denial-retired/v1".to_vec();
    bytes.extend_from_slice(
        crate::agent_sdk::Hash::digest(
            b"vos/agent/management-denial-intent/v1",
            &[&intent.encode()],
        )
        .as_bytes(),
    );
    bytes
}

impl ServiceWire for DeniedManagementIntent {
    const MAGIC: [u8; 4] = *b"CND1";
    fn encode_body(&self, output: &mut Vec<u8>) {
        self.0.encode_body(output);
        output.extend_from_slice(&self.1);
    }
    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let intent = CleanManagementIntent::decode_body(decoder)?;
        let mut signature = [0; 64];
        signature[..32].copy_from_slice(&decoder.fixed()?);
        signature[32..].copy_from_slice(&decoder.fixed()?);
        if intent.authorization_work.is_none()
            || intent.finalization_work.is_some()
            || !super::authority::verify_raw_ed25519(
                &intent.call.authority.binding.public_key,
                &denial_retirement_signing_bytes(&intent),
                &signature,
            )
        {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self(intent, signature))
    }
}

impl ServiceWire for RetiredManagementIntent {
    const MAGIC: [u8; 4] = *b"CMR2";

    fn encode_body(&self, output: &mut Vec<u8>) {
        self.0.encode_body(output);
    }

    fn decode_body(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let intent = CleanManagementIntent::decode_body(decoder)?;
        if intent.authorization_work.is_none() || intent.finalization_work.is_none() {
            return Err(DecodeError::NonCanonical);
        }
        Ok(Self(intent))
    }
}

/// Dedicated single-writer intent store. It must not share its physical image
/// with the issuer even though both use the same atomic whole-image contract.
pub(crate) struct CleanManagementIntentSlot<B> {
    store: B,
    intent: Option<CleanManagementIntent>,
    retired: bool,
    denied: bool,
    poisoned: bool,
}

/// Constructor-validated cache only. The original store lease never moves into
/// this value, and installing it does not establish physical execution.
pub(crate) struct ReloadedManagementIntent {
    intent: Option<CleanManagementIntent>,
    retired: bool,
    denied: bool,
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
        if self.poisoned || self.denied {
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
        let retained = store
            .load()
            .map_err(IntentSlotError::Storage)?
            .map(|bytes| {
                if bytes.len() > MAX_INTENT_BYTES {
                    return Err(IntentSlotError::Invalid);
                }
                if bytes.starts_with(&DeniedManagementIntent::MAGIC) {
                    DeniedManagementIntent::decode(&bytes)
                        .map(|denied| (denied.0, false, true))
                        .map_err(|_| IntentSlotError::Invalid)
                } else if bytes.starts_with(&RetiredManagementIntent::MAGIC) {
                    RetiredManagementIntent::decode(&bytes)
                        .map(|retired| (retired.0, true, false))
                        .map_err(|_| IntentSlotError::Invalid)
                } else {
                    CleanManagementIntent::decode(&bytes)
                        .map(|intent| (intent, false, false))
                        .map_err(|_| IntentSlotError::Invalid)
                }
            })
            .transpose()?;
        let (intent, retired, denied) = match retained {
            Some((intent, retired, denied)) => (Some(intent), retired, denied),
            None => (None, false, false),
        };
        Ok(Self {
            store,
            intent,
            retired,
            denied,
            poisoned: false,
        })
    }

    /// Transfer ownership of the still-leased store, not trust in cached state.
    /// The next protocol owner must reopen and validate its durable image.
    pub(crate) fn into_store(self) -> B {
        self.store
    }

    pub(crate) fn leased_store_mut(&mut self) -> &mut B {
        &mut self.store
    }

    pub(crate) fn into_reload_cache(
        self,
    ) -> Result<ReloadedManagementIntent, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        Ok(ReloadedManagementIntent {
            intent: self.intent,
            retired: self.retired,
            denied: self.denied,
        })
    }

    /// An ambiguous commit may grow the retained phase, but cannot substitute
    /// the signed Create or any work/anchor already held by this live owner.
    pub(crate) fn validates_reload_cache(&self, cache: &ReloadedManagementIntent) -> bool {
        let (Some(before), Some(after)) = (&self.intent, &cache.intent) else {
            return false;
        };
        before.request == after.request
            && before.call == after.call
            && before
                .authorization_work
                .as_ref()
                .is_none_or(|work| after.authorization_work.as_ref() == Some(work))
            && before
                .authorization_anchor
                .as_ref()
                .is_none_or(|anchor| after.authorization_anchor.as_ref() == Some(anchor))
            && before
                .finalization_work
                .as_ref()
                .is_none_or(|work| after.finalization_work.as_ref() == Some(work))
            && before
                .finalization_anchor
                .as_ref()
                .is_none_or(|anchor| after.finalization_anchor.as_ref() == Some(anchor))
            && (!self.retired || cache.retired)
            && (!self.denied || cache.denied)
    }

    /// The complete borrowed recovery and both cache guards must pass first.
    /// This is deliberately infallible so adoption has no half-installed state.
    pub(crate) fn install_reload_cache(&mut self, cache: ReloadedManagementIntent) {
        self.intent = cache.intent;
        self.retired = cache.retired;
        self.denied = cache.denied;
        self.poisoned = false;
    }

    pub(crate) fn management_continuation_store(&mut self) -> Result<B, IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanSharedManagementIntentStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        self.store
            .management_intent_continuation()
            .map_err(IntentSlotError::Storage)
    }

    pub(crate) fn load_external_create_archive(
        &mut self,
    ) -> Result<Option<Vec<u8>>, IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        self.store
            .load_external_create_archive()
            .map_err(IntentSlotError::Storage)
    }

    pub(crate) fn retain_external_create_archive(
        &mut self,
        archive: &[u8],
    ) -> Result<(), IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        match self.load_external_create_archive()? {
            Some(bytes) if bytes == archive => Ok(()),
            Some(_) => Err(IntentSlotError::Conflict),
            None => {
                self.poisoned = true;
                self.store
                    .commit_external_create_archive(archive)
                    .map_err(IntentSlotError::Storage)?;
                self.poisoned = false;
                Ok(())
            }
        }
    }

    pub(crate) fn load_runtime(&mut self) -> Result<Option<Vec<u8>>, IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanManagementRuntimeStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        self.store.load_runtime().map_err(IntentSlotError::Storage)
    }

    pub(crate) fn retain_runtime(&mut self, package: &[u8]) -> Result<(), IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanManagementRuntimeStore,
    {
        if self.intent.is_none() {
            return Err(IntentSlotError::Invalid);
        }
        match self.load_runtime()? {
            Some(bytes) if bytes == package => Ok(()),
            Some(_) => Err(IntentSlotError::Conflict),
            None => {
                self.poisoned = true;
                self.store
                    .commit_runtime(package)
                    .map_err(IntentSlotError::Storage)?;
                self.poisoned = false;
                Ok(())
            }
        }
    }

    /// External Local Create stages its exact package before the signed
    /// intent. A crash in between leaves an inert candidate; after the intent
    /// is pledged, startup always has the package needed for recovery.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn stage_external_create_runtime(
        &mut self,
        intent: &CleanManagementIntent,
        package: &super::package_admission::AdmittedStateRuntimePackage,
    ) -> Result<(), IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanManagementRuntimeStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let ManagementRequest::Create(descriptor) = intent.request() else {
            return Err(IntentSlotError::Invalid);
        };
        if intent.validate().is_err()
            || !super::external_local_executor::state_runtime_matches_descriptor(
                descriptor, package,
            )
        {
            return Err(IntentSlotError::Invalid);
        }
        if let Some(existing) = &self.intent
            && (existing.request != intent.request || existing.call != intent.call)
        {
            return Err(IntentSlotError::Conflict);
        }
        match self.load_runtime()? {
            Some(bytes) if bytes == package.exact_bytes() => Ok(()),
            Some(_) => Err(IntentSlotError::Conflict),
            None => {
                self.poisoned = true;
                self.store
                    .commit_runtime(package.exact_bytes())
                    .map_err(IntentSlotError::Storage)?;
                self.poisoned = false;
                Ok(())
            }
        }
    }

    /// Only an absent intent, empty actor/archive sidecars, and a valid
    /// optional staged state package may be ignored during external startup.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn verify_unpledged_external_staging(
        &mut self,
    ) -> Result<(), IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanManagementRuntimeStore
            + super::clean_authority_issuer::CleanManagementActorStore
            + super::clean_authority_issuer::CleanExternalLocalCreateArchiveStore
            + super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        if self.intent.is_some() || self.retired || self.denied {
            return Err(IntentSlotError::Invalid);
        }
        if self
            .store
            .load_actor()
            .map_err(IntentSlotError::Storage)?
            .is_some()
            || self
                .store
                .load_external_create_archive()
                .map_err(IntentSlotError::Storage)?
                .is_some()
            || self
                .store
                .load_pending_install()
                .map_err(IntentSlotError::Storage)?
                .is_some()
        {
            return Err(IntentSlotError::Conflict);
        }
        if let Some(bytes) = self.load_runtime()? {
            super::package_admission::admit_state_runtime_package(&bytes)
                .map_err(|_| IntentSlotError::Invalid)?;
        }
        Ok(())
    }

    /// Re-admit an exact signed future Install retained before intent handoff.
    /// Its caller must still bind the claim to the selected Authority/Agent.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn load_external_pending_install(
        &mut self,
    ) -> Result<Option<super::local_lifecycle::LocalInstallSubmission>, IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        self.store
            .load_pending_install()
            .map_err(IntentSlotError::Storage)?
            .map(|bytes| {
                let submission = super::local_lifecycle::LocalInstallSubmission::decode(&bytes)
                    .map_err(|_| IntentSlotError::Invalid)?;
                (submission.encode() == bytes)
                    .then_some(submission)
                    .ok_or(IntentSlotError::Invalid)
            })
            .transpose()
    }

    /// Stage LIQ1 while the previous Create/Install intent remains retired.
    /// A crash before handoff leaves that previous actor sidecar untouched;
    /// a crash afterward can restore the new actor from this exact request.
    #[cfg(all(
        target_os = "linux",
        feature = "storage",
        feature = "experimental-state-blocks"
    ))]
    pub(crate) fn stage_external_pending_install(
        &mut self,
        expected: &CleanManagementIntent,
        next: &CleanManagementIntent,
        submission: &super::local_lifecycle::LocalInstallSubmission,
    ) -> Result<(), IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanExternalLocalPendingInstallStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let ManagementRequest::Install(install) = next.request() else {
            return Err(IntentSlotError::Invalid);
        };
        if install.as_ref() != submission.install()
            || next.call() != submission.call()
            || next.authorization_work().is_some()
            || next.finalization_work().is_some()
            || next
                .verify(
                    next.call().authority,
                    next.call().managed,
                    &super::clean_bootstrap::RawCredentialVerifier,
                )
                .is_err()
        {
            return Err(IntentSlotError::Invalid);
        }
        let current = self.intent.clone().ok_or(IntentSlotError::Conflict)?;
        let exact = submission.encode();
        let retained = self.load_external_pending_install()?;
        if current.request() == next.request() && current.call() == next.call() {
            return if retained
                .as_ref()
                .is_some_and(|saved| saved.encode() == exact)
            {
                Ok(())
            } else {
                Err(IntentSlotError::Conflict)
            };
        }
        if !self.retired || &current != expected {
            return Err(IntentSlotError::Conflict);
        }
        if let Some(saved) = retained {
            if saved.encode() == exact {
                return Ok(());
            }
            if !matches!(current.request(), ManagementRequest::Install(old) if old.as_ref() == saved.install())
                || current.call() != saved.call()
            {
                return Err(IntentSlotError::Conflict);
            }
        }
        self.poisoned = true;
        self.store
            .commit_pending_install(&exact)
            .map_err(IntentSlotError::Storage)?;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn load_shared_install_handoff(
        &mut self,
    ) -> Result<Option<SharedInstallHandoff>, IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanSharedManagementIntentStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        self.store
            .load_shared_install_handoff()
            .map_err(IntentSlotError::Storage)?
            .map(|bytes| {
                if bytes.len()
                    > super::clean_authority_issuer::MAX_CLEAN_SHARED_INSTALL_HANDOFF_BYTES
                {
                    return Err(IntentSlotError::Invalid);
                }
                let record =
                    SharedInstallHandoff::decode(&bytes).map_err(|_| IntentSlotError::Invalid)?;
                if record.encode() != bytes {
                    return Err(IntentSlotError::Invalid);
                }
                Ok(record)
            })
            .transpose()
    }

    pub(crate) fn stage_shared_install_handoff(
        &mut self,
        record: &SharedInstallHandoff,
    ) -> Result<(), IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanSharedManagementIntentStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let current = self.intent.clone().ok_or(IntentSlotError::Conflict)?;
        let bytes = record.encode();
        if bytes.len() > super::clean_authority_issuer::MAX_CLEAN_SHARED_INSTALL_HANDOFF_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        let saved = self.load_shared_install_handoff()?;
        if SharedInstallHandoff::matches(&current, &record.next) {
            return if saved.is_some_and(|saved| saved.encode() == bytes) {
                Ok(())
            } else {
                Err(IntentSlotError::Conflict)
            };
        }
        let terminal_matches = if let Some((certificate, _)) = &record.denial {
            self.load_denial_certificate()?.as_ref() == Some(certificate)
        } else {
            self.retired
        };
        if !terminal_matches || !SharedInstallHandoff::matches(&current, &record.previous) {
            return Err(IntentSlotError::Conflict);
        }
        if let Some(saved) = saved {
            if saved.encode() == bytes {
                return Ok(());
            }
            if !SharedInstallHandoff::matches(&current, &saved.next) {
                return Err(IntentSlotError::Conflict);
            }
        }
        self.poisoned = true;
        self.store
            .commit_shared_install_handoff(&bytes)
            .map_err(IntentSlotError::Storage)?;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn intent(&self) -> Option<&CleanManagementIntent> {
        self.intent.as_ref()
    }

    pub(crate) fn load_denial_certificate(
        &mut self,
    ) -> Result<Option<Vec<u8>>, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        if !self.denied {
            return Ok(None);
        }
        let bytes = self
            .store
            .load()
            .map_err(IntentSlotError::Storage)?
            .ok_or(IntentSlotError::Invalid)?;
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        let denied =
            DeniedManagementIntent::decode(&bytes).map_err(|_| IntentSlotError::Invalid)?;
        if self.intent.as_ref() != Some(&denied.0) {
            return Err(IntentSlotError::Conflict);
        }
        Ok(Some(bytes))
    }

    /// Re-admit the exact actor package named by the current Install intent.
    /// A file envelope or an old operation's sidecar is not package authority.
    pub(crate) fn load_actor(
        &mut self,
    ) -> Result<Option<super::package_admission::AdmittedActorPackage>, IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanManagementActorStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let Some(ManagementRequest::Install(install)) =
            self.intent.as_ref().map(|intent| intent.request())
        else {
            return Err(IntentSlotError::Invalid);
        };
        let Some(bytes) = self.store.load_actor().map_err(IntentSlotError::Storage)? else {
            return Ok(None);
        };
        let package = super::package_admission::admit_actor_package(&bytes)
            .map_err(|_| IntentSlotError::Invalid)?;
        if package.package_ref() != &install.package {
            return Err(IntentSlotError::Conflict);
        }
        Ok(Some(package))
    }

    /// Publish before authorization preparation. Once a work envelope exists,
    /// never reconstruct missing artifact evidence from a retry's request.
    pub(crate) fn retain_actor(
        &mut self,
        package: &super::package_admission::AdmittedActorPackage,
    ) -> Result<(), IntentSlotError<B::Error>>
    where
        B: super::clean_authority_issuer::CleanManagementActorStore,
    {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let intent = self.intent.as_ref().ok_or(IntentSlotError::Invalid)?;
        let ManagementRequest::Install(install) = intent.request() else {
            return Err(IntentSlotError::Invalid);
        };
        if package.package_ref() != &install.package {
            return Err(IntentSlotError::Conflict);
        }
        let previous = self.store.load_actor().map_err(IntentSlotError::Storage)?;
        if previous.as_deref() == Some(package.exact_bytes()) {
            return Ok(());
        }
        if self.retired
            || self.denied
            || intent.authorization_work.is_some()
            || intent.finalization_work.is_some()
        {
            return Err(IntentSlotError::Conflict);
        }
        if let Some(bytes) = previous {
            // A predecessor may differ, but malformed persisted evidence is
            // never silently repaired by an otherwise valid new submission.
            super::package_admission::admit_actor_package(&bytes)
                .map_err(|_| IntentSlotError::Invalid)?;
        }
        self.poisoned = true;
        self.store
            .commit_actor(package.exact_bytes())
            .map_err(IntentSlotError::Storage)?;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn denial_complete(&self) -> Result<bool, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        Ok(self.denied)
    }

    pub(crate) fn denial_signing_bytes(&self) -> Result<Vec<u8>, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let intent = self.intent.as_ref().ok_or(IntentSlotError::Invalid)?;
        if self.retired || intent.authorization_work.is_none() || intent.finalization_work.is_some()
        {
            return Err(IntentSlotError::Conflict);
        }
        Ok(denial_retirement_signing_bytes(intent))
    }

    /// Caller has verified denial and positive retirement before signing.
    pub(crate) fn commit_denial(
        &mut self,
        signature: [u8; 64],
    ) -> Result<(), IntentSlotError<B::Error>> {
        let message = self.denial_signing_bytes()?;
        let intent = self.intent.as_ref().ok_or(IntentSlotError::Invalid)?;
        if !super::authority::verify_raw_ed25519(
            &intent.call.authority.binding.public_key,
            &message,
            &signature,
        ) {
            return Err(IntentSlotError::Invalid);
        }
        if self.denied {
            return Ok(());
        }
        let bytes = DeniedManagementIntent(intent.clone(), signature).encode();
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        self.poisoned = true;
        self.store
            .commit(&bytes)
            .map_err(IntentSlotError::Storage)?;
        self.denied = true;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn retirement_complete(&self) -> Result<bool, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        Ok(self.retired)
    }

    /// Only call inside the network retirement completion callback: an
    /// application acknowledgement alone is not runtime-result retirement.
    pub(crate) fn commit_retirement(
        &mut self,
        acknowledgement: &crate::agent_sdk::authority::ManagementApplicationAck,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        self.commit_retirement_for_message(&CleanManagementIntent::finalization_message(
            acknowledgement,
        ))
    }

    pub(crate) fn commit_failure_retirement(
        &mut self,
        failure: &crate::agent_sdk::authority::ManagementApplicationFailure,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        self.commit_retirement_for_message(&CleanManagementIntent::failure_finalization_message(
            failure,
        ))
    }

    fn commit_retirement_for_message(
        &mut self,
        finalization_message: &[u8],
    ) -> Result<bool, IntentSlotError<B::Error>> {
        if self.denied {
            return Err(IntentSlotError::Conflict);
        }
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let intent = self.intent.as_ref().ok_or(IntentSlotError::Invalid)?;
        let Some(RuntimeWork::Invoke { invocation, .. }) = &intent.finalization_work else {
            return Err(IntentSlotError::Invalid);
        };
        if intent.authorization_work.is_none() || invocation.message != finalization_message {
            return Err(IntentSlotError::Conflict);
        }
        if self.retired {
            return Ok(false);
        }
        let bytes = RetiredManagementIntent(intent.clone()).encode();
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(IntentSlotError::Storage(error));
        }
        self.retired = true;
        Ok(true)
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

    pub(crate) fn authorization_anchor(
        &self,
    ) -> Result<Option<&ManagementJournalAnchor>, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        Ok(self
            .intent
            .as_ref()
            .and_then(|intent| intent.authorization_anchor.as_ref()))
    }

    pub(crate) fn finalization_anchor(
        &self,
    ) -> Result<Option<&ManagementJournalAnchor>, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        Ok(self
            .intent
            .as_ref()
            .and_then(|intent| intent.finalization_anchor.as_ref()))
    }

    /// Persist the exact physically prepared envelope before dispatch. A
    /// retry must reuse it, including its original preflight observation.
    pub(crate) fn pledge_authorization_work(
        &mut self,
        work: RuntimeWork,
        anchor: ManagementJournalAnchor,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        self.pledge_work(work, anchor, false)
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
        anchor: ManagementJournalAnchor,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        self.pledge_work(work, anchor, true)
    }

    fn pledge_work(
        &mut self,
        work: RuntimeWork,
        anchor: ManagementJournalAnchor,
        finalization: bool,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        if self.denied {
            return Err(IntentSlotError::Conflict);
        }
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        let mut intent = self.intent.clone().ok_or(IntentSlotError::Invalid)?;
        let pending_anchor = if finalization {
            &mut intent.finalization_anchor
        } else {
            &mut intent.authorization_anchor
        };
        let pending = if finalization {
            &mut intent.finalization_work
        } else {
            &mut intent.authorization_work
        };
        if let Some(existing) = pending {
            return if *existing == work && pending_anchor.as_ref() == Some(&anchor) {
                Ok(false)
            } else {
                Err(IntentSlotError::Conflict)
            };
        }
        *pending = Some(work);
        *pending_anchor = Some(anchor);
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

    /// Atomically replace one durably retired intent with the next signed
    /// request in the same Agent's store. This grants no policy approval:
    /// dispatch must still verify independently selected Authority/Agent routes.
    pub(crate) fn handoff_retired<V: AuthorityCredentialVerifier>(
        &mut self,
        expected: &CleanManagementIntent,
        next: CleanManagementIntent,
        verifier: &V,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        self.handoff_terminal(expected, next, verifier, false)
    }

    pub(crate) fn handoff_denied<V: AuthorityCredentialVerifier>(
        &mut self,
        expected: &CleanManagementIntent,
        next: CleanManagementIntent,
        certificate: &[u8],
        verifier: &V,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        if self.load_denial_certificate()?.as_deref() != Some(certificate) {
            return Err(IntentSlotError::Conflict);
        }
        self.handoff_terminal(expected, next, verifier, true)
    }

    fn handoff_terminal<V: AuthorityCredentialVerifier>(
        &mut self,
        expected: &CleanManagementIntent,
        next: CleanManagementIntent,
        verifier: &V,
        allow_denied: bool,
    ) -> Result<bool, IntentSlotError<B::Error>> {
        if self.poisoned {
            return Err(IntentSlotError::Poisoned);
        }
        next.verify(next.call.authority, next.call.managed, verifier)
            .map_err(|_| IntentSlotError::Invalid)?;
        if next.authorization_work.is_some()
            || next.finalization_work.is_some()
            || next.call.managed.space != expected.call.managed.space
            || next.call.managed.agent != expected.call.managed.agent
            || next.call == expected.call
        {
            return Err(IntentSlotError::Invalid);
        }
        let current = self.intent.as_ref().ok_or(IntentSlotError::Conflict)?;
        // Recover an ambiguous successful replacement without resetting any
        // envelopes the new request may already have durably prepared.
        if current.call == next.call && current.request == next.request {
            return Ok(false);
        }
        if !(self.retired || (allow_denied && self.denied)) || current != expected {
            return Err(IntentSlotError::Conflict);
        }
        let bytes = next.encode();
        if bytes.len() > MAX_INTENT_BYTES {
            return Err(IntentSlotError::Invalid);
        }
        if let Err(error) = self.store.commit(&bytes) {
            self.poisoned = true;
            return Err(IntentSlotError::Storage(error));
        }
        self.intent = Some(next);
        self.retired = false;
        self.denied = false;
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
