//! Bounded durable continuation history for one exact retained invocation.
//! Every request is saved before sending; each reply must bind its exact step.

use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{RuntimeExecutionContext, RuntimeOutcome};
use vos::agent::supervisor_adapters::{
    AgentAcknowledgementRequest, AgentAcknowledgementResponse, AgentInvocationRequest,
    AgentInvocationResponse, AgentResumeRequest, AgentResumeResponse,
};

pub(crate) const MAX_PROGRESS_BYTES: usize = 64 * 1024 * 1024;
const MAX_STEPS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Progress {
    format: String,
    invocation: String,
    exchanges: Vec<Exchange>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    request: String,
    response: Option<String>,
}

enum Action {
    Resume(AgentResumeRequest),
    Acknowledge(AgentAcknowledgementRequest),
}

impl Action {
    fn for_outcome(
        request: &AgentInvocationRequest,
        outcome: &RuntimeOutcome,
    ) -> anyhow::Result<Option<Self>> {
        Ok(match outcome {
            RuntimeOutcome::Yielded(yielded) => Some(Self::Resume(
                AgentResumeRequest::new(
                    RuntimeExecutionContext::Direct,
                    None,
                    request.work().clone(),
                    request.authorization().clone(),
                    yielded.clone(),
                )
                .map_err(|error| anyhow::anyhow!("invalid retained yield: {error:?}"))?,
            )),
            RuntimeOutcome::Completed(_) => Some(Self::Acknowledge(
                AgentAcknowledgementRequest::new(
                    RuntimeExecutionContext::Direct,
                    None,
                    request.work().clone(),
                    request.authorization().clone(),
                )
                .map_err(|error| anyhow::anyhow!("invalid retirement request: {error:?}"))?,
            )),
            RuntimeOutcome::Acknowledged(_) => None,
            _ => anyhow::bail!("invalid invocation outcome"),
        })
    }

    fn encode(&self) -> anyhow::Result<Vec<u8>> {
        let bytes = match self {
            Self::Resume(request) => request.encode(),
            Self::Acknowledge(request) => request.encode(),
        }
        .map_err(|error| anyhow::anyhow!("encode continuation: {error:?}"))?;
        anyhow::ensure!(
            bytes.len() <= super::local_invocation::MAX_REQUEST_BYTES,
            "continuation exceeds HTTP limit"
        );
        Ok(bytes)
    }

    fn path(&self) -> &'static str {
        match self {
            Self::Resume(_) => "/__agents/resume",
            Self::Acknowledge(_) => "/__agents/acknowledge",
        }
    }

    fn verify(&self, bytes: &[u8]) -> anyhow::Result<RuntimeOutcome> {
        anyhow::ensure!(
            bytes.len() <= super::local_invocation::MAX_RESPONSE_BYTES,
            "continuation response too large"
        );
        match self {
            Self::Resume(request) => {
                let response = AgentResumeResponse::decode(bytes)
                    .map_err(|error| anyhow::anyhow!("invalid ARR3: {error:?}"))?;
                anyhow::ensure!(
                    response.matches_request(request),
                    "resume response differs from exact retained step"
                );
                Ok(response.outcome().clone())
            }
            Self::Acknowledge(request) => {
                let response = AgentAcknowledgementResponse::decode(bytes)
                    .map_err(|error| anyhow::anyhow!("invalid AAR3: {error:?}"))?;
                anyhow::ensure!(
                    response.matches_request(request),
                    "retirement response differs from exact retained step"
                );
                Ok(response.outcome().clone())
            }
        }
    }
}

impl Progress {
    pub(crate) fn new(request: &[u8]) -> anyhow::Result<Self> {
        let request = super::local_invocation::validate_request(request)?;
        Ok(Self {
            format: "CIP1".into(),
            invocation: hex::encode(request.commitment().0),
            exchanges: Vec::new(),
        })
    }

    pub(crate) fn encode(&self) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            self.exchanges.len() <= MAX_STEPS,
            "continuation history is full"
        );
        let bytes = serde_json::to_vec(self)?;
        anyhow::ensure!(
            bytes.len() <= MAX_PROGRESS_BYTES,
            "continuation history exceeds its durable limit"
        );
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8], request: &[u8], response: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_PROGRESS_BYTES,
            "continuation history too large"
        );
        let value: Self = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            value.encode()? == bytes,
            "noncanonical continuation history"
        );
        value.outcome(request, response)?;
        Ok(value)
    }

    fn outcome(&self, request: &[u8], response: &[u8]) -> anyhow::Result<RuntimeOutcome> {
        let call = super::local_invocation::validate_request(request)?;
        anyhow::ensure!(
            self.format == "CIP1"
                && self.invocation == hex::encode(call.commitment().0)
                && self.exchanges.len() <= MAX_STEPS,
            "continuation history has wrong invocation"
        );
        let AgentInvocationResponse::Direct { mut outcome, .. } =
            super::local_invocation::verify_response(request, response)?
        else {
            anyhow::bail!("Direct delivery required");
        };
        for (index, exchange) in self.exchanges.iter().enumerate() {
            let action = Action::for_outcome(&call, &outcome)?
                .ok_or_else(|| anyhow::anyhow!("history continues after acknowledgement"))?;
            anyhow::ensure!(
                exchange.request == hex::encode(action.encode()?),
                "continuation request differs from saved predecessor"
            );
            match &exchange.response {
                Some(encoded) => {
                    let bytes = hex::decode(encoded)?;
                    anyhow::ensure!(hex::encode(&bytes) == *encoded, "noncanonical response hex");
                    outcome = action.verify(&bytes)?;
                }
                None => anyhow::ensure!(
                    index + 1 == self.exchanges.len(),
                    "unfinished continuation is not last"
                ),
            }
        }
        Ok(outcome)
    }

    /// Only append an unsent request or fill the last pending response. No
    /// completed predecessor, original intent, or step may be replaced.
    pub(crate) fn succeeds(&self, previous: &Self) -> bool {
        if self.format != previous.format || self.invocation != previous.invocation {
            return false;
        }
        if self == previous {
            return true;
        }
        if self.exchanges.len() == previous.exchanges.len() + 1 {
            return self.exchanges[..previous.exchanges.len()] == previous.exchanges
                && previous
                    .exchanges
                    .last()
                    .is_none_or(|last| last.response.is_some())
                && self
                    .exchanges
                    .last()
                    .is_some_and(|last| last.response.is_none());
        }
        if !self.exchanges.is_empty() && self.exchanges.len() == previous.exchanges.len() {
            let last = self.exchanges.len() - 1;
            return self.exchanges[..last] == previous.exchanges[..last]
                && self.exchanges[last].request == previous.exchanges[last].request
                && previous.exchanges[last].response.is_none()
                && self.exchanges[last].response.is_some();
        }
        false
    }
}

pub(crate) fn continue_retained(
    root: &std::path::Path,
    address: std::net::SocketAddr,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "continuation requires nonzero loopback HTTP"
    );
    let mut store = super::clean_store::CleanInvocationFile::open_or_create(root)?;
    let request = store
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("no retained invocation"))?;
    let response = store
        .load_response()?
        .ok_or_else(|| anyhow::anyhow!("retain initial invocation delivery before continuing"))?;
    let call = super::local_invocation::validate_request(&request)?;
    let mut progress = match store.load_progress()? {
        Some(bytes) => Progress::decode(&bytes, &request, &response)?,
        None => Progress::new(&request)?,
    };
    loop {
        let outcome = progress.outcome(&request, &response)?;
        let Some(action) = Action::for_outcome(&call, &outcome)? else {
            anyhow::ensure!(
                matches!(outcome, RuntimeOutcome::Acknowledged(Ok(_))),
                "retained acknowledgement reports retirement failure"
            );
            return Ok(());
        };
        let bytes = action.encode()?;
        if progress
            .exchanges
            .last()
            .is_none_or(|last| last.response.is_some())
        {
            anyhow::ensure!(
                progress.exchanges.len() < MAX_STEPS,
                "continuation history is full; preserved without discarding predecessors"
            );
            progress.exchanges.push(Exchange {
                request: hex::encode(&bytes),
                response: None,
            });
            store.publish_progress(&progress.encode()?)?;
        }
        let reply = super::local_create::post_binary(
            address,
            action.path(),
            200,
            &bytes,
            super::local_invocation::MAX_RESPONSE_BYTES,
        )?;
        action.verify(&reply)?;
        progress
            .exchanges
            .last_mut()
            .expect("retained pending request")
            .response = Some(hex::encode(reply));
        store.publish_progress(&progress.encode()?)?;
    }
}

pub(crate) fn run(root: &std::path::Path, address: std::net::SocketAddr) -> anyhow::Result<()> {
    continue_retained(root, address).map_err(|error| {
        anyhow::anyhow!("{error}; continuation history retained, retry exact pending work")
    })?;
    crate::output::print_json(&serde_json::json!({"delivery_retired": true}));
    Ok(())
}

#[cfg(test)]
#[path = "invocation_progress_tests.rs"]
mod tests;
