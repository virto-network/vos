//! Exact durable AOQ1 delivery. This does not prepare, issue or apply locally.
use vos::agent::local_lifecycle::AuthorityOperationSubmission;
use vos::agent::sdk::wire::CanonicalWire as _;

#[path = "operation_preparation.rs"]
pub(crate) mod preparation;

pub(crate) fn submit(
    root: &std::path::Path,
    input: Option<&std::path::Path>,
    address: std::net::SocketAddr,
) -> anyhow::Result<Vec<u8>> {
    use std::io::Read as _;
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "operation authorization requires nonzero loopback HTTP"
    );
    let mut store = super::clean_store::CleanOperationClientFile::open_or_create(root)?;
    let request = match store.load_request()? {
        Some(bytes) => bytes,
        None => {
            let input = input.ok_or_else(|| {
                anyhow::anyhow!(
                    "no retained authorization; provide --request with canonical signed AOQ1"
                )
            })?;
            let mut bytes = Vec::new();
            std::fs::File::open(input)?
                .take(AuthorityOperationSubmission::MAX_ENCODED_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            let candidate = AuthorityOperationSubmission::decode(&bytes)
                .map_err(|e| anyhow::anyhow!("invalid AOQ1: {e:?}"))?;
            anyhow::ensure!(
                candidate.call().authenticated_node().is_none(),
                "HTTP cannot assert a transport node"
            );
            store.publish_request(&bytes)?;
            bytes
        }
    };
    let submission = AuthorityOperationSubmission::decode(&request)
        .map_err(|e| anyhow::anyhow!("invalid retained AOQ1: {e:?}"))?;
    anyhow::ensure!(
        submission.call().authenticated_node().is_none(),
        "HTTP cannot assert a transport node"
    );
    (|| {
        if let Some(response) = store.load_response()? {
            return Ok(response);
        }
        let response = super::local_create::post_binary(
            address,
            "/__agents/authorize",
            200,
            &request,
            AuthorityOperationSubmission::MAX_RESPONSE_BYTES,
        )?;
        submission
            .decode_response(&response)
            .map_err(|e| anyhow::anyhow!("invalid request-bound AOR1: {e:?}"))?;
        store.publish_response(&response)?;
        Ok(response)
    })()
    .map_err(|error: anyhow::Error| {
        anyhow::anyhow!("{error}; exact authorization request retained, outcome may be unknown")
    })
}

pub(crate) fn run(
    root: &std::path::Path,
    input: Option<&std::path::Path>,
    address: std::net::SocketAddr,
) -> anyhow::Result<()> {
    let response = submit(root, input, address)?;
    // submit has verified and synchronized AOR1; its canonical discriminant
    // distinguishes the two decisions, not HTTP status or unsigned error text.
    let decision = if response[4] == 0 { "issued" } else { "denied" };
    crate::output::print_json(&serde_json::json!({
        "decision": decision, "response": hex::encode(response),
        "decision_retained": true, "applied": false,
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Args {
        #[command(subcommand)]
        command: super::super::SpaceCommand,
    }
    #[test]
    fn operation_authorization_command_accepts_fresh_and_retained_requests() {
        for input in [
            vec![
                "vosx",
                "submit-agent-authorization",
                "/private/operation",
                "--http",
                "127.0.0.1:8080",
            ],
            vec![
                "vosx",
                "submit-agent-authorization",
                "/private/operation",
                "--http",
                "127.0.0.1:8080",
                "--request",
                "request.aoq1",
            ],
        ] {
            let fresh = input.len() == 7;
            let super::super::SpaceCommand::SubmitAgentAuthorization { request, .. } =
                Args::try_parse_from(input).unwrap().command
            else {
                panic!("wrong command")
            };
            assert_eq!(request.is_some(), fresh);
        }
    }
}
