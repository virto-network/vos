//! Retained admin transport. No automatic credential sequencing or signing.
use super::clean_store::CleanOperationClientFile;
use std::{io::Read as _, net::SocketAddr, path::Path};
use vos::agent::clean_bootstrap::{
    NativeAuthorityAdminCompletion, NativeAuthorityAdminPreparation, NativeAuthorityAdminSubmission,
};
use vos::agent::sdk::{authority::AuthorityAdminCall, wire::CanonicalWire as _};

pub(crate) fn deliver(
    root: &Path,
    input: Option<&Path>,
    address: SocketAddr,
    prepare: bool,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        address.ip().is_loopback() && address.port() != 0,
        "admin control requires nonzero loopback HTTP"
    );
    let mut store = if prepare {
        CleanOperationClientFile::open_admin_preparation(root)?
    } else {
        CleanOperationClientFile::open_admin_submission(root)?
    };
    let maximum = if prepare {
        AuthorityAdminCall::MAX_ENCODED_BYTES
    } else {
        NativeAuthorityAdminSubmission::MAX_ENCODED_BYTES
    };
    let request = match store.load_request()? {
        Some(bytes) => bytes,
        None => {
            let input = input.ok_or_else(|| anyhow::anyhow!("no retained admin request; provide --request with a signed zero-slot draft or NAS1"))?;
            let mut bytes = Vec::new();
            std::fs::File::open(input)?
                .take(maximum as u64 + 1)
                .read_to_end(&mut bytes)?;
            store.publish_request(&bytes)?;
            bytes
        }
    };
    (|| {
        if let Some(response) = store.load_response()? { return Ok(response); }
        let path = if prepare { "/__agents/admin/prepare" } else { "/__agents/admin" };
        let maximum = if prepare { NativeAuthorityAdminPreparation::MAX_ENCODED_BYTES } else { NativeAuthorityAdminCompletion::MAX_BYTES };
        let (status, response) = super::local_create::post_binary_response(address, path, 200, &request, maximum, (!prepare).then_some(NativeAuthorityAdminCompletion::MAX_BYTES), None)?;
        if !prepare {
            let submission = NativeAuthorityAdminSubmission::decode(&request).map_err(|e| anyhow::anyhow!("invalid retained NAS1: {e:?}"))?;
            let completion = submission.verify_completion(&response).map_err(|e| anyhow::anyhow!("invalid admin completion: {e:?}"))?;
            anyhow::ensure!((status == 403) == completion.result().is_none(), "admin HTTP status contradicts signed completion");
        }
        store.publish_response(&response)?;
        Ok(response)
    })().map_err(|error: anyhow::Error| {
        let diagnostic = format!("{error}; exact admin request retained; outcome may be unknown; retry the same request directory");
        error.context(diagnostic)
    })
}

pub(crate) fn run(
    root: &Path,
    input: Option<&Path>,
    address: SocketAddr,
    prepare: bool,
) -> anyhow::Result<()> {
    let response = deliver(root, input, address, prepare)?;
    let decision = if prepare {
        "prepared"
    } else {
        let mut store = CleanOperationClientFile::open_admin_submission(root)?;
        let request = store
            .load_request()?
            .ok_or_else(|| anyhow::anyhow!("missing retained NAS1"))?;
        let submission = NativeAuthorityAdminSubmission::decode(&request)
            .map_err(|e| anyhow::anyhow!("invalid retained NAS1: {e:?}"))?;
        let completion = submission
            .verify_completion(&response)
            .map_err(|e| anyhow::anyhow!("invalid retained completion: {e:?}"))?;
        if completion.result().is_some() {
            "applied"
        } else {
            "denied"
        }
    };
    crate::output::print_json(&serde_json::json!({
        "phase": if prepare { "prepared" } else { "retired" },
        "decision": decision,
        "response": hex::encode(response), "response_retained": true,
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
    fn admin_client_cli_requires_address_and_allows_retained_retry() {
        for command in ["prepare-admin", "submit-admin"] {
            assert!(Args::try_parse_from(["space", command, "state"]).is_err());
            assert!(
                Args::try_parse_from(["space", command, "state", "--http", "127.0.0.1:8080"])
                    .is_ok()
            );
            assert!(
                Args::try_parse_from([
                    "space",
                    command,
                    "state",
                    "--http",
                    "127.0.0.1:8080",
                    "--request",
                    "signed.bin"
                ])
                .is_ok()
            );
        }
    }

    #[test]
    fn retained_admin_preparation_preserves_transport_causes_and_signed_request() {
        use super::super::clean_store::tests::Fixture;
        use super::*;
        use vos::agent::sdk::{
            CredentialId, InvocationId, NodeId, RoleId, authority::AuthorityAdminOperation,
        };
        let fixture = Fixture::new("retained-admin-transport");
        let (operator, authority, descriptor, _) = super::super::local_create::tests::fixture();
        let public = operator.public().try_into_ed25519().unwrap().to_bytes();
        let mut draft = AuthorityAdminCall {
            invocation: InvocationId::ZERO,
            authority,
            administrator: descriptor.identity.owner,
            credential: CredentialId::of_public_key(&public),
            request_sequence: core::num::NonZeroU64::new(1).unwrap(),
            credential_public_key: public,
            authenticated_node: NodeId([9; 32]),
            observed_slot: 0,
            expected_generation: core::num::NonZeroU64::new(1).unwrap(),
            operation: AuthorityAdminOperation::SetSpaceRole {
                principal: descriptor.identity.owner,
                role: RoleId([0x51; 32]),
                granted: true,
            },
            signature: [1; 64],
        };
        draft.invocation = draft.expected_invocation();
        draft.signature = operator
            .sign(&draft.signing_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        draft
            .verify_with(&super::super::local_create::CredentialVerifier)
            .unwrap();
        let exact = draft.encode().unwrap();
        CleanOperationClientFile::open_admin_preparation(&fixture.root)
            .unwrap()
            .publish_request(&exact)
            .unwrap();
        let unavailable = b"HTTP/1.1 503 Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        for response in [Some(unavailable.as_slice()), None] {
            let (address, server) = super::super::local_create::tests::binary_response_for_test(
                "/__agents/admin/prepare",
                &exact,
                response,
            );
            let error = deliver(&fixture.root, None, address, true).unwrap_err();
            server.join().unwrap();
            let cause = error
                .downcast_ref::<ureq::Error>()
                .expect("typed HTTP/transport cause");
            assert!(match response {
                Some(_) => matches!(cause, ureq::Error::Status(503, _)),
                None => matches!(cause, ureq::Error::Transport(_)),
            });
            assert_eq!(
                error.to_string(),
                format!(
                    "{cause}; exact admin request retained; outcome may be unknown; retry the same request directory"
                )
            );
            let mut retained =
                CleanOperationClientFile::open_admin_preparation(&fixture.root).unwrap();
            assert!(
                retained.load_request().unwrap().unwrap() == exact,
                "admin draft changed after ambiguity"
            );
            assert!(retained.load_response().unwrap().is_none());
        }
    }
}
