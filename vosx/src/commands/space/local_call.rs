//! Human-readable Local calls use the same retained ATQ1 authorization and
//! delivery path as `invoke-local`. The package is an argument-encoding aid;
//! the live Agent still selects and validates its installed actor and policy.

use super::clean_identity::CleanOperatorIdentitySigner;
use serde_json::Value as Json;
use std::net::SocketAddr;
use std::path::PathBuf;
use vos::agent::sdk::RuntimeOutcome;
use vos::agent::sdk::method_policy::{ActorMethodPolicy, ActorMethodPolicyArtifact};
use vos::agent::sdk::wire::CanonicalWire as _;
use vos::agent::sdk::{ActorId, AgentId, InvocationId, InvocationOrigin, InvocationRoleClaims};
use vos::agent::supervisor::AgentRouteKey;
use vos::agent::supervisor_adapters::{
    AgentInvocationIntent, AgentInvocationResponse, AgentTargetedPreparationRequest,
};
use vos::value::{Msg, Value};
use vos::{Decode as _, Encode as _};

#[derive(clap::Args, Debug)]
pub struct CallLocalArgs {
    pub space: String,
    /// Full Agent ID, as printed by create-local-agent.
    pub agent: String,
    /// Installed top-level actor name.
    pub actor: String,
    /// Method declared by the signed actor package.
    pub method: String,
    /// Signed VOS3 package used to encode arguments (the live route remains authoritative).
    #[arg(long)]
    pub package: PathBuf,
    /// Flat JSON object of named method arguments, for example '{"by":7}'.
    #[arg(long, default_value = "{}")]
    pub args: String,
    #[arg(long)]
    pub http: Option<SocketAddr>,
}

pub(crate) fn run(args: CallLocalArgs) -> anyhow::Result<()> {
    use std::io::Read as _;
    let (data, space, node_public, address) =
        super::local_create::resolve_local_space(&args.space, args.http)?;
    let agent = AgentId(
        hex::decode(&args.agent)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid full Agent ID"))?,
    );
    let operator = crate::identity::load_existing()?;
    let identity = CleanOperatorIdentitySigner::new(&operator)?;
    let mut bytes = Vec::new();
    std::fs::File::open(&args.package)?
        .take(vos::agent::sdk::package::MAX_PACKAGE_ENCODED_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let package = vos::agent::package_admission::admit_actor_package(&bytes)
        .map_err(|error| anyhow::anyhow!("invalid actor package: {error:?}"))?;
    let policies = ActorMethodPolicyArtifact::decode(package.method_policy_bytes())
        .map_err(|error| anyhow::anyhow!("invalid actor method policy: {error:?}"))?;
    let method = policies.method(&args.method).ok_or_else(|| {
        anyhow::anyhow!("method '{}' is not declared by the package", args.method)
    })?;
    let message = encode_message(method, &args.args)?;
    let mut nonce = [0u8; 32];
    getrandom::getrandom(&mut nonce)
        .map_err(|error| anyhow::anyhow!("invocation nonce entropy: {error}"))?;
    anyhow::ensure!(nonce != [0; 32], "zero invocation nonce");
    let intent = AgentTargetedPreparationRequest::new(
        AgentRouteKey::new(space, agent, ActorId::top_level(agent, &args.actor))?,
        AgentInvocationIntent::new(
            InvocationId(nonce),
            method.mode,
            InvocationOrigin {
                principal: Some(identity.principal()),
                credential: Some(identity.credential()),
                ..InvocationOrigin::anonymous()
            },
            InvocationRoleClaims::none(),
            message,
            vos::agent::execution::MAX_EXECUTION_GAS,
            false,
        )?,
    )?;
    let (request_dir, response) = super::local_operation::authorize_with_application(
        &data,
        address,
        &operator,
        space,
        node_public,
        Some(&intent),
        true,
    )?;
    let denied = response[4] == 1; // Verified canonical AOR1.
    let result = if denied {
        None
    } else {
        Some(retained_result(&request_dir)?)
    };
    crate::output::print_json(&serde_json::json!({
        "decision": if denied { "denied" } else { "issued" },
        "request_dir": request_dir,
        "decision_retained": true,
        "delivery_retired": !denied,
        "result": result,
        "retry": format!("vosx space invoke-local {} --resume --http {}", args.space, address),
    }));
    Ok(())
}

fn retained_result(request_dir: &std::path::Path) -> anyhow::Result<Json> {
    let application = request_dir
        .parent()
        .ok_or_else(|| anyhow::anyhow!("invalid retained operation path"))?
        .join("application");
    let mut store = super::clean_store::CleanInvocationFile::open_or_create(application)?;
    let request = store
        .load_request()?
        .ok_or_else(|| anyhow::anyhow!("missing retained invocation"))?;
    let response = store
        .load_response()?
        .ok_or_else(|| anyhow::anyhow!("missing retained invocation response"))?;
    let outcome = super::local_invocation::verify_response(&request, &response)?;
    let (AgentInvocationResponse::Direct { outcome, .. }
    | AgentInvocationResponse::Attested { outcome, .. }) = outcome;
    Ok(match outcome {
        RuntimeOutcome::Completed(Ok(reply)) => serde_json::json!({
            "status": format!("{:?}", reply.status),
            "value": Value::try_decode(&reply.reply).map(|value| crate::output::value_to_json(&value)),
            "reply_hex": hex::encode(reply.reply),
        }),
        RuntimeOutcome::Completed(Err(error)) => serde_json::json!({
            "error": format!("{error:?}"),
        }),
        other => serde_json::json!({"outcome": format!("{other:?}")}),
    })
}

fn encode_message(method: &ActorMethodPolicy, args: &str) -> anyhow::Result<Vec<u8>> {
    let Json::Object(mut supplied) = serde_json::from_str(args)? else {
        anyhow::bail!("method arguments must be a flat JSON object");
    };
    let mut msg = Msg::new(&method.name);
    for argument in &method.arguments {
        let value = supplied
            .remove(&argument.name)
            .ok_or_else(|| anyhow::anyhow!("missing argument '{}'", argument.name))?;
        msg = msg.with(
            &argument.name,
            encode_argument(&argument.type_identity, value)?,
        );
    }
    anyhow::ensure!(
        supplied.is_empty(),
        "unknown argument(s): {}",
        supplied.keys().cloned().collect::<Vec<_>>().join(", ")
    );
    let mut message = vec![vos::value::TAG_DYNAMIC];
    message.extend_from_slice(&msg.encode());
    Ok(message)
}

fn encode_argument(type_identity: &str, value: Json) -> anyhow::Result<Value> {
    let ty: String = type_identity
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let bad = || anyhow::anyhow!("argument is not a valid {type_identity}");
    Ok(match ty.as_str() {
        "u8" => Value::U8(
            value
                .as_u64()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(bad)?,
        ),
        "u16" => Value::U16(
            value
                .as_u64()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(bad)?,
        ),
        "u32" => Value::U32(
            value
                .as_u64()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(bad)?,
        ),
        "u64" => Value::U64(value.as_u64().ok_or_else(bad)?),
        "i32" => Value::I32(
            value
                .as_i64()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(bad)?,
        ),
        "i64" => Value::I64(value.as_i64().ok_or_else(bad)?),
        "bool" => Value::Bool(value.as_bool().ok_or_else(bad)?),
        "String" => Value::Str(value.as_str().ok_or_else(bad)?.to_owned()),
        "Vec<u8>" => Value::Bytes(parse_bytes(value)?),
        "Vec<u32>" => Value::ListU32(parse_u32_list(value)?),
        "Vec<String>" => Value::ListStr(parse_string_list(value)?),
        _ if ty.starts_with("[u8;") && ty.ends_with(']') => {
            let len: usize = ty[4..ty.len() - 1].parse().map_err(|_| bad())?;
            let bytes = parse_bytes(value)?;
            anyhow::ensure!(bytes.len() == len, "expected exactly {len} bytes");
            Value::Bytes(bytes)
        }
        _ => anyhow::bail!(
            "unsupported CLI argument type {type_identity}; use invoke-local with a canonical ATQ1"
        ),
    })
}

fn parse_bytes(value: Json) -> anyhow::Result<Vec<u8>> {
    if let Some(hex) = value.as_str() {
        return hex::decode(hex.strip_prefix("0x").unwrap_or(hex)).map_err(Into::into);
    }
    let Json::Array(values) = value else {
        anyhow::bail!("bytes require a hex string or an array of u8 values");
    };
    values
        .into_iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("byte array element is not u8"))
        })
        .collect()
}

fn parse_u32_list(value: Json) -> anyhow::Result<Vec<u32>> {
    let Json::Array(values) = value else {
        anyhow::bail!("Vec<u32> requires an array");
    };
    values
        .into_iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|n| n.try_into().ok())
                .ok_or_else(|| anyhow::anyhow!("array element is not u32"))
        })
        .collect()
}

fn parse_string_list(value: Json) -> anyhow::Result<Vec<String>> {
    let Json::Array(values) = value else {
        anyhow::bail!("Vec<String> requires an array");
    };
    values
        .into_iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("array element is not a string"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos::agent::sdk::MethodMode;
    use vos::agent::sdk::method_policy::{
        AttestationRequirement, AuthorizationPolicySelector, IdempotencyRequirement, MethodArgument,
    };

    fn method() -> ActorMethodPolicy {
        ActorMethodPolicy {
            name: "increment".into(),
            mode: MethodMode::Linear,
            arguments: vec![MethodArgument {
                name: "by".into(),
                type_identity: "u64".into(),
            }],
            return_type_identity: "u64".into(),
            authorization_policy: AuthorizationPolicySelector::Public,
            idempotency: IdempotencyRequirement::Required,
            attestation: AttestationRequirement::None,
        }
    }

    #[test]
    fn schema_argument_encoder_accepts_exact_shape_and_rejects_extra_fields() {
        let encoded = encode_message(&method(), r#"{"by":7}"#).unwrap();
        assert_eq!(encoded[0], vos::value::TAG_DYNAMIC);
        assert_eq!(
            &encoded[1..],
            Msg::new("increment").with("by", 7u64).encode()
        );
        assert!(encode_message(&method(), r#"{"by":7,"other":1}"#).is_err());
        assert!(encode_message(&method(), r#"{"by":-1}"#).is_err());
    }

    #[test]
    fn byte_arguments_validate_fixed_length() {
        assert_eq!(
            encode_argument("[u8; 2]", Json::String("00ff".into())).unwrap(),
            Value::Bytes(vec![0, 255])
        );
        assert_eq!(
            encode_argument("Vec<u8>", Json::String("0x00ff".into())).unwrap(),
            Value::Bytes(vec![0, 255])
        );
        assert!(encode_argument("[u8; 2]", Json::String("00".into())).is_err());
    }
}
