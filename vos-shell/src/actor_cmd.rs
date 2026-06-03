//! `ActorCommand` — adapts one CLI-exposed actor message into a nushell
//! command. The command name is `"<instance> <method>"` (a nushell
//! subcommand, e.g. `counter add`), so actors read like programs of an OS
//! with their methods as subcommands.
//!
//! Arguments are **required positionals in declared field order**
//! (`counter add 2 3`), each coerced against the field's declared type via
//! [`crate::value_bridge`]. The reply is bridged back to a nu value.

use std::sync::Arc;

use nu_engine::command_prelude::*;
use vos::metadata::ParsedMessage;
use vos::value::Msg;

use crate::backend::{BackendError, SpaceClient};
use crate::value_bridge;

/// Map a declared Rust field type string to a nushell `SyntaxShape` for the
/// signature (drives parsing + completion). Unknown types accept anything.
pub fn syntax_for(ty: &str) -> SyntaxShape {
    match ty {
        "u8" | "u16" | "u32" | "u64" | "i32" | "i64" => SyntaxShape::Int,
        "bool" => SyntaxShape::Boolean,
        "String" | "str" | "&str" | "&'static str" => SyntaxShape::String,
        "Vec<u8>" | "Vec<u32>" => SyntaxShape::List(Box::new(SyntaxShape::Int)),
        "Vec<String>" | "Vec<&str>" => SyntaxShape::List(Box::new(SyntaxShape::String)),
        _ => SyntaxShape::Any,
    }
}

#[derive(Clone)]
pub struct ActorCommand {
    agent: String,
    method: String,
    full_name: String,
    /// (field name, declared type) in declaration order.
    fields: Vec<(String, String)>,
    description: String,
    client: Arc<dyn SpaceClient>,
}

impl ActorCommand {
    pub fn new(agent: String, msg: &ParsedMessage, client: Arc<dyn SpaceClient>) -> Self {
        let full_name = format!("{agent} {}", msg.name);
        let fields = msg
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.ty.clone()))
            .collect();
        let description = if msg.is_query {
            format!("query (read-only) on `{agent}`")
        } else {
            format!("action (write) on `{agent}`")
        };
        Self {
            agent,
            method: msg.name.clone(),
            full_name,
            fields,
            description,
            client,
        }
    }
}

impl Command for ActorCommand {
    fn name(&self) -> &str {
        &self.full_name
    }

    fn description(&self) -> &str {
        &self.description
    }

    fn signature(&self) -> Signature {
        let mut sig = Signature::build(self.full_name.clone())
            .category(Category::Custom("space".into()))
            .input_output_types(vec![(Type::Any, Type::Any)]);
        for (name, ty) in &self.fields {
            sig = sig.required(name.clone(), syntax_for(ty), ty.clone());
        }
        sig
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let mut msg = Msg::new(self.method.clone());
        for (i, (name, ty)) in self.fields.iter().enumerate() {
            let nu_val: Value = call.req(engine_state, stack, i)?;
            let vos_val = value_bridge::nu_to_vos_typed(&nu_val, ty)
                .map_err(|e| arg_error(&self.full_name, name, &e, call.head))?;
            msg = msg.with(name.clone(), vos_val);
        }

        let target = self
            .client
            .resolve_target(&self.agent)
            .map_err(|e| backend_error(e, call.head))?;
        let reply = self
            .client
            .invoke(target, &msg)
            .map_err(|e| backend_error(e, call.head))?;
        Ok(value_bridge::vos_to_nu(reply, call.head).into_pipeline_data())
    }
}

fn arg_error(cmd: &str, field: &str, msg: &str, span: Span) -> ShellError {
    ShellError::GenericError {
        error: format!("invalid argument `{field}` for `{cmd}`"),
        msg: msg.to_string(),
        span: Some(span),
        help: None,
        inner: vec![],
    }
}

fn backend_error(e: BackendError, span: Span) -> ShellError {
    let help = matches!(e, BackendError::Forbidden)
        .then(|| "ask a space admin to grant your identity a higher role".to_string());
    ShellError::GenericError {
        error: e.to_string(),
        msg: String::new(),
        span: Some(span),
        help,
        inner: vec![],
    }
}
