//! `ConsoleEngine` — owns the sandboxed nushell `EngineState` + a persistent
//! `Stack`, registers actor commands discovered from the space, and evaluates
//! a line of nu-script returning rendered text.
//!
//! The persistent stack + per-line delta merge give REPL semantics: a `let`
//! on one line is visible on the next, exactly as nushell's own REPL does.

use std::sync::Arc;

use nu_protocol::debugger::WithoutDebug;
use nu_protocol::engine::{EngineState, Stack, StateWorkingSet};
use nu_protocol::{PipelineData, Span};

use crate::actor_cmd::ActorCommand;
use crate::backend::{BackendError, SpaceClient};
use crate::sandbox;
use crate::value_bridge;

/// The outcome of evaluating one line.
#[derive(Debug, Clone)]
pub struct EvalResult {
    /// Rendered value (success) or error text (failure).
    pub output: String,
    /// True if evaluation failed (parse or runtime).
    pub is_error: bool,
    /// True if the failure was the daemon's auth gate (permission denied).
    /// Exec mode maps this to a distinct exit code; the TUI highlights it.
    pub forbidden: bool,
}

impl EvalResult {
    fn ok(output: String) -> Self {
        Self {
            output,
            is_error: false,
            forbidden: false,
        }
    }
    fn err(output: String, forbidden: bool) -> Self {
        Self {
            output,
            is_error: true,
            forbidden,
        }
    }
}

pub struct ConsoleEngine {
    engine_state: EngineState,
    stack: Stack,
    client: Arc<dyn SpaceClient>,
}

impl ConsoleEngine {
    /// Build an engine, discovering + registering the space's actor commands.
    pub fn new(client: Arc<dyn SpaceClient>) -> Result<Self, BackendError> {
        let mut me = Self {
            engine_state: sandbox::base_engine_state(),
            stack: Stack::new(),
            client,
        };
        me.refresh()?;
        Ok(me)
    }

    /// Borrow the underlying client (for the TUI browser / completion).
    pub fn client(&self) -> &Arc<dyn SpaceClient> {
        &self.client
    }

    /// (Re)discover installed agents and register their messages as commands.
    /// Idempotent and additive — safe to call when agents change. Returns the
    /// number of commands registered this pass.
    ///
    /// Unlike the top-level `vosx` CLI (which curates its surface via the
    /// `#[msg(cli)]` tag / `exposed_to_cli`), the console exposes an actor's
    /// FULL message interface — it's the OS-like interactive surface, so every
    /// message is a command, matching what the HTTP gateway dispatches.
    pub fn refresh(&mut self) -> Result<usize, BackendError> {
        let agents = self.client.list_agents()?;
        let mut count = 0;
        let delta = {
            let mut ws = StateWorkingSet::new(&self.engine_state);
            for agent in &agents {
                // A missing/undecodable schema just means no commands for that
                // agent yet — skip rather than fail the whole refresh.
                let meta = match self.client.schema(&agent.instance_name) {
                    Ok(Some(m)) => m,
                    Ok(None) | Err(_) => continue,
                };
                for msg in &meta.messages {
                    ws.add_decl(Box::new(ActorCommand::new(
                        agent.instance_name.clone(),
                        msg,
                        self.client.clone(),
                    )));
                    count += 1;
                }
            }
            ws.render()
        };
        self.engine_state
            .merge_delta(delta)
            .map_err(|e| BackendError::Other(format!("merge actor commands: {e:?}")))?;
        Ok(count)
    }

    /// Evaluate one line of nu-script.
    pub fn eval(&mut self, src: &str) -> EvalResult {
        // Parse against a working set derived from the live engine; capture the
        // delta (new vars/defs) so REPL state persists across lines.
        let (block, delta) = {
            let mut ws = StateWorkingSet::new(&self.engine_state);
            let block = nu_parser::parse(&mut ws, None, src.as_bytes(), false);
            if let Some(err) = ws.parse_errors.first() {
                return EvalResult::err(err.to_string(), false);
            }
            (block, ws.render())
        };
        if let Err(e) = self.engine_state.merge_delta(delta) {
            return EvalResult::err(format!("internal error: {e:?}"), false);
        }

        match nu_engine::eval_block::<WithoutDebug>(
            &self.engine_state,
            &mut self.stack,
            &block,
            PipelineData::empty(),
        ) {
            Ok(data) => match data.body.into_value(Span::unknown()) {
                Ok(v) => EvalResult::ok(value_bridge::render_value(&v)),
                Err(e) => EvalResult::err(e.to_string(), false),
            },
            Err(e) => {
                let text = e.to_string();
                let forbidden = text.contains("permission denied");
                let output = if sandbox::is_unknown_command_error(&text) {
                    sandbox::friendly_unknown_command()
                } else {
                    text
                };
                EvalResult::err(output, forbidden)
            }
        }
    }
}
