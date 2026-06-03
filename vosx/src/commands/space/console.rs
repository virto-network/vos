//! `vosx space console <space>` — open the sandboxed nu-script console against
//! a running local daemon. Actors of the space appear as commands; the prompt
//! evaluates real nu-script with no filesystem/network access (see `vos-shell`).
//!
//! This is the local milestone of the SSH-accessible console: it drives the
//! shared [`vos_shell::ConsoleEngine`] over a [`DaemonClientBackend`]. The same
//! engine is later driven over SSH (`ServiceCtx::ask_raw_as`). For now the UI
//! is a line REPL; a ratatui TUI replaces the loop in a follow-up, reusing the
//! engine unchanged.

use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use vos::abi::service::ServiceId;
use vos::value::{Msg, Value};
use vos_shell::backend::{AgentInfo, BackendError, SpaceClient};
use vos_shell::{ConsoleEngine, is_forbidden_envelope};

use super::client::DaemonClient;

/// Adapts the libp2p `DaemonClient` to the transport-agnostic `SpaceClient`
/// the console engine consumes. The operator's persistent identity is carried
/// by the client's libp2p peer, so the daemon enforces ACLs on the real
/// caller — no role plumbing needed here (that's the SSH backend's job).
///
/// `DaemonClient` holds an `mpsc::Receiver` and so is `!Sync`, but nushell's
/// `Command` (which transitively owns this via the engine) requires
/// `Send + Sync`. A `Mutex` provides the `Sync` shell; it is uncontended
/// because the console REPL evaluates on a single thread.
struct DaemonClientBackend {
    client: Mutex<DaemonClient>,
}

impl SpaceClient for DaemonClientBackend {
    fn list_agents(&self) -> Result<Vec<AgentInfo>, BackendError> {
        self.client
            .lock()
            .unwrap()
            .agents()
            .map(|rows| {
                rows.into_iter()
                    .map(|r| AgentInfo {
                        instance_name: r.instance_name,
                        program_name: r.program_name,
                    })
                    .collect()
            })
            .map_err(|e| BackendError::Other(e.to_string()))
    }

    fn resolve_target(&self, name: &str) -> Result<ServiceId, BackendError> {
        self.client
            .lock()
            .unwrap()
            .resolve_target(name)
            .map_err(|_| BackendError::NotFound(name.to_string()))
    }

    fn raw_meta(&self, name: &str) -> Result<Vec<u8>, BackendError> {
        self.client
            .lock()
            .unwrap()
            .meta_for_instance(name)
            .map_err(|e| BackendError::Other(e.to_string()))
    }

    fn invoke(&self, target: ServiceId, msg: &Msg) -> Result<Value, BackendError> {
        let reply = self
            .client
            .lock()
            .unwrap()
            .invoke_dyn_bytes(target, msg)
            .map_err(|e| {
                let m = e.to_string();
                if m.contains("didn't reply") {
                    BackendError::Unreachable
                } else {
                    BackendError::Other(m)
                }
            })?;
        if is_forbidden_envelope(&reply) {
            return Err(BackendError::Forbidden);
        }
        if reply.is_empty() {
            return Ok(Value::Unit);
        }
        Ok(vos::Decode::decode(&reply))
    }
}

pub fn run(space: &str) -> anyhow::Result<()> {
    let client =
        DaemonClient::connect(space).with_context(|| format!("connecting to space '{space}'"))?;
    let backend = Arc::new(DaemonClientBackend {
        client: Mutex::new(client),
    });

    let mut engine = ConsoleEngine::new(backend.clone())
        .map_err(|e| anyhow::anyhow!("starting console: {e}"))?;

    let stdin = io::stdin();
    let interactive = stdin.is_terminal();
    if interactive {
        println!(
            "vos space console — actors are commands (e.g. `<agent> <method> args…`); \
             real nu-script, sandboxed (no fs/net). `exit` or Ctrl-D to quit."
        );
    }

    let mut out = io::stdout();
    let mut handle = stdin.lock();
    let mut line = String::new();
    loop {
        if interactive {
            print!("{space}> ");
            out.flush().ok();
        }
        line.clear();
        if handle.read_line(&mut line)? == 0 {
            break; // EOF
        }
        let src = line.trim_end();
        if src.is_empty() {
            continue;
        }
        if src == "exit" || src == "quit" {
            break;
        }
        let result = engine.eval(src);
        if result.is_error {
            eprintln!("{}", result.output);
        } else if !result.output.is_empty() {
            println!("{}", result.output);
        }
    }

    // Drop the engine's Arc clone so the backend (and its DaemonClient) can be
    // reclaimed and shut down cleanly, draining libp2p threads.
    drop(engine);
    if let Ok(backend) = Arc::try_unwrap(backend) {
        if let Ok(client) = backend.client.into_inner() {
            client.shutdown().ok();
        }
    }
    Ok(())
}
