//! Calls and queries signed with a client key, reads of the workflows it
//! started, and the answers printed.

use std::mem;
use std::path::Path;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_node::client::{Client, ClientError};
use vos_wire::Encode;
use vos_wire::abi::Refusal;
use vos_wire::ids::{AgentId, InstanceId, WorkflowId};
use vos_wire::ingress::{Answer, Consistency, WorkflowStatus};
use vos_wire::result::Outcome;

use crate::args::{CallArgs, NodeArgs, WorkflowArgs};
use crate::kept::Kept;
use crate::{at, failed, key_bytes, method_named};

/// A client of the node `node` for the key whose seed file is `key`, going
/// on with what the key kept, which comes back emptied of what the client
/// took.
fn resume(node: &NodeArgs, key: &Path) -> Result<(Client, Kept), String> {
    let seed = std::fs::read_to_string(key).map_err(at(key))?;
    let signing = SigningKey::from_bytes(&key_bytes(&seed)?);
    let target = node.target()?;
    let mut kept = Kept::load(key)?;
    let client = Client::resume(
        &target,
        signing,
        mem::take(&mut kept.sessions),
        mem::take(&mut kept.identities),
    );
    for (agent, at) in mem::take(&mut kept.floors) {
        client.raise_floor(agent, at);
    }
    Ok((client, kept))
}

/// Keep what `client` learned beside the key `key`.
fn keep(client: &Client, mut kept: Kept, key: &Path) -> Result<(), String> {
    kept.sessions = client.sessions();
    kept.identities = client.identities();
    kept.floors = client.floors();
    kept.save(key)
}

/// A call, or (`Some(linearizable)`) a query.
pub fn invoke(call: &CallArgs, query: Option<bool>) -> Result<(), String> {
    let arguments = hex::decode(call.args.trim()).map_err(|error| error.to_string())?;
    let agent = AgentId(call.agent);
    let instance = InstanceId(call.instance);
    let (mut client, mut kept) = resume(&call.node, &call.key)?;
    let schema = client
        .schema(agent, instance)
        .map_err(failed)?
        .ok_or_else(|| format!("nothing is installed as instance {}", call.instance))?;
    let method = method_named(&schema, &call.method)?;
    let answer = if let Some(linearizable) = query {
        let not_after = vos_node::wall_clock() + 60_000;
        let consistency = if linearizable {
            Consistency::Linearizable
        } else {
            Consistency::Applied {
                at: client.floor(agent),
            }
        };
        client.query_with(agent, instance, method, &arguments, not_after, consistency)
    } else {
        // A call that failed before its answer goes again with its
        // sequence, and is answered once. Another call leaves that session
        // first, so the earlier one's answer is never taken for its own.
        let digest =
            vos_pvm::precompile::blake2b_256(&(instance, method, arguments.clone()).encode());
        match kept.pending.remove(&agent) {
            Some(pending) if pending != digest => {
                eprintln!(
                    "an earlier call to agent {} was never answered: whether it ran stays unknown",
                    agent.0
                );
                client.renew(agent);
            }
            // A refusal of its session proves nothing of the first: copies
            // may be on their way, or its session collected.
            Some(_) => client.repeats_unknown(agent),
            None => {}
        }
        let answer = client.call(agent, instance, method, &arguments);
        // Unanswered: the call may have run, or may yet. A lost one can be
        // answered no more.
        let unanswered = match &answer {
            Err(ClientError::Lost) => false,
            Err(_) => true,
            Ok(answer) => matches!(
                answer,
                Answer::Stopped | Answer::NotLeader { .. } | Answer::Unavailable | Answer::TimedOut
            ),
        };
        if unanswered {
            kept.pending.insert(agent, digest);
        }
        answer
    };
    keep(&client, kept, &call.key)?;
    match answer {
        Ok(answer) => print_answer(&answer),
        Err(ClientError::Lost) => Err(
            "the call may have run, and its session is gone: its answer is lost for good".into(),
        ),
        Err(error) if query.is_none() => Err(format!(
            "{}; the call may have run: run it again to learn its answer",
            failed(error)
        )),
        Err(error) => Err(failed(error)),
    }
}

/// What an answer says: a call that ran, done or failed, or the workflow
/// it started, as printed; any other answer as an error.
pub fn said(answer: &Answer) -> Result<String, String> {
    match answer {
        Answer::Ran {
            outcome: Outcome::Done(reply),
            ..
        } => Ok(format!("done {}", hex::encode(reply))),
        Answer::Ran {
            outcome: Outcome::Failed { code, detail },
            ..
        } => Ok(format!("failed {} {}", code.code(), hex::encode(detail))),
        Answer::Ran {
            outcome: Outcome::Started(workflow),
            ..
        } => Ok(format!("started {}", workflow.0)),
        Answer::Refused(Refusal::SessionsFull) => {
            Err("refused: the agent holds as many sessions as it may; try again later".into())
        }
        Answer::Refused(Refusal::KeySessionsFull) => {
            Err("refused: this key holds as many sessions at the agent as it may".into())
        }
        Answer::Refused(code) => Err(format!("refused {}", code.code())),
        other => Err(format!("{other:?}")),
    }
}

/// Read a workflow the key started, waiting as asked for it to end, and
/// print where it stands: `running`, `awaiting <agent> until <time>`,
/// `sleeping until <time>`, or its result as a call's is printed.
pub fn read_workflow(read: &WorkflowArgs) -> Result<(), String> {
    let agent = AgentId(read.agent);
    let (client, kept) = resume(&read.node, &read.key)?;
    let consistency = if read.linearizable {
        Consistency::Linearizable
    } else {
        Consistency::Applied {
            at: client.floor(agent),
        }
    };
    let wait = Duration::from_secs(read.wait);
    let answer = client.workflow_with(agent, WorkflowId(read.id), wait, consistency);
    keep(&client, kept, &read.key)?;
    let status = match answer.map_err(failed)? {
        Answer::Workflow { status, .. } => status,
        other => return Err(said(&other).err().unwrap_or_else(|| format!("{other:?}"))),
    };
    let line = match status {
        WorkflowStatus::Unknown => {
            return Err(format!(
                "agent {} holds no workflow {} this key started: a result is kept about an hour after its workflow ends",
                read.agent, read.id
            ));
        }
        WorkflowStatus::Running => "running".to_string(),
        WorkflowStatus::Awaiting { agent, deadline } => {
            format!("awaiting {} until {deadline}", agent.0)
        }
        WorkflowStatus::Sleeping { until } => format!("sleeping until {until}"),
        WorkflowStatus::Ended(outcome) => said(&Answer::Ran { outcome, at: 0 })?,
    };
    println!("{line}");
    Ok(())
}

pub fn print_answer(answer: &Answer) -> Result<(), String> {
    println!("{}", said(answer)?);
    Ok(())
}

/// An install's or a role's answer. Each overwrites what it sets, so one
/// that timed out is safe to send again.
pub fn print_admin_answer(answer: &Answer) -> Result<(), String> {
    match answer {
        Answer::TimedOut => {
            Err("no answer in time: it may have run, or may yet; sending it again is safe".into())
        }
        other => print_answer(other),
    }
}
