//! Calls and queries signed with a client key, and the answers printed.

use std::mem;

use ed25519_dalek::SigningKey;
use vos_node::client::{Client, ClientError};
use vos_wire::Encode;
use vos_wire::abi::refusal;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::{Answer, Consistency};
use vos_wire::result::Outcome;

use crate::args::CallArgs;
use crate::kept::Kept;
use crate::{at, failed, key_bytes, method_named};

/// A call, or (`Some(linearizable)`) a query.
pub fn invoke(call: &CallArgs, query: Option<bool>) -> Result<(), String> {
    let seed = std::fs::read_to_string(&call.key).map_err(at(&call.key))?;
    let key = SigningKey::from_bytes(&key_bytes(&seed)?);
    let arguments = hex::decode(call.args.trim()).map_err(|error| error.to_string())?;
    let agent = AgentId(call.agent);
    let instance = InstanceId(call.instance);
    let target = call.node.target()?;
    let mut kept = Kept::load(&call.key)?;
    let mut client = Client::resume(
        &target,
        key,
        mem::take(&mut kept.sessions),
        mem::take(&mut kept.identities),
    );
    for (agent, at) in mem::take(&mut kept.floors) {
        client.raise_floor(agent, at);
    }
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
    kept.sessions = client.sessions();
    kept.identities = client.identities();
    kept.floors = client.floors();
    kept.save(&call.key)?;
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

/// What an answer says: a call that ran, done or failed, as printed; any
/// other answer as an error.
pub fn said(answer: &Answer) -> Result<String, String> {
    match answer {
        Answer::Ran {
            outcome: Outcome::Done(reply),
            ..
        } => Ok(format!("done {}", hex::encode(reply))),
        Answer::Ran {
            outcome: Outcome::Failed { code, detail },
            ..
        } => Ok(format!("failed {code} {}", hex::encode(detail))),
        Answer::Refused(refusal::SESSIONS_FULL) => {
            Err("refused: the agent holds as many sessions as it may; try again later".into())
        }
        Answer::Refused(refusal::KEY_SESSIONS_FULL) => {
            Err("refused: this key holds as many sessions at the agent as it may".into())
        }
        Answer::Refused(code) => Err(format!("refused {code}")),
        other => Err(format!("{other:?}")),
    }
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
