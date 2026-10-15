//! What nodes send each other: every message survives the wire whole, and
//! each arrival passes the checks before it reaches a group, here a real
//! consensus core.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod checks;
mod consensus;
mod placements;
mod wire;

use proptest::prelude::*;
use vos_net::Class;
use vos_node::peer::{self, Drops, Refusal, decode, from_wire, to_wire};
use vos_raft::core::{Action, Core, Recovered, Write};
use vos_raft::{AppendResult, Config, LogEntry, Message, Role};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MethodId, ProgramHash, Session};
use vos_wire::ingress::{Call, Response};
use vos_wire::peer::{
    Configuration, CreationRecord, Leading, Manifest, NodeNumber, PeerMessage, Placement, Raft,
    SnapshotAck, SnapshotChunk,
};
use vos_wire::result::Outcome;

const AGENT: AgentId = AgentId(7);

fn chunk(term: u64) -> SnapshotChunk {
    SnapshotChunk {
        agent: AGENT,
        term,
        index: 40,
        snapshot_term: 3,
        sequence: 0,
        manifest: Some(Manifest {
            configuration: Some(Configuration {
                members: vec![1, 2, 3],
                joint_old: Some(vec![1, 2]),
                index: 12,
            }),
            last_result: Some((1_000, [7; 32])),
        }),
        rows: vec![(b"key".to_vec(), b"value".to_vec())],
        last: false,
    }
}

fn forward() -> PeerMessage {
    PeerMessage::Forward {
        agent: AGENT,
        token: 77,
        term: 6,
        call: Call {
            session: Session {
                key: [1; 32],
                name: [2; 16],
                t0: 3,
            },
            sequence: 4,
            instance: InstanceId(5),
            method: MethodId(6),
            arguments: vec![7],
            signature: [8; 64],
        },
    }
}

const SPACE: [NodeNumber; 4] = [1, 2, 3, 4];

fn raft(message: Raft) -> PeerMessage {
    PeerMessage::Raft {
        agent: AGENT,
        message,
    }
}

fn unfollowed(_: AgentId) -> Option<(NodeNumber, u64)> {
    None
}

/// Check `message` as it arrives on its own class and stream.
fn check(
    space: &[NodeNumber],
    from: NodeNumber,
    message: &PeerMessage,
    followed: impl FnOnce(AgentId) -> Option<(NodeNumber, u64)>,
) -> Result<(), Refusal> {
    let way = (peer::class(message), peer::stream(message));
    peer::check(space, from, way, message, followed)
}
