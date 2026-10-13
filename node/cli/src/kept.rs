//! What a client key keeps between commands, in a file next to it.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use vos_node::client;
use vos_wire::ids::AgentId;

use crate::{at, key_bytes};

/// A key's sessions, kept next to the key file so calls go on in them.
/// The file holds a line per item, its fields split by spaces, agent ids
/// in decimal and bytes in hex:
///
/// - `session <agent> <name> <t0> <next>`: the agent's session, its
///   creation time and the next sequence to send;
/// - `identity <agent> <identity>`: the agent's identity, once fetched;
/// - `at <agent> <index>`: the agent's floor, so queries read the key's own
///   writes across commands;
/// - `pending <agent> <digest>`: a call that failed before its answer,
///   until it is answered.
#[derive(Default)]
pub struct Kept {
    pub sessions: HashMap<AgentId, client::Kept>,
    pub identities: HashMap<AgentId, [u8; 32]>,
    pub floors: HashMap<AgentId, u64>,
    /// Each agent's call left unanswered, by its digest.
    pub pending: HashMap<AgentId, [u8; 32]>,
}

impl Kept {
    fn path(key: &Path) -> PathBuf {
        let mut path = key.as_os_str().to_owned();
        path.push(".session");
        PathBuf::from(path)
    }

    /// What the key kept; nothing when there is no file. A file with a
    /// line this command cannot read is refused, not dropped: it may hold
    /// a call whose fate is unknown.
    pub fn load(key: &Path) -> Result<Self, String> {
        let path = Self::path(key);
        let text = match std::fs::read_to_string(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            read => read.map_err(at(&path))?,
        };
        Self::parse(&text).map_err(|line| {
            format!(
                "{}: a line this command cannot read ({line:?}); fix or remove it",
                path.display()
            )
        })
    }

    /// The kept file's contents, or the first line that does not read.
    fn parse(text: &str) -> Result<Self, String> {
        let mut kept = Self::default();
        let agent = |text: &str| text.parse().ok().map(AgentId);
        for line in text.lines() {
            let fields: Vec<&str> = line.split_whitespace().collect();
            let mut read = || -> Option<()> {
                match fields.as_slice() {
                    [] => {}
                    ["session", id, name, t0, next] => {
                        let name = hex::decode(name).ok()?.try_into().ok()?;
                        let session = client::Kept {
                            name,
                            t0: t0.parse().ok()?,
                            next: next.parse().ok()?,
                        };
                        kept.sessions.insert(agent(id)?, session);
                    }
                    ["identity", id, identity] => {
                        kept.identities
                            .insert(agent(id)?, key_bytes(identity).ok()?);
                    }
                    ["at", id, at] => {
                        kept.floors.insert(agent(id)?, at.parse().ok()?);
                    }
                    ["pending", id, digest] => {
                        kept.pending.insert(agent(id)?, key_bytes(digest).ok()?);
                    }
                    _ => return None,
                }
                Some(())
            };
            read().ok_or_else(|| line.to_string())?;
        }
        Ok(kept)
    }

    pub fn save(&self, key: &Path) -> Result<(), String> {
        // Replaced whole: a write cut short must not lose a pending call.
        let path = Self::path(key);
        let mut partial = path.clone().into_os_string();
        partial.push(".partial");
        std::fs::write(&partial, self.to_string())
            .and_then(|()| std::fs::rename(&partial, &path))
            .map_err(at(&path))
    }
}

/// The kept file's contents, as `Kept::parse` reads them.
impl fmt::Display for Kept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (agent, session) in &self.sessions {
            writeln!(
                f,
                "session {} {} {} {}",
                agent.0,
                hex::encode(session.name),
                session.t0,
                session.next
            )?;
        }
        for (agent, identity) in &self.identities {
            writeln!(f, "identity {} {}", agent.0, hex::encode(identity))?;
        }
        for (agent, at) in &self.floors {
            writeln!(f, "at {} {at}", agent.0)?;
        }
        for (agent, digest) in &self.pending {
            writeln!(f, "pending {} {}", agent.0, hex::encode(digest))?;
        }
        Ok(())
    }
}
