//! The space a node runs in: its nodes, each with its number, its key, the
//! address its peers reach it at, and the address its clients do.
//!
//! A space file holds one node per line, as four fields: the number, the
//! key in hex, the peer address, and the ingress address. A `#` starts a
//! comment.
//!
//! ```text
//! # number  key                                                               peer            ingress
//! 1         7f3a...e2                                                          10.0.0.1:7800   https://10.0.0.1:7700
//! ```
//!
//! Beside it, `<space file>.genesis` holds the space's genesis
//! ([`SpaceGenesis`]): its founding nodes, the clock that numbers its
//! windows, its founder's time and a nonce, whose hash is the space's id.
//! It is written once, when the space is founded (`vos space up`), and
//! never changes: a space with another genesis is another space. The file
//! is the genesis's canonical encoding in hex; a `#` starts a comment.
//! Without it, a space has no id ([`SpaceId::NONE`]): its agents belong to
//! no space, and anchor nothing.
//!
//! An agent records its space at its first install, for good: an agent of
//! a space with no genesis belongs to no space forever. So a space is
//! founded before its first agent: `vos space up` on one node's space file,
//! before any agent is created, then `<space file>.genesis` copied beside
//! every node's space file, and the nodes restarted. A node refuses an
//! agent's record that names another space than its own.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use vos_wire::peer::NodeNumber;
use vos_wire::{SpaceGenesis, SpaceId, WindowClock};

/// One node of a space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceNode {
    pub number: NodeNumber,
    pub key: [u8; 32],
    /// Where its peers reach it.
    pub peer: SocketAddr,
    /// Where its clients reach it: an `http://` or `https://` address.
    pub ingress: String,
}

/// The nodes of a space, and its genesis once it has one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Space {
    nodes: Vec<SpaceNode>,
    genesis: Option<SpaceGenesis>,
    /// Its genesis's hash, or [`SpaceId::NONE`].
    id: SpaceId,
}

/// The genesis file beside the space file at `space`: its name with
/// `.genesis` after it.
pub(crate) fn genesis_path(space: &Path) -> PathBuf {
    let mut name = space.as_os_str().to_owned();
    name.push(".genesis");
    PathBuf::from(name)
}

/// A genesis file's text: comments and white space dropped, the rest the
/// genesis's encoding in hex.
fn parse_genesis(text: &str) -> Result<SpaceGenesis, String> {
    let digits: String = text
        .lines()
        .map(|line| line.split('#').next().unwrap_or_default())
        .flat_map(str::split_whitespace)
        .collect();
    let bytes = hex::decode(&digits).map_err(|_| "a genesis in hex".to_string())?;
    SpaceGenesis::decode(&bytes).map_err(|error| format!("the genesis: {error}"))
}

/// The genesis beside the space file at `space`; none when there is no
/// such file.
pub(crate) fn read_genesis(space: &Path) -> Result<Option<SpaceGenesis>, String> {
    let path = genesis_path(space);
    match std::fs::read_to_string(&path) {
        Ok(text) => parse_genesis(&text)
            .map(Some)
            .map_err(|error| format!("{}: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Write `genesis` beside the space file at `space`, once: an existing
/// genesis is never replaced. Answers the file's path.
pub fn write_genesis(space: &Path, genesis: &SpaceGenesis) -> Result<PathBuf, String> {
    use std::io::Write;
    let path = genesis_path(space);
    let text = hex::encode(genesis.encode());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => format!(
                "{}: the space has a genesis already, and it never changes",
                path.display()
            ),
            _ => format!("{}: {error}", path.display()),
        })?;
    file.write_all(format!("{text}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

impl Space {
    /// A space of `nodes`, each number and key once, with no genesis.
    pub fn new(nodes: Vec<SpaceNode>) -> Result<Self, String> {
        for (at, node) in nodes.iter().enumerate() {
            for other in &nodes[..at] {
                if other.number == node.number {
                    return Err(format!("node {} is listed twice", node.number));
                }
                if other.key == node.key {
                    return Err(format!(
                        "nodes {} and {} have one key",
                        other.number, node.number
                    ));
                }
            }
        }
        Ok(Self {
            nodes,
            genesis: None,
            id: SpaceId::NONE,
        })
    }

    /// The space with its genesis: each founding node that the space still
    /// lists holds the key it was founded with. A space that lists none of
    /// its founders, every one of them replaced, is the same space.
    pub fn with_genesis(mut self, genesis: SpaceGenesis) -> Result<Self, String> {
        for (number, key) in &genesis.nodes {
            if let Some(node) = self.node(*number)
                && node.key != *key
            {
                return Err(format!(
                    "node {number} is listed with another key than the one the space was founded with"
                ));
            }
        }
        self.id = vos_wire::vos_anchor::space_id(&genesis);
        self.genesis = Some(genesis);
        Ok(self)
    }

    /// Its genesis, once founded.
    pub fn genesis(&self) -> Option<&SpaceGenesis> {
        self.genesis.as_ref()
    }

    /// The space's id, its genesis's hash; [`SpaceId::NONE`] without one.
    pub fn id(&self) -> SpaceId {
        self.id
    }

    /// The clock that numbers the space's windows, its genesis's; the
    /// default clock without one.
    pub fn clock(&self) -> WindowClock {
        self.genesis
            .as_ref()
            .map_or(WindowClock::DEFAULT, |genesis| genesis.clock)
    }

    /// A genesis founding this space: its nodes as listed, `clock`, the
    /// founder's `time` and `nonce`. A venue must be able to register it:
    /// the clock's length one it registers, and 1 to
    /// [`vos_wire::vos_anchor::MAX_FOUNDING_KEYS`] nodes.
    pub fn found(
        &self,
        clock: WindowClock,
        time: u64,
        nonce: [u8; 16],
    ) -> Result<SpaceGenesis, String> {
        if !clock.registrable() {
            return Err(format!(
                "windows of {} ms: a venue registers {} to {} ms",
                clock.length_ms,
                vos_wire::vos_anchor::MIN_LENGTH_MS,
                vos_wire::vos_anchor::MAX_LENGTH_MS
            ));
        }
        let founders = self.nodes.len();
        if !(1..=vos_wire::vos_anchor::MAX_FOUNDING_KEYS).contains(&founders) {
            return Err(format!(
                "{founders} nodes: a venue registers a space of 1 to {} founding nodes",
                vos_wire::vos_anchor::MAX_FOUNDING_KEYS
            ));
        }
        let mut nodes: Vec<(NodeNumber, [u8; 32])> = self
            .nodes
            .iter()
            .map(|node| (node.number, node.key))
            .collect();
        nodes.sort_unstable();
        Ok(SpaceGenesis {
            version: vos_wire::vos_anchor::GENESIS_VERSION,
            nodes,
            clock,
            time,
            nonce,
        })
    }

    pub fn parse(text: &str) -> Result<Self, String> {
        let mut nodes = Vec::new();
        for (line, content) in text.lines().enumerate() {
            let content = content.split('#').next().unwrap_or_default().trim();
            if content.is_empty() {
                continue;
            }
            let at = |why: &str| format!("line {}: {why}", line + 1);
            let fields: Vec<&str> = content.split_whitespace().collect();
            let [number, key, peer, ingress] = fields[..] else {
                return Err(at(
                    "four fields: number, key, peer address, ingress address",
                ));
            };
            nodes.push(SpaceNode {
                number: number.parse().map_err(|_| at("a node number, 0 to 255"))?,
                key: crate::hex32(key).ok_or_else(|| at("a key: 64 hex digits"))?,
                peer: peer
                    .parse()
                    .map_err(|_| at("a peer address: host and port"))?,
                ingress: ingress.to_string(),
            });
        }
        Self::new(nodes)
    }

    /// The space file at `path`, with the genesis beside it if there is
    /// one.
    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        let space = Self::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        match read_genesis(path)? {
            Some(genesis) => space
                .with_genesis(genesis)
                .map_err(|error| format!("{}: {error}", genesis_path(path).display())),
            None => Ok(space),
        }
    }

    pub fn nodes(&self) -> &[SpaceNode] {
        &self.nodes
    }

    pub fn node(&self, number: NodeNumber) -> Option<&SpaceNode> {
        self.nodes.iter().find(|node| node.number == number)
    }

    /// The node holding `key`.
    pub fn by_key(&self, key: &[u8; 32]) -> Option<&SpaceNode> {
        self.nodes.iter().find(|node| node.key == *key)
    }

    pub fn numbers(&self) -> Vec<NodeNumber> {
        self.nodes.iter().map(|node| node.number).collect()
    }

    /// The network's view of the nodes.
    pub fn peers(&self) -> Vec<vos_net::Peer> {
        self.nodes
            .iter()
            .map(|node| vos_net::Peer {
                number: node.number,
                key: node.key,
                address: node.peer,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_space_file_lists_its_nodes() {
        let key = |byte: u8| format!("{byte:02x}").repeat(32);
        let text = format!(
            "# the space\n\
             1 {} 10.0.0.1:7800 https://10.0.0.1:7700\n\
             \n\
             2 {} 10.0.0.2:7800 https://10.0.0.2:7700 # the second\n",
            key(1),
            key(2)
        );
        let space = Space::parse(&text).unwrap();
        assert_eq!(space.numbers(), [1, 2]);
        assert_eq!(
            space.by_key(&[2; 32]).unwrap().ingress,
            "https://10.0.0.2:7700"
        );
        assert_eq!(space.peers()[0].address, "10.0.0.1:7800".parse().unwrap());
        for bad in [
            format!("1 {} 10.0.0.1:7800", key(1)),
            format!("300 {} 10.0.0.1:7800 x", key(1)),
            "1 abcd 10.0.0.1:7800 x".to_string(),
            format!("1 {} nowhere x", key(1)),
            format!("1 {} 1.1.1.1:1 x\n1 {} 1.1.1.2:1 x", key(1), key(2)),
            format!("1 {} 1.1.1.1:1 x\n2 {} 1.1.1.2:1 x", key(1), key(1)),
        ] {
            assert!(Space::parse(&bad).is_err(), "{bad}");
        }
    }

    /// The genesis beside the space file: none at first, so no id; written
    /// once, never replaced; read back with the space, its id its hash.
    #[test]
    fn a_space_keeps_its_genesis_beside_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("space");
        let key = |byte: u8| format!("{byte:02x}").repeat(32);
        std::fs::write(
            &path,
            format!(
                "2 {} 10.0.0.2:7800 x\n1 {} 10.0.0.1:7800 x\n",
                key(2),
                key(1)
            ),
        )
        .unwrap();
        let space = Space::read(&path).unwrap();
        assert_eq!(space.genesis(), None);
        assert_eq!(space.id(), SpaceId::NONE);
        assert_eq!(space.clock(), WindowClock::DEFAULT);

        let clock = WindowClock {
            origin_ms: 1_000,
            length_ms: 600_000,
        };
        let genesis = space.found(clock, 1_000, [9; 16]).unwrap();
        assert_eq!(genesis.nodes, [(1, [1; 32]), (2, [2; 32])], "by number");
        let written = write_genesis(&path, &genesis).unwrap();
        assert_eq!(written, dir.path().join("space.genesis"));
        let again = space.found(clock, 2_000, [9; 16]).unwrap();
        let refused = write_genesis(&path, &again).unwrap_err();
        assert!(refused.contains("never changes"), "{refused}");

        let space = Space::read(&path).unwrap();
        assert_eq!(space.genesis(), Some(&genesis));
        assert_eq!(space.id(), vos_wire::vos_anchor::space_id(&genesis));
        assert_ne!(space.id(), vos_wire::vos_anchor::space_id(&again));
        assert_eq!(space.clock(), clock);

        let short = WindowClock {
            origin_ms: 0,
            length_ms: 60_000,
        };
        assert!(space.found(short, 1_000, [9; 16]).is_err());

        // A venue registers 1 to 16 founders.
        let nodes = |count: u8| {
            (1..=count)
                .map(|number| SpaceNode {
                    number,
                    key: [number; 32],
                    peer: "10.0.0.1:7800".parse().unwrap(),
                    ingress: "x".into(),
                })
                .collect()
        };
        for (count, founded) in [(0, false), (1, true), (16, true), (17, false)] {
            let space = Space::new(nodes(count)).unwrap();
            assert_eq!(space.found(clock, 0, [0; 16]).is_ok(), founded, "{count}");
        }
    }

    /// A genesis file that is not one genesis in hex, or whose founding
    /// node the space lists under another key, is refused.
    #[test]
    fn a_wrong_genesis_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("space");
        std::fs::write(&path, format!("1 {} 10.0.0.1:7800 x\n", "01".repeat(32))).unwrap();
        let space = Space::read(&path).unwrap();
        let genesis = space.found(WindowClock::DEFAULT, 0, [0; 16]).unwrap();
        let hex = hex::encode(genesis.encode());
        for bad in [
            "zz".to_string(),
            hex[..hex.len() - 2].to_string(),
            format!("{hex}00"),
        ] {
            std::fs::write(genesis_path(&path), &bad).unwrap();
            assert!(Space::read(&path).is_err(), "{bad}");
        }
        std::fs::write(genesis_path(&path), format!("# the genesis\n{hex}\n")).unwrap();
        assert_eq!(
            Space::read(&path).unwrap().id(),
            vos_wire::vos_anchor::space_id(&genesis)
        );

        let mut other = genesis.clone();
        other.nodes[0].1 = [7; 32];
        let refused = space.with_genesis(other).unwrap_err();
        assert!(refused.contains("another key"), "{refused}");
    }
}
