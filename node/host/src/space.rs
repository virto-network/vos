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

use std::net::SocketAddr;
use std::path::Path;

use vos_wire::peer::NodeNumber;

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

/// The nodes of a space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Space {
    nodes: Vec<SpaceNode>,
}

impl Space {
    /// A space of `nodes`, each number and key once.
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
        Ok(Self { nodes })
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
                key: hex_key(key).ok_or_else(|| at("a key: 64 hex digits"))?,
                peer: peer
                    .parse()
                    .map_err(|_| at("a peer address: host and port"))?,
                ingress: ingress.to_string(),
            });
        }
        Self::new(nodes)
    }

    pub fn read(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Self::parse(&text).map_err(|error| format!("{}: {error}", path.display()))
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

fn hex_key(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (at, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * at..2 * at + 2)?, 16).ok()?;
    }
    Some(key)
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
}
