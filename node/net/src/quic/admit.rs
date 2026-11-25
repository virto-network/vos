//! Which handshakes the endpoint takes: places per address, more for an
//! address configured peers have, and a total for every other address.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use super::Handshakes;
use crate::Peer;

/// The places handshakes take.
pub(super) struct Admission {
    handshakes: Handshakes,
    /// The configured peers at each address.
    listed: RwLock<HashMap<IpAddr, usize>>,
    places: Mutex<Places>,
}

#[derive(Default)]
struct Places {
    by_address: HashMap<IpAddr, usize>,
    /// Those taken from addresses no configured peer has.
    unlisted: usize,
}

impl Admission {
    pub(super) fn new(handshakes: Handshakes) -> Self {
        Self {
            handshakes,
            listed: RwLock::default(),
            places: Mutex::default(),
        }
    }

    /// How long a handshake may take.
    pub(super) fn deadline(&self) -> Duration {
        self.handshakes.deadline
    }

    pub(super) fn set_peers(&self, peers: &[Peer]) {
        let mut listed = HashMap::new();
        for peer in peers {
            *listed.entry(address(peer.address.ip())).or_insert(0) += 1;
        }
        *self.listed.write().expect("the listed addresses") = listed;
    }

    /// A place for a handshake from `from`, if its address has one left.
    pub(super) fn take(self: &Arc<Self>, from: IpAddr) -> Option<Place> {
        let address = address(from);
        let peers = self
            .listed
            .read()
            .expect("the listed addresses")
            .get(&address)
            .copied()
            .unwrap_or(0);
        let share = self.handshakes.per_address.saturating_mul(peers.max(1));
        let mut places = self.places.lock().expect("the handshakes' places");
        let listed = peers > 0;
        if places.by_address.get(&address).copied().unwrap_or(0) >= share
            || (!listed && places.unlisted >= self.handshakes.total)
        {
            return None;
        }
        *places.by_address.entry(address).or_insert(0) += 1;
        if !listed {
            places.unlisted += 1;
        }
        Some(Place {
            admission: Arc::clone(self),
            address,
            listed,
        })
    }
}

/// A handshake's place, given back when dropped.
pub(super) struct Place {
    admission: Arc<Admission>,
    address: IpAddr,
    listed: bool,
}

impl Place {
    /// Keep the place of a handshake that failed for a while, then give it
    /// back.
    pub(super) async fn keep(self) {
        smol::Timer::after(self.admission.handshakes.failed).await;
    }
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut places = self
            .admission
            .places
            .lock()
            .expect("the handshakes' places");
        if let Some(count) = places.by_address.get_mut(&self.address) {
            *count -= 1;
            if *count == 0 {
                places.by_address.remove(&self.address);
            }
        }
        if !self.listed {
            places.unlisted -= 1;
        }
    }
}

/// The address places are counted by: an IPv4 address (an IPv4-mapped one
/// too), or an IPv6 address's /64, which one host is commonly given.
fn address(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        },
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_at(address: &str) -> Peer {
        Peer {
            number: 1,
            key: [0; 32],
            address: address.parse().unwrap(),
        }
    }

    #[test]
    fn places_are_per_address_and_in_all_for_strangers() {
        let admission = Arc::new(Admission::new(Handshakes {
            total: 3,
            per_address: 2,
            deadline: Duration::from_secs(1),
            failed: Duration::from_secs(1),
        }));
        admission.set_peers(&[peer_at("10.0.0.1:1"), peer_at("10.0.0.1:2")]);
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        // Two places an address, three in all for strangers.
        let a = [
            admission.take(ip("10.1.0.1")),
            admission.take(ip("10.1.0.1")),
        ];
        assert!(a.iter().all(Option::is_some));
        assert!(admission.take(ip("10.1.0.1")).is_none());
        // One /64 is one address; an IPv4-mapped address is its IPv4 one.
        let b = admission.take(ip("2001:db8::1")).unwrap();
        assert!(admission.take(ip("2001:db8::2")).is_none());
        assert!(admission.take(ip("::ffff:10.1.0.1")).is_none());
        drop(b);
        // A peers' address has its own, two for each peer there.
        let listed: Vec<_> = (0..4).map(|_| admission.take(ip("10.0.0.1"))).collect();
        assert!(listed.iter().all(Option::is_some));
        assert!(admission.take(ip("10.0.0.1")).is_none());
        // A place given back is taken again.
        drop(a);
        assert!(admission.take(ip("10.1.0.1")).is_some());
        drop(listed);
        assert!(admission.places.lock().unwrap().by_address.is_empty());
        assert_eq!(admission.places.lock().unwrap().unlisted, 0);
    }
}
