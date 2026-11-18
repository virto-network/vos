//! Limits per source address, before any authentication or decoding:
//! connections at once, and requests a second with a burst. An onion
//! service's clients have no address: each rendezvous circuit counts as
//! one ([`crate::circuits`]).

use std::collections::HashMap;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// What one address may take.
#[derive(Clone, Copy, Debug)]
pub struct PerAddress {
    pub connections: usize,
    /// Requests in flight at once, from every connection.
    pub in_flight: usize,
    /// Requests a second, on average.
    pub rate: u32,
    /// Requests at once past the average.
    pub burst: u32,
}

impl Default for PerAddress {
    fn default() -> Self {
        Self {
            connections: 64,
            in_flight: 64,
            rate: 200,
            burst: 400,
        }
    }
}

/// A token bucket: `tokens` left at `at`.
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Buckets kept: past them the full ones are let go (a full bucket is a
/// fresh one), then the longest idle.
const BUCKETS: usize = 1 << 14;
/// The shortest time between two sweeps of the buckets.
const SWEEP: std::time::Duration = std::time::Duration::from_secs(1);

/// The address a limit counts: an IPv6 address's /64, which one
/// subscriber holds whole, else the address.
pub fn counted(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6((u128::from(v6) & !((1u128 << 64) - 1)).into()),
        },
        v4 => v4,
    }
}

/// A token bucket for each key: `rate` a second on average, `burst` at
/// once.
pub struct Rate<K> {
    rate: f64,
    burst: f64,
    buckets: Mutex<Buckets<K>>,
}

struct Buckets<K> {
    by: HashMap<K, Bucket>,
    swept: Instant,
}

impl<K: Hash + Eq> Rate<K> {
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            rate: f64::from(rate),
            burst: f64::from(burst.max(1)),
            buckets: Mutex::new(Buckets {
                by: HashMap::new(),
                swept: Instant::now(),
            }),
        }
    }

    /// Whether `key` may act now: a token taken from its bucket.
    pub fn take(&self, key: K) -> bool {
        let now = Instant::now();
        let (rate, burst) = (self.rate, self.burst);
        let mut buckets = self.buckets.lock().expect("the buckets");
        if buckets.by.len() >= BUCKETS && now.duration_since(buckets.swept) >= SWEEP {
            buckets.swept = now;
            buckets.by.retain(|_, bucket| {
                bucket.tokens + now.duration_since(bucket.at).as_secs_f64() * rate < burst
            });
            if buckets.by.len() >= BUCKETS {
                // Still full: the longest idle half goes.
                let mut idle: Vec<Instant> = buckets.by.values().map(|bucket| bucket.at).collect();
                idle.sort_unstable();
                let cut = idle[idle.len() / 2];
                buckets.by.retain(|_, bucket| bucket.at > cut);
            }
        }
        let bucket = buckets.by.entry(key).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        bucket.tokens =
            (bucket.tokens + now.duration_since(bucket.at).as_secs_f64() * rate).min(burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Each address's connections, requests in flight and requests.
pub struct Limits {
    per: PerAddress,
    open: Mutex<HashMap<IpAddr, usize>>,
    flying: Mutex<HashMap<IpAddr, usize>>,
    requests: Rate<IpAddr>,
}

/// A connection's or a request's place among its address's, given back
/// when it ends.
pub struct Place {
    limits: Arc<Limits>,
    address: IpAddr,
    request: bool,
}

impl Drop for Place {
    fn drop(&mut self) {
        let counts = match self.request {
            true => &self.limits.flying,
            false => &self.limits.open,
        };
        let mut open = counts.lock().expect("the counts");
        if let Some(count) = open.get_mut(&self.address) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.address);
            }
        }
    }
}

impl Limits {
    pub fn new(per: PerAddress) -> Arc<Self> {
        Arc::new(Self {
            per,
            open: Mutex::new(HashMap::new()),
            flying: Mutex::new(HashMap::new()),
            requests: Rate::new(per.rate, per.burst),
        })
    }

    /// A place for a connection from `address`, if it holds fewer than its
    /// limit.
    pub fn connect(self: &Arc<Self>, address: IpAddr) -> Option<Place> {
        self.place(address, false)
    }

    /// A place for a request in flight from `address`, if it has fewer in
    /// flight than its limit.
    pub fn in_flight(self: &Arc<Self>, address: IpAddr) -> Option<Place> {
        self.place(address, true)
    }

    fn place(self: &Arc<Self>, address: IpAddr, request: bool) -> Option<Place> {
        let address = counted(address);
        let (counts, most) = match request {
            true => (&self.flying, self.per.in_flight),
            false => (&self.open, self.per.connections),
        };
        let mut open = counts.lock().expect("the counts");
        let count = open.entry(address).or_insert(0);
        if *count >= most {
            return None;
        }
        *count += 1;
        Some(Place {
            limits: Arc::clone(self),
            address,
            request,
        })
    }

    /// Whether `address` may make a request now: a token taken from its
    /// bucket.
    pub fn request(&self, address: IpAddr) -> bool {
        self.requests.take(counted(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_gets_its_connections_and_its_burst() {
        let limits = Limits::new(PerAddress {
            connections: 2,
            in_flight: 1,
            rate: 1,
            burst: 3,
        });
        let address: IpAddr = "10.0.0.1".parse().unwrap();
        let other: IpAddr = "10.0.0.2".parse().unwrap();
        let first = limits.connect(address).unwrap();
        let _second = limits.connect(address).unwrap();
        assert!(limits.connect(address).is_none());
        assert!(limits.connect(other).is_some());
        drop(first);
        assert!(limits.connect(address).is_some());
        // Requests in flight are counted apart from connections.
        let flying = limits.in_flight(address).unwrap();
        assert!(limits.in_flight(address).is_none());
        drop(flying);
        assert!(limits.in_flight(address).is_some());
        assert!((0..3).all(|_| limits.request(address)));
        assert!(!limits.request(address), "past the burst");
        assert!(limits.request(other), "another address's own");
        // One subscriber's /64 is one address.
        let first: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let second: IpAddr = "2001:db8:1:2:ffff::9".parse().unwrap();
        assert!((0..3).all(|_| limits.request(first)));
        assert!(!limits.request(second));
        assert_eq!(counted("::ffff:10.0.0.1".parse().unwrap()), address);
    }
}
