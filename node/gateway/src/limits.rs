//! Limits per source address, before any authentication or decoding:
//! connections at once, and requests a second with a burst.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// What one address may take.
#[derive(Clone, Copy, Debug)]
pub struct PerAddress {
    pub connections: usize,
    /// Requests a second, on average.
    pub rate: u32,
    /// Requests at once past the average.
    pub burst: u32,
}

impl Default for PerAddress {
    fn default() -> Self {
        Self {
            connections: 64,
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

/// Each address's connections and requests.
pub struct Limits {
    per: PerAddress,
    open: Mutex<HashMap<IpAddr, usize>>,
    buckets: Mutex<Buckets>,
}

struct Buckets {
    by: HashMap<IpAddr, Bucket>,
    swept: Instant,
}

/// A connection's place among its address's, given back when it ends.
pub struct Place {
    limits: Arc<Limits>,
    address: IpAddr,
}

impl Drop for Place {
    fn drop(&mut self) {
        let mut open = self.limits.open.lock().expect("the open connections");
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
            buckets: Mutex::new(Buckets {
                by: HashMap::new(),
                swept: Instant::now(),
            }),
        })
    }

    /// A place for a connection from `address`, if it holds fewer than its
    /// limit.
    pub fn connect(self: &Arc<Self>, address: IpAddr) -> Option<Place> {
        let address = counted(address);
        let mut open = self.open.lock().expect("the open connections");
        let count = open.entry(address).or_insert(0);
        if *count >= self.per.connections {
            return None;
        }
        *count += 1;
        Some(Place {
            limits: Arc::clone(self),
            address,
        })
    }

    /// Whether `address` may make a request now: a token taken from its
    /// bucket.
    pub fn request(&self, address: IpAddr) -> bool {
        let address = counted(address);
        let now = Instant::now();
        let (rate, burst) = (f64::from(self.per.rate), f64::from(self.per.burst.max(1)));
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
        let bucket = buckets.by.entry(address).or_insert(Bucket {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_gets_its_connections_and_its_burst() {
        let limits = Limits::new(PerAddress {
            connections: 2,
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
