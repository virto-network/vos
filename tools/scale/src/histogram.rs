//! Histograms over the node's buckets (`vos_wire::ingress::bucket`):
//! exact below 8, then four to each power of two, so a quantile read from
//! them is within 25% of the value.

use vos_wire::ingress::{BUCKETS, bucket};

/// The least value bucket `index` holds.
pub fn floor(index: usize) -> u64 {
    if index < 8 {
        return index as u64;
    }
    let exponent = (index - 8) / 4 + 3;
    let sub = ((index - 8) % 4) as u64;
    (4 + sub) << (exponent - 2)
}

#[derive(Clone, Debug)]
pub struct Histogram {
    pub counts: Vec<u64>,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: vec![0; BUCKETS],
        }
    }
}

impl Histogram {
    pub fn record(&mut self, value: u64) {
        self.counts[bucket(value)] += 1;
    }

    pub fn add(&mut self, other: &Histogram) {
        for (count, more) in self.counts.iter_mut().zip(&other.counts) {
            *count += more;
        }
    }

    pub fn count(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// The `q` quantile's bucket floor; 0 when empty.
    pub fn quantile(&self, q: f64) -> u64 {
        quantile(&self.counts, q)
    }
}

/// The `q` quantile of `counts`, as its bucket's floor.
pub fn quantile(counts: &[u64], q: f64) -> u64 {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return 0;
    }
    let rank = ((total as f64) * q).ceil().max(1.0) as u64;
    let mut seen = 0;
    for (index, count) in counts.iter().enumerate() {
        seen += count;
        if seen >= rank {
            return floor(index);
        }
    }
    floor(counts.len() - 1)
}

#[cfg(test)]
mod tests {
    use super::{Histogram, floor};
    use vos_wire::ingress::{BUCKETS, bucket};

    #[test]
    fn a_buckets_floor_is_its_least_value() {
        for index in 0..BUCKETS - 1 {
            assert_eq!(bucket(floor(index)), index, "{index}");
            assert_eq!(bucket(floor(index + 1) - 1), index, "{index}");
        }
    }

    #[test]
    fn quantiles_read_within_a_bucket() {
        let mut histogram = Histogram::default();
        for value in 1..=1_000u64 {
            histogram.record(value * 100);
        }
        let p50 = histogram.quantile(0.5) as f64;
        let p99 = histogram.quantile(0.99) as f64;
        assert!((40_000.0..=50_000.0).contains(&p50), "{p50}");
        assert!((79_000.0..=99_000.0).contains(&p99), "{p99}");
        assert_eq!(Histogram::default().quantile(0.99), 0);
    }
}
