//! Histograms over the node's buckets (`vos_wire::ingress::bucket`):
//! exact below 8, then four to each power of two, so a quantile read from
//! them is within 25% of the value. A driver's histogram also keeps finer
//! counts of its own ([`SUB`] to each power of two, exact below), read
//! within 1% of the value: its quantiles compare runs a node bucket apart.

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

/// A fine bucket's sub-buckets to each power of two, and the values held
/// exactly: a fine bucket is under 1/128 of its least value wide.
pub const SUB: u64 = 128;
const SUB_BITS: u32 = SUB.trailing_zeros();

/// The fine bucket `value` falls in.
pub fn fine_bucket(value: u64) -> usize {
    if value < SUB {
        return value as usize;
    }
    let exponent = 63 - value.leading_zeros();
    let sub = (value >> (exponent - SUB_BITS)) - SUB;
    (SUB + u64::from(exponent - SUB_BITS) * SUB + sub) as usize
}

/// The least value fine bucket `index` holds.
pub fn fine_floor(index: usize) -> u64 {
    let index = index as u64;
    if index < SUB {
        return index;
    }
    let shift = (index - SUB) / SUB;
    (SUB + (index - SUB) % SUB) << shift
}

#[derive(Clone, Debug)]
pub struct Histogram {
    pub counts: Vec<u64>,
    /// By [`fine_bucket`], as long as the largest value recorded needs.
    pub fine: Vec<u64>,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: vec![0; BUCKETS],
            fine: Vec::new(),
        }
    }
}

impl Histogram {
    pub fn record(&mut self, value: u64) {
        self.counts[bucket(value)] += 1;
        let index = fine_bucket(value);
        if self.fine.len() <= index {
            self.fine.resize(index + 1, 0);
        }
        self.fine[index] += 1;
    }

    pub fn add(&mut self, other: &Histogram) {
        for (count, more) in self.counts.iter_mut().zip(&other.counts) {
            *count += more;
        }
        if self.fine.len() < other.fine.len() {
            self.fine.resize(other.fine.len(), 0);
        }
        for (count, more) in self.fine.iter_mut().zip(&other.fine) {
            *count += more;
        }
    }

    /// The `q` quantile's bucket floor; 0 when empty.
    pub fn quantile(&self, q: f64) -> u64 {
        quantile(&self.counts, q)
    }

    /// The `q` quantile's fine bucket floor, within 1% below the value;
    /// 0 when empty.
    pub fn fine_quantile(&self, q: f64) -> u64 {
        rank(&self.fine, q).map_or(0, fine_floor)
    }

    /// The fine counts as `[least value, count]` pairs, the empty left
    /// out: what a record keeps for its quantiles to be read again over
    /// any span of its intervals.
    pub fn fine_counts(&self) -> Vec<[u64; 2]> {
        self.fine
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .map(|(index, count)| [fine_floor(index), *count])
            .collect()
    }

    /// The fine quantiles and counts, a record's `fine` field.
    pub fn fine_json(&self) -> serde_json::Value {
        serde_json::json!({
            "p50_us": self.fine_quantile(0.5),
            "p99_us": self.fine_quantile(0.99),
            "p999_us": self.fine_quantile(0.999),
            "counts": self.fine_counts(),
        })
    }
}

/// The index of the bucket that holds the `q` quantile of `counts`.
fn rank(counts: &[u64], q: f64) -> Option<usize> {
    let total: u64 = counts.iter().sum();
    if total == 0 {
        return None;
    }
    let rank = ((total as f64) * q).ceil().max(1.0) as u64;
    let mut seen = 0;
    for (index, count) in counts.iter().enumerate() {
        seen += count;
        if seen >= rank {
            return Some(index);
        }
    }
    Some(counts.len() - 1)
}

/// The `q` quantile of `counts`, as its bucket's floor.
pub fn quantile(counts: &[u64], q: f64) -> u64 {
    rank(counts, q).map_or(0, floor)
}

#[cfg(test)]
mod tests {
    use super::{Histogram, fine_bucket, fine_floor, floor};
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

    #[test]
    fn a_fine_buckets_floor_is_its_least_value_and_within_1_percent() {
        for index in 0..fine_bucket(u64::MAX) {
            let least = fine_floor(index);
            let next = fine_floor(index + 1);
            assert_eq!(fine_bucket(least), index, "{index}");
            assert_eq!(fine_bucket(next - 1), index, "{index}");
            assert!(
                (next - least) as f64 <= (least as f64 / 128.0).max(1.0),
                "{index}"
            );
        }
        assert_eq!(
            fine_floor(fine_bucket(u64::MAX)),
            u64::MAX - (u64::MAX >> 8)
        );
    }

    /// Values in one node bucket read apart at the fine buckets, and
    /// adding two histograms adds their fine counts.
    #[test]
    fn fine_quantiles_read_within_1_percent() {
        let mut low = Histogram::default();
        let mut high = Histogram::default();
        for value in 1..=1_000u64 {
            low.record(value * 1_860);
            high.record(value * 2_100);
        }
        assert_eq!(low.quantile(0.99), high.quantile(0.99));
        let (low99, high99) = (
            low.fine_quantile(0.99) as f64,
            high.fine_quantile(0.99) as f64,
        );
        assert!(
            (0.99 * 1_841_400.0..=1_841_400.0).contains(&low99),
            "{low99}"
        );
        assert!(
            (0.99 * 2_079_000.0..=2_079_000.0).contains(&high99),
            "{high99}"
        );
        let mut both = low.clone();
        both.add(&high);
        let counted: u64 = both.fine_counts().iter().map(|[_, count]| count).sum();
        assert_eq!(counted, 2_000);
        assert_eq!(Histogram::default().fine_quantile(0.5), 0);
        assert!(Histogram::default().fine_counts().is_empty());
    }
}
