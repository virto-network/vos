//! Beginner-facing CRDT field types for `#[actor(crdt)]`.
//!
//! The Merkle-DAG transports and persists causal changes; these payload types
//! supply the convergence rules. Operation identifiers are logical and stable
//! (change id + ordinal), never wall-clock timestamps.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = rkyv)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct ChangeId(pub [u8; 32]);

impl ChangeId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn derive(namespace: &[u8], nonce: &[u8]) -> Self {
        let namespace_len = (namespace.len() as u64).to_le_bytes();
        let nonce_len = (nonce.len() as u64).to_le_bytes();
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/crdt-change/v2",
            &[&namespace_len, namespace, &nonce_len, nonce],
        ))
    }

    pub const fn operation(self, ordinal: u32) -> OpId {
        OpId {
            change: self,
            ordinal,
        }
    }
}

impl From<crate::v2::InvocationId> for ChangeId {
    fn from(value: crate::v2::InvocationId) -> Self {
        Self(value.0)
    }
}

#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[rkyv(crate = rkyv)]
#[rkyv(derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash))]
pub struct OpId {
    pub change: ChangeId,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    DivergentOperation(OpId),
    LogicalClockOverflow,
    IndexOutOfBounds,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DivergentOperation(id) => {
                write!(f, "CRDT operation {id:?} has divergent contents")
            }
            Self::LogicalClockOverflow => f.write_str("CRDT logical clock overflow"),
            Self::IndexOutOfBounds => f.write_str("CRDT sequence index is out of bounds"),
        }
    }
}

impl core::error::Error for Error {}

/// Multi-value register. The visible value is selected deterministically by
/// operation id; concurrent alternatives remain available through
/// [`conflicts`](Self::conflicts).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct Value<T> {
    values: BTreeMap<OpId, T>,
    removed: BTreeSet<OpId>,
}

impl<T> Default for Value<T> {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            removed: BTreeSet::new(),
        }
    }
}

impl<T> Value<T> {
    pub fn new(id: OpId, value: T) -> Self {
        let mut this = Self::default();
        this.values.insert(id, value);
        this
    }

    pub fn get(&self) -> Option<&T> {
        self.values
            .iter()
            .rev()
            .find(|(id, _)| !self.removed.contains(id))
            .map(|(_, value)| value)
    }

    pub fn visible_id(&self) -> Option<OpId> {
        self.values
            .keys()
            .rev()
            .find(|id| !self.removed.contains(id))
            .copied()
    }

    pub fn conflicts(&self) -> impl Iterator<Item = &T> {
        let visible = self.visible_id();
        self.values
            .iter()
            .filter(move |(id, _)| !self.removed.contains(id) && Some(**id) != visible)
            .map(|(_, value)| value)
    }

    pub fn versions(&self) -> impl Iterator<Item = (OpId, &T)> {
        self.values
            .iter()
            .filter(|(id, _)| !self.removed.contains(id))
            .map(|(id, value)| (*id, value))
    }

    pub fn is_empty(&self) -> bool {
        self.visible_id().is_none()
    }

    fn remove_observed(&mut self) {
        self.removed.extend(self.values.keys().copied());
    }
}

impl<T: Clone + PartialEq> Value<T> {
    /// Assign a value, superseding every version observed by this replica.
    /// Reusing an operation ID with identical contents is an idempotent retry;
    /// reusing it with different contents is rejected.
    pub fn set(&mut self, id: OpId, value: T) -> Result<(), Error> {
        if let Some(existing) = self.values.get(&id) {
            return if existing == &value {
                Ok(())
            } else {
                Err(Error::DivergentOperation(id))
            };
        }
        if !self.removed.contains(&id) {
            let observed: Vec<_> = self
                .values
                .keys()
                .filter(|observed| !self.removed.contains(observed))
                .copied()
                .collect();
            self.removed.extend(observed);
        }
        self.values.insert(id, value);
        Ok(())
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        for (id, value) in &other.values {
            if let Some(existing) = self.values.get(id)
                && existing != value
            {
                return Err(Error::DivergentOperation(*id));
            }
        }
        self.removed.extend(other.removed.iter().copied());
        for (id, value) in &other.values {
            self.values.entry(*id).or_insert_with(|| value.clone());
        }
        Ok(())
    }
}

/// Observed-remove map with a multi-value register per key.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct Map<K, V> {
    entries: BTreeMap<K, Value<V>>,
    operation_keys: BTreeMap<OpId, K>,
}

impl<K, V> Default for Map<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            operation_keys: BTreeMap::new(),
        }
    }
}

impl<K: Ord, V: Clone + PartialEq> Map<K, V> {
    pub fn insert(&mut self, id: OpId, key: K, value: V) -> Result<(), Error>
    where
        K: Clone + PartialEq,
    {
        if let Some(existing_key) = self.operation_keys.get(&id)
            && existing_key != &key
        {
            return Err(Error::DivergentOperation(id));
        }
        match self.entries.get_mut(&key) {
            Some(entry) => entry.set(id, value)?,
            None => {
                self.entries.insert(key.clone(), Value::new(id, value));
            }
        }
        self.operation_keys.insert(id, key);
        Ok(())
    }
}

impl<K: Ord, V> Map<K, V> {
    pub fn get(&self, key: &K) -> Option<&V> {
        self.entries.get(key).and_then(Value::get)
    }

    pub fn conflicts(&self, key: &K) -> impl Iterator<Item = &V> {
        self.entries.get(key).into_iter().flat_map(Value::conflicts)
    }

    pub fn remove(&mut self, key: &K) -> bool {
        let Some(value) = self.entries.get_mut(key) else {
            return false;
        };
        let existed = !value.is_empty();
        value.remove_observed();
        existed
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries
            .iter()
            .filter_map(|(key, value)| value.get().map(|value| (key, value)))
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<K: Ord + Clone, V: Clone + PartialEq> Map<K, V> {
    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        for (id, key) in &other.operation_keys {
            if let Some(existing_key) = self.operation_keys.get(id)
                && existing_key != key
            {
                return Err(Error::DivergentOperation(*id));
            }
        }
        let mut staged = self.clone();
        for (key, value) in &other.entries {
            match staged.entries.get_mut(key) {
                Some(entry) => entry.merge(value)?,
                None => {
                    staged.entries.insert(key.clone(), value.clone());
                }
            }
        }
        staged.operation_keys.extend(
            other
                .operation_keys
                .iter()
                .map(|(id, key)| (*id, key.clone())),
        );
        *self = staged;
        Ok(())
    }
}

/// Add-wins observed-remove set.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct Set<T> {
    operations: BTreeMap<OpId, T>,
    removed: BTreeSet<OpId>,
}

impl<T> Default for Set<T> {
    fn default() -> Self {
        Self {
            operations: BTreeMap::new(),
            removed: BTreeSet::new(),
        }
    }
}

impl<T: Ord + Clone + PartialEq> Set<T> {
    pub fn insert(&mut self, id: OpId, value: T) -> Result<bool, Error> {
        if let Some(existing) = self.operations.get(&id) {
            return if existing == &value {
                Ok(false)
            } else {
                Err(Error::DivergentOperation(id))
            };
        }
        self.operations.insert(id, value);
        Ok(true)
    }

    pub fn remove(&mut self, value: &T) -> bool {
        let observed: Vec<_> = self
            .operations
            .iter()
            .filter(|(id, candidate)| !self.removed.contains(id) && *candidate == value)
            .map(|(id, _)| *id)
            .collect();
        let existed = !observed.is_empty();
        self.removed.extend(observed);
        existed
    }

    pub fn contains(&self, value: &T) -> bool {
        self.operations
            .iter()
            .any(|(id, candidate)| !self.removed.contains(id) && candidate == value)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.operations
            .iter()
            .filter(|(id, _)| !self.removed.contains(id))
            .map(|(_, value)| value)
            .collect::<BTreeSet<_>>()
            .into_iter()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        for (id, value) in &other.operations {
            if let Some(existing) = self.operations.get(id)
                && existing != value
            {
                return Err(Error::DivergentOperation(*id));
            }
        }
        self.operations.extend(
            other
                .operations
                .iter()
                .map(|(id, value)| (*id, value.clone())),
        );
        self.removed.extend(other.removed.iter().copied());
        Ok(())
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq)]
#[rkyv(crate = rkyv)]
struct ListElement<T> {
    after: Option<OpId>,
    /// Lamport-style insertion order captured from the causal snapshot.
    /// Later insertions at the same anchor sort before older siblings;
    /// concurrent insertions share a clock and tie-break by `OpId`. The clock
    /// is assigned once by the originating operation and must be copied
    /// verbatim during merge/replay; independently mutator-applying the same
    /// operation against different local maxima is a divergent operation.
    logical_time: u64,
    value: T,
}

/// RGA-style list with stable element identifiers.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct List<T> {
    elements: BTreeMap<OpId, ListElement<T>>,
    removed: BTreeSet<OpId>,
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self {
            elements: BTreeMap::new(),
            removed: BTreeSet::new(),
        }
    }
}

impl<T: PartialEq> List<T> {
    pub fn push(&mut self, id: OpId, value: T) -> Result<(), Error> {
        let after = self.ordered_ids().last().copied();
        self.insert_after(id, after, value)
    }

    pub fn insert(&mut self, index: usize, id: OpId, value: T) -> Result<(), Error> {
        let visible = self.visible_ids();
        if index > visible.len() {
            return Err(Error::IndexOutOfBounds);
        }
        let after = index.checked_sub(1).and_then(|i| visible.get(i).copied());
        self.insert_after(id, after, value)
    }

    pub fn remove(&mut self, index: usize) -> Result<T, Error>
    where
        T: Clone,
    {
        let id = self
            .visible_ids()
            .get(index)
            .copied()
            .ok_or(Error::IndexOutOfBounds)?;
        self.removed.insert(id);
        self.elements
            .get(&id)
            .map(|element| element.value.clone())
            .ok_or(Error::IndexOutOfBounds)
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        let ids = self.visible_ids();
        ids.get(index)
            .and_then(|id| self.elements.get(id))
            .map(|element| &element.value)
    }

    pub fn iter(&self) -> alloc::vec::IntoIter<&T> {
        self.visible_ids()
            .into_iter()
            .filter_map(|id| self.elements.get(&id).map(|element| &element.value))
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub fn len(&self) -> usize {
        self.visible_ids().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert_after(&mut self, id: OpId, after: Option<OpId>, value: T) -> Result<(), Error> {
        if let Some(existing) = self.elements.get(&id) {
            return if existing.after == after && existing.value == value {
                Ok(())
            } else {
                Err(Error::DivergentOperation(id))
            };
        }
        let logical_time = self
            .elements
            .values()
            .map(|element| element.logical_time)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::LogicalClockOverflow)?;
        self.elements.insert(
            id,
            ListElement {
                after,
                logical_time,
                value,
            },
        );
        Ok(())
    }

    fn visible_ids(&self) -> Vec<OpId> {
        self.ordered_ids()
            .into_iter()
            .filter(|id| !self.removed.contains(id))
            .collect()
    }

    fn ordered_ids(&self) -> Vec<OpId> {
        let mut children: BTreeMap<Option<OpId>, Vec<OpId>> = BTreeMap::new();
        for (id, element) in &self.elements {
            children.entry(element.after).or_default().push(*id);
        }
        for ids in children.values_mut() {
            ids.sort_by(|left, right| {
                let left_time = self
                    .elements
                    .get(left)
                    .map_or(0, |element| element.logical_time);
                let right_time = self
                    .elements
                    .get(right)
                    .map_or(0, |element| element.logical_time);
                right_time.cmp(&left_time).then_with(|| left.cmp(right))
            });
        }

        let mut result = Vec::with_capacity(self.elements.len());
        let mut visited = BTreeSet::new();
        fn append_descendants(
            parent: Option<OpId>,
            children: &BTreeMap<Option<OpId>, Vec<OpId>>,
            visited: &mut BTreeSet<OpId>,
            result: &mut Vec<OpId>,
        ) {
            let mut pending = Vec::new();
            if let Some(ids) = children.get(&parent) {
                pending.extend(ids.iter().rev().copied());
            }
            while let Some(id) = pending.pop() {
                if visited.insert(id) {
                    result.push(id);
                    if let Some(ids) = children.get(&Some(id)) {
                        pending.extend(ids.iter().rev().copied());
                    }
                }
            }
        }
        append_descendants(None, &children, &mut visited, &mut result);
        // Invalid/dangling ancestry remains deterministic and visible for
        // diagnostics; complete Merkle ancestry normally makes this empty.
        for id in self.elements.keys() {
            if visited.insert(*id) {
                result.push(*id);
                append_descendants(Some(*id), &children, &mut visited, &mut result);
            }
        }
        result
    }
}

impl<T: Clone + PartialEq> List<T> {
    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        for (id, element) in &other.elements {
            if let Some(existing) = self.elements.get(id) {
                if existing != element {
                    return Err(Error::DivergentOperation(*id));
                }
            }
        }
        self.elements.extend(
            other
                .elements
                .iter()
                .map(|(id, element)| (*id, element.clone())),
        );
        self.removed.extend(other.removed.iter().copied());
        Ok(())
    }
}

/// Unicode scalar sequence editing. Rich-text marks are intentionally not part
/// of the v2 ABI.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Default)]
#[rkyv(crate = rkyv)]
pub struct Text {
    chars: List<char>,
}

impl Text {
    pub fn insert(&mut self, index: usize, change: ChangeId, text: &str) -> Result<(), Error> {
        if index > self.len() {
            return Err(Error::IndexOutOfBounds);
        }
        let mut staged = self.clone();
        for (offset, ch) in text.chars().enumerate() {
            staged
                .chars
                .insert(index + offset, change.operation(offset as u32), ch)?;
        }
        *self = staged;
        Ok(())
    }

    pub fn delete(&mut self, index: usize, count: usize) -> Result<(), Error> {
        if index.checked_add(count).is_none_or(|end| end > self.len()) {
            return Err(Error::IndexOutOfBounds);
        }
        for _ in 0..count {
            self.chars.remove(index)?;
        }
        Ok(())
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        self.chars.merge(&other.chars)
    }

    pub fn as_string(&self) -> String {
        self.chars.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.chars.len()
    }

    pub fn is_empty(&self) -> bool {
        self.chars.is_empty()
    }
}

impl core::fmt::Display for Text {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for ch in self.chars.iter() {
            write!(f, "{ch}")?;
        }
        Ok(())
    }
}

/// Additive positive/negative counter. Every operation id contributes once.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, Default)]
#[rkyv(crate = rkyv)]
pub struct Counter {
    operations: BTreeMap<OpId, i128>,
}

impl Counter {
    pub fn increment(&mut self, id: OpId, amount: u64) -> Result<(), Error> {
        self.apply(id, amount as i128)
    }

    pub fn decrement(&mut self, id: OpId, amount: u64) -> Result<(), Error> {
        self.apply(id, -(amount as i128))
    }

    pub fn add(&mut self, id: OpId, delta: i64) -> Result<(), Error> {
        self.apply(id, delta as i128)
    }

    pub fn value(&self) -> i64 {
        let mut positive = 0u128;
        let mut negative = 0u128;
        for amount in self.operations.values() {
            if *amount >= 0 {
                positive = positive.saturating_add(*amount as u128);
            } else {
                negative = negative.saturating_add(amount.unsigned_abs());
            }
        }
        if positive >= negative {
            positive.saturating_sub(negative).min(i64::MAX as u128) as i64
        } else {
            let magnitude = negative.saturating_sub(positive);
            if magnitude >= (i64::MAX as u128) + 1 {
                i64::MIN
            } else {
                -(magnitude as i64)
            }
        }
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        for (id, amount) in &other.operations {
            if let Some(existing) = self.operations.get(id)
                && existing != amount
            {
                return Err(Error::DivergentOperation(*id));
            }
        }
        self.operations
            .extend(other.operations.iter().map(|(id, amount)| (*id, *amount)));
        Ok(())
    }

    fn apply(&mut self, id: OpId, amount: i128) -> Result<(), Error> {
        if let Some(existing) = self.operations.get(&id) {
            return if *existing == amount {
                Ok(())
            } else {
                Err(Error::DivergentOperation(id))
            };
        }
        self.operations.insert(id, amount);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn change(byte: u8) -> ChangeId {
        ChangeId([byte; 32])
    }

    #[test]
    fn concurrent_counter_increments_survive() {
        let mut a = Counter::default();
        let mut b = Counter::default();
        a.increment(change(1).operation(0), 2).unwrap();
        b.increment(change(2).operation(0), 3).unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(a.value(), 5);
        assert_eq!(b.value(), 5);
    }

    #[test]
    fn change_ids_frame_variable_length_inputs() {
        assert_ne!(ChangeId::derive(b"ab", b"c"), ChangeId::derive(b"a", b"bc"));
    }

    #[test]
    fn scalar_winner_converges_and_conflict_remains_visible() {
        let mut a = Value::new(change(1).operation(0), "a");
        let mut b = Value::new(change(2).operation(0), "b");
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(a.get(), b.get());
        assert_eq!(a.conflicts().copied().collect::<Vec<_>>(), vec!["a"]);
    }

    #[test]
    fn observed_remove_set_is_add_wins() {
        let mut a = Set::default();
        a.insert(change(1).operation(0), "task").unwrap();
        let mut b = a.clone();
        a.remove(&"task");
        b.insert(change(2).operation(0), "task").unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert!(a.contains(&"task"));
        assert!(b.contains(&"task"));
    }

    #[test]
    fn concurrent_list_and_text_edits_converge() {
        let mut a = List::default();
        a.push(change(1).operation(0), 'a').unwrap();
        let mut b = a.clone();
        a.push(change(2).operation(0), 'x').unwrap();
        b.push(change(3).operation(0), 'y').unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(
            a.iter().copied().collect::<Vec<_>>(),
            b.iter().copied().collect::<Vec<_>>()
        );

        let mut ta = Text::default();
        let mut tb = Text::default();
        ta.insert(0, change(4), "Hi").unwrap();
        tb.insert(0, change(5), "👋").unwrap();
        ta.merge(&tb).unwrap();
        tb.merge(&ta).unwrap();
        assert_eq!(ta.as_string(), tb.as_string());
    }

    #[test]
    fn sequential_list_and_text_inserts_preserve_requested_positions() {
        let mut list = List::default();
        list.push(change(1).operation(0), 'A').unwrap();
        list.push(change(1).operation(1), 'C').unwrap();
        list.insert(1, change(2).operation(0), 'B').unwrap();
        list.insert(0, change(3).operation(0), 'Z').unwrap();
        assert_eq!(
            list.iter().copied().collect::<Vec<_>>(),
            vec!['Z', 'A', 'B', 'C']
        );

        let mut text = Text::default();
        text.insert(0, change(4), "AC").unwrap();
        text.insert(1, change(5), "B").unwrap();
        text.insert(0, change(6), "Z").unwrap();
        assert_eq!(text.as_string(), "ZABC");
    }

    #[test]
    fn long_sequential_list_walk_is_iterative() {
        const ELEMENTS: u64 = 50_000;
        let mut list = List::default();
        let mut after = None;
        for logical_time in 1..=ELEMENTS {
            let mut change = [0u8; 32];
            change[..8].copy_from_slice(&logical_time.to_le_bytes());
            let id = ChangeId(change).operation(0);
            list.elements.insert(
                id,
                ListElement {
                    after,
                    logical_time,
                    value: logical_time,
                },
            );
            after = Some(id);
        }

        let ordered = list.ordered_ids();
        assert_eq!(ordered.len(), ELEMENTS as usize);
        assert_eq!(ordered.last(), after.as_ref());
    }

    #[test]
    fn map_retains_concurrent_value_conflicts() {
        let mut a = Map::default();
        let mut b = Map::default();
        a.insert(change(1).operation(0), "title", "one").unwrap();
        b.insert(change(2).operation(0), "title", "two").unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(a.get(&"title"), b.get(&"title"));
        assert_eq!(a.conflicts(&"title").count(), 1);
    }

    #[test]
    fn scalar_operation_retry_is_idempotent_and_divergence_is_rejected() {
        let original = change(1).operation(0);
        let concurrent = change(2).operation(0);
        let mut value = Value::new(original, "one");
        value.merge(&Value::new(concurrent, "two")).unwrap();
        value.set(original, "one").unwrap();
        assert_eq!(value.versions().count(), 2);
        assert_eq!(
            value.set(original, "different"),
            Err(Error::DivergentOperation(original))
        );
        assert_eq!(value.versions().count(), 2);
    }

    #[test]
    fn collection_operation_ids_bind_their_exact_contents() {
        let id = change(7).operation(0);

        let mut set = Set::default();
        set.insert(id, "left").unwrap();
        assert_eq!(set.insert(id, "right"), Err(Error::DivergentOperation(id)));
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec!["left"]);

        let mut left = Map::default();
        left.insert(id, "left", 1).unwrap();
        let mut right = Map::default();
        right.insert(id, "right", 1).unwrap();
        assert_eq!(left.merge(&right), Err(Error::DivergentOperation(id)));
        assert_eq!(left.get(&"left"), Some(&1));
        assert_eq!(left.get(&"right"), None);
    }

    #[test]
    fn failed_merges_leave_materialized_state_unchanged() {
        let divergent = change(9).operation(0);

        let mut map = Map::default();
        map.insert(divergent, "z", 1).unwrap();
        let mut other_map = Map::default();
        other_map.insert(change(1).operation(0), "a", 2).unwrap();
        other_map.insert(divergent, "z", 3).unwrap();
        assert_eq!(
            map.merge(&other_map),
            Err(Error::DivergentOperation(divergent))
        );
        assert_eq!(
            map.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
            vec![("z", 1)]
        );

        let mut list = List::default();
        list.push(divergent, 'a').unwrap();
        let mut other_list = List::default();
        other_list.push(change(1).operation(0), 'x').unwrap();
        other_list.push(divergent, 'b').unwrap();
        assert_eq!(
            list.merge(&other_list),
            Err(Error::DivergentOperation(divergent))
        );
        assert_eq!(list.iter().copied().collect::<Vec<_>>(), vec!['a']);

        let mut counter = Counter::default();
        counter.increment(divergent, 1).unwrap();
        let mut other_counter = Counter::default();
        other_counter.increment(change(1).operation(0), 5).unwrap();
        other_counter.increment(divergent, 2).unwrap();
        assert_eq!(
            counter.merge(&other_counter),
            Err(Error::DivergentOperation(divergent))
        );
        assert_eq!(counter.value(), 1);
    }

    #[test]
    fn every_builtin_converges_for_all_three_replica_sync_orders() {
        let permutations = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];

        let values = [
            Value::new(change(1).operation(0), "a"),
            Value::new(change(2).operation(0), "b"),
            Value::new(change(3).operation(0), "c"),
        ];
        let mut expected_value = None;
        for order in permutations {
            let mut merged = Value::default();
            for index in order {
                merged.merge(&values[index]).unwrap();
            }
            let view = merged
                .versions()
                .map(|(id, value)| (id, *value))
                .collect::<Vec<_>>();
            assert_eq!(expected_value.get_or_insert_with(|| view.clone()), &view);
        }

        let mut maps = [Map::default(), Map::default(), Map::default()];
        maps[0]
            .insert(change(1).operation(0), "title", "a")
            .unwrap();
        maps[1]
            .insert(change(2).operation(0), "title", "b")
            .unwrap();
        maps[2]
            .insert(change(3).operation(0), "other", "c")
            .unwrap();
        let mut expected_map = None;
        for order in permutations {
            let mut merged = Map::default();
            for index in order {
                merged.merge(&maps[index]).unwrap();
            }
            let view = merged
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>();
            assert_eq!(expected_map.get_or_insert_with(|| view.clone()), &view);
        }

        let mut base_set = Set::default();
        base_set.insert(change(4).operation(0), "x").unwrap();
        let mut sets = [base_set.clone(), base_set.clone(), base_set];
        sets[0].remove(&"x");
        sets[1].insert(change(5).operation(0), "x").unwrap();
        sets[2].insert(change(6).operation(0), "y").unwrap();
        let mut expected_set = None;
        for order in permutations {
            let mut merged = Set::default();
            for index in order {
                merged.merge(&sets[index]).unwrap();
            }
            let view = merged.iter().copied().collect::<Vec<_>>();
            assert_eq!(expected_set.get_or_insert_with(|| view.clone()), &view);
        }

        let mut base_list = List::default();
        base_list.push(change(7).operation(0), 'a').unwrap();
        let mut lists = [base_list.clone(), base_list.clone(), base_list];
        lists[0].push(change(8).operation(0), 'x').unwrap();
        lists[1].push(change(9).operation(0), 'y').unwrap();
        lists[2].push(change(10).operation(0), 'z').unwrap();
        let mut expected_list = None;
        for order in permutations {
            let mut merged = List::default();
            for index in order {
                merged.merge(&lists[index]).unwrap();
            }
            let view = merged.iter().copied().collect::<Vec<_>>();
            assert_eq!(expected_list.get_or_insert_with(|| view.clone()), &view);
        }

        let mut base_text = Text::default();
        base_text.insert(0, change(11), "A").unwrap();
        let mut texts = [base_text.clone(), base_text.clone(), base_text];
        texts[0].insert(1, change(12), "x").unwrap();
        texts[1].insert(1, change(13), "y").unwrap();
        texts[2].insert(1, change(14), "z").unwrap();
        let mut expected_text = None;
        for order in permutations {
            let mut merged = Text::default();
            for index in order {
                merged.merge(&texts[index]).unwrap();
            }
            let view = merged.as_string();
            assert_eq!(expected_text.get_or_insert_with(|| view.clone()), &view);
        }

        let mut counters = [Counter::default(), Counter::default(), Counter::default()];
        counters[0]
            .increment(change(15).operation(0), u64::MAX)
            .unwrap();
        counters[1]
            .decrement(change(16).operation(0), u64::MAX)
            .unwrap();
        counters[2].add(change(17).operation(0), -7).unwrap();
        for order in permutations {
            let mut merged = Counter::default();
            for index in order {
                merged.merge(&counters[index]).unwrap();
            }
            assert_eq!(merged.value(), -7);
        }
    }
}
