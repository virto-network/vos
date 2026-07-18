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
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/crdt-change/v2",
            &[namespace, nonce],
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
    IndexOutOfBounds,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DivergentOperation(id) => {
                write!(f, "CRDT operation {id:?} has divergent contents")
            }
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

    /// Assign a value, superseding every version observed by this replica.
    pub fn set(&mut self, id: OpId, value: T) {
        self.removed.extend(self.values.keys().copied());
        self.values.clear();
        if !self.removed.contains(&id) {
            self.values.insert(id, value);
        }
    }

    pub fn get(&self) -> Option<&T> {
        self.values.last_key_value().map(|(_, value)| value)
    }

    pub fn visible_id(&self) -> Option<OpId> {
        self.values.last_key_value().map(|(id, _)| *id)
    }

    pub fn conflicts(&self) -> impl Iterator<Item = &T> {
        let visible = self.visible_id();
        self.values
            .iter()
            .filter(move |(id, _)| Some(**id) != visible)
            .map(|(_, value)| value)
    }

    pub fn versions(&self) -> impl Iterator<Item = (OpId, &T)> {
        self.values.iter().map(|(id, value)| (*id, value))
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    fn remove_observed(&mut self) {
        self.removed.extend(self.values.keys().copied());
        self.values.clear();
    }
}

impl<T: Clone + PartialEq> Value<T> {
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
            if !self.removed.contains(id) {
                self.values.entry(*id).or_insert_with(|| value.clone());
            }
        }
        self.values.retain(|id, _| !self.removed.contains(id));
        Ok(())
    }
}

/// Observed-remove map with a multi-value register per key.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct Map<K, V> {
    entries: BTreeMap<K, Value<V>>,
}

impl<K, V> Default for Map<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
}

impl<K: Ord, V> Map<K, V> {
    pub fn insert(&mut self, id: OpId, key: K, value: V) {
        match self.entries.get_mut(&key) {
            Some(entry) => entry.set(id, value),
            None => {
                self.entries.insert(key, Value::new(id, value));
            }
        }
    }

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
        for (key, value) in &other.entries {
            match self.entries.get_mut(key) {
                Some(entry) => entry.merge(value)?,
                None => {
                    self.entries.insert(key.clone(), value.clone());
                }
            }
        }
        Ok(())
    }
}

/// Add-wins observed-remove set.
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct Set<T> {
    adds: BTreeMap<T, BTreeSet<OpId>>,
    removed: BTreeMap<T, BTreeSet<OpId>>,
}

impl<T> Default for Set<T> {
    fn default() -> Self {
        Self {
            adds: BTreeMap::new(),
            removed: BTreeMap::new(),
        }
    }
}

impl<T: Ord + Clone> Set<T> {
    pub fn insert(&mut self, id: OpId, value: T) -> bool {
        self.adds.entry(value).or_default().insert(id)
    }

    pub fn remove(&mut self, value: &T) -> bool {
        let Some(observed) = self.adds.get(value) else {
            return false;
        };
        if observed.is_empty() {
            return false;
        }
        self.removed
            .entry(value.clone())
            .or_default()
            .extend(observed.iter().copied());
        self.prune(value);
        true
    }

    pub fn contains(&self, value: &T) -> bool {
        self.adds.get(value).is_some_and(|ids| !ids.is_empty())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.adds
            .iter()
            .filter(|(_, ids)| !ids.is_empty())
            .map(|(value, _)| value)
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn merge(&mut self, other: &Self) {
        for (value, ids) in &other.adds {
            self.adds
                .entry(value.clone())
                .or_default()
                .extend(ids.iter().copied());
        }
        for (value, ids) in &other.removed {
            self.removed
                .entry(value.clone())
                .or_default()
                .extend(ids.iter().copied());
        }
        let keys: Vec<_> = self.adds.keys().cloned().collect();
        for key in &keys {
            self.prune(key);
        }
    }

    fn prune(&mut self, value: &T) {
        if let (Some(adds), Some(removed)) = (self.adds.get_mut(value), self.removed.get(value)) {
            adds.retain(|id| !removed.contains(id));
        }
    }
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone, PartialEq)]
#[rkyv(crate = rkyv)]
struct ListElement<T> {
    id: OpId,
    after: Option<OpId>,
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

impl<T> List<T> {
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
        Ok(self.elements[&id].value.clone())
    }

    pub fn get(&self, index: usize) -> Option<&T> {
        let ids = self.visible_ids();
        ids.get(index).map(|id| &self.elements[id].value)
    }

    pub fn iter(&self) -> alloc::vec::IntoIter<&T> {
        self.visible_ids()
            .into_iter()
            .map(|id| &self.elements[&id].value)
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
        if self.elements.contains_key(&id) {
            return Err(Error::DivergentOperation(id));
        }
        self.elements.insert(id, ListElement { id, after, value });
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
        for element in self.elements.values() {
            children.entry(element.after).or_default().push(element.id);
        }
        let mut result = Vec::with_capacity(self.elements.len());
        let mut visited = BTreeSet::new();
        fn append(
            parent: Option<OpId>,
            children: &BTreeMap<Option<OpId>, Vec<OpId>>,
            visited: &mut BTreeSet<OpId>,
            result: &mut Vec<OpId>,
        ) {
            if let Some(ids) = children.get(&parent) {
                for id in ids {
                    if visited.insert(*id) {
                        result.push(*id);
                        append(Some(*id), children, visited, result);
                    }
                }
            }
        }
        append(None, &children, &mut visited, &mut result);
        // Invalid/dangling ancestry remains deterministic and visible for
        // diagnostics; complete Merkle ancestry normally makes this empty.
        for id in self.elements.keys() {
            if visited.insert(*id) {
                result.push(*id);
                append(Some(*id), &children, &mut visited, &mut result);
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
            } else {
                self.elements.insert(*id, element.clone());
            }
        }
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
        for (offset, ch) in text.chars().enumerate() {
            self.chars
                .insert(index + offset, change.operation(offset as u32), ch)?;
        }
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
    operations: BTreeMap<OpId, i64>,
}

impl Counter {
    pub fn increment(&mut self, id: OpId, amount: i64) -> Result<(), Error> {
        self.apply(id, amount)
    }

    pub fn decrement(&mut self, id: OpId, amount: i64) -> Result<(), Error> {
        self.apply(id, amount.saturating_neg())
    }

    pub fn value(&self) -> i64 {
        self.operations
            .values()
            .copied()
            .fold(0i64, i64::saturating_add)
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), Error> {
        for (id, amount) in &other.operations {
            self.apply(*id, *amount)?;
        }
        Ok(())
    }

    fn apply(&mut self, id: OpId, amount: i64) -> Result<(), Error> {
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
        a.insert(change(1).operation(0), "task");
        let mut b = a.clone();
        a.remove(&"task");
        b.insert(change(2).operation(0), "task");
        a.merge(&b);
        b.merge(&a);
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
    fn map_retains_concurrent_value_conflicts() {
        let mut a = Map::default();
        let mut b = Map::default();
        a.insert(change(1).operation(0), "title", "one");
        b.insert(change(2).operation(0), "title", "two");
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(a.get(&"title"), b.get(&"title"));
        assert_eq!(a.conflicts(&"title").count(), 1);
    }
}
