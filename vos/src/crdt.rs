//! Beginner-facing CRDT field types for `#[actor(crdt)]`.
//!
//! The Merkle-DAG transports and persists causal changes; these payload types
//! supply the convergence rules. Operation identifiers are logical and stable
//! (change id + ordinal), never wall-clock timestamps.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy)]
struct ChangeScope {
    change: ChangeId,
    next_ordinal: u32,
}

#[cfg(feature = "std")]
std::thread_local! {
    static CHANGE_SCOPE: core::cell::RefCell<Option<ChangeScope>> = const {
        core::cell::RefCell::new(None)
    };
}

#[cfg(not(feature = "std"))]
struct GuestChangeScope(core::cell::UnsafeCell<Option<ChangeScope>>);

#[cfg(not(feature = "std"))]
unsafe impl Sync for GuestChangeScope {}

#[cfg(not(feature = "std"))]
static CHANGE_SCOPE: GuestChangeScope = GuestChangeScope(core::cell::UnsafeCell::new(None));

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
    NoChangeScope,
    NestedChangeScope,
    OperationOverflow,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DivergentOperation(id) => {
                write!(f, "CRDT operation {id:?} has divergent contents")
            }
            Self::IndexOutOfBounds => f.write_str("CRDT sequence index is out of bounds"),
            Self::NoChangeScope => f.write_str(
                "CRDT mutation requires an active actor execution slice; mutate replicated fields only inside an actor method",
            ),
            Self::NestedChangeScope => {
                f.write_str("a CRDT execution slice cannot start another change scope")
            }
            Self::OperationOverflow => {
                f.write_str("one CRDT execution slice emitted too many operations")
            }
        }
    }
}

impl core::error::Error for Error {}

/// Run one actor execution slice with stable CRDT operation allocation.
/// Generated actor glue establishes this scope; it is public only so native
/// tests and advanced materializers can exercise the same deterministic API.
#[doc(hidden)]
pub fn with_change<R>(change: ChangeId, f: impl FnOnce() -> Result<R, Error>) -> Result<R, Error> {
    begin_change(change)?;
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            end_change();
        }
    }
    let _reset = Reset;
    f()
}

#[cfg(feature = "std")]
fn begin_change(change: ChangeId) -> Result<(), Error> {
    CHANGE_SCOPE.with(|scope| {
        let mut scope = scope.borrow_mut();
        if scope.is_some() {
            return Err(Error::NestedChangeScope);
        }
        *scope = Some(ChangeScope {
            change,
            next_ordinal: 0,
        });
        Ok(())
    })
}

#[cfg(not(feature = "std"))]
fn begin_change(change: ChangeId) -> Result<(), Error> {
    // SAFETY: PVM guests are single-threaded and actor dispatch never nests a
    // change scope. The explicit occupied check turns accidental nesting into
    // a deterministic error.
    let scope = unsafe { &mut *CHANGE_SCOPE.0.get() };
    if scope.is_some() {
        return Err(Error::NestedChangeScope);
    }
    *scope = Some(ChangeScope {
        change,
        next_ordinal: 0,
    });
    Ok(())
}

#[cfg(feature = "std")]
fn end_change() {
    CHANGE_SCOPE.with(|scope| *scope.borrow_mut() = None);
}

#[cfg(not(feature = "std"))]
fn end_change() {
    // SAFETY: see `begin_change`; this clears the same single-threaded slot.
    unsafe { *CHANGE_SCOPE.0.get() = None };
}

#[cfg(feature = "std")]
fn next_operation() -> Result<OpId, Error> {
    CHANGE_SCOPE.with(|scope| next_operation_from(scope.borrow_mut().as_mut()))
}

#[cfg(not(feature = "std"))]
fn next_operation() -> Result<OpId, Error> {
    // SAFETY: see `begin_change`; mutation is serialized by actor dispatch.
    let scope = unsafe { &mut *CHANGE_SCOPE.0.get() };
    next_operation_from(scope.as_mut())
}

fn next_operation_from(scope: Option<&mut ChangeScope>) -> Result<OpId, Error> {
    let scope = scope.ok_or(Error::NoChangeScope)?;
    let ordinal = scope.next_ordinal;
    scope.next_ordinal = ordinal.checked_add(1).ok_or(Error::OperationOverflow)?;
    Ok(scope.change.operation(ordinal))
}

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
    pub fn new(value: T) -> Result<Self, Error> {
        Ok(Self::new_with_id(next_operation()?, value))
    }

    #[doc(hidden)]
    pub fn new_with_id(id: OpId, value: T) -> Self {
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
    pub fn set(&mut self, value: T) -> Result<(), Error> {
        self.set_with_id(next_operation()?, value)
    }

    #[doc(hidden)]
    pub fn set_with_id(&mut self, id: OpId, value: T) -> Result<(), Error> {
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
    pub fn insert(&mut self, key: K, value: V) -> Result<(), Error>
    where
        K: Clone + PartialEq,
    {
        self.insert_with_id(next_operation()?, key, value)
    }

    #[doc(hidden)]
    pub fn insert_with_id(&mut self, id: OpId, key: K, value: V) -> Result<(), Error>
    where
        K: Clone + PartialEq,
    {
        if let Some(existing_key) = self.operation_keys.get(&id)
            && existing_key != &key
        {
            return Err(Error::DivergentOperation(id));
        }
        match self.entries.get_mut(&key) {
            Some(entry) => entry.set_with_id(id, value)?,
            None => {
                self.entries
                    .insert(key.clone(), Value::new_with_id(id, value));
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
    pub fn insert(&mut self, value: T) -> Result<bool, Error> {
        self.insert_with_id(next_operation()?, value)
    }

    #[doc(hidden)]
    pub fn insert_with_id(&mut self, id: OpId, value: T) -> Result<bool, Error> {
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

impl<T: PartialEq> List<T> {
    pub fn push(&mut self, value: T) -> Result<(), Error> {
        self.push_with_id(next_operation()?, value)
    }

    #[doc(hidden)]
    pub fn push_with_id(&mut self, id: OpId, value: T) -> Result<(), Error> {
        let after = self.ordered_ids().last().copied();
        self.insert_after_with_id(id, after, value)
    }

    pub fn insert(&mut self, index: usize, value: T) -> Result<(), Error> {
        self.insert_with_id(index, next_operation()?, value)
    }

    #[doc(hidden)]
    pub fn insert_with_id(&mut self, index: usize, id: OpId, value: T) -> Result<(), Error> {
        let visible = self.visible_ids();
        if index > visible.len() {
            return Err(Error::IndexOutOfBounds);
        }
        let after = index.checked_sub(1).and_then(|i| visible.get(i).copied());
        self.insert_after_with_id(id, after, value)
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

    fn insert_after_with_id(
        &mut self,
        id: OpId,
        after: Option<OpId>,
        value: T,
    ) -> Result<(), Error> {
        if let Some(existing) = self.elements.get(&id) {
            return if existing.after == after && existing.value == value {
                Ok(())
            } else {
                Err(Error::DivergentOperation(id))
            };
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
    pub fn insert(&mut self, index: usize, text: &str) -> Result<(), Error> {
        if index > self.len() {
            return Err(Error::IndexOutOfBounds);
        }
        let mut staged = self.clone();
        for (offset, ch) in text.chars().enumerate() {
            staged.chars.insert(index + offset, ch)?;
        }
        *self = staged;
        Ok(())
    }

    #[doc(hidden)]
    pub fn insert_with_change(
        &mut self,
        index: usize,
        change: ChangeId,
        text: &str,
    ) -> Result<(), Error> {
        if index > self.len() {
            return Err(Error::IndexOutOfBounds);
        }
        let mut staged = self.clone();
        for (offset, ch) in text.chars().enumerate() {
            staged
                .chars
                .insert_with_id(index + offset, change.operation(offset as u32), ch)?;
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
    pub fn increment(&mut self, amount: u64) -> Result<(), Error> {
        self.increment_with_id(next_operation()?, amount)
    }

    #[doc(hidden)]
    pub fn increment_with_id(&mut self, id: OpId, amount: u64) -> Result<(), Error> {
        self.apply(id, amount as i128)
    }

    pub fn decrement(&mut self, amount: u64) -> Result<(), Error> {
        self.decrement_with_id(next_operation()?, amount)
    }

    #[doc(hidden)]
    pub fn decrement_with_id(&mut self, id: OpId, amount: u64) -> Result<(), Error> {
        self.apply(id, -(amount as i128))
    }

    pub fn add(&mut self, delta: i64) -> Result<(), Error> {
        self.add_with_id(next_operation()?, delta)
    }

    #[doc(hidden)]
    pub fn add_with_id(&mut self, id: OpId, delta: i64) -> Result<(), Error> {
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
    fn actor_slice_allocates_stable_operation_ids() {
        let mut left = Counter::default();
        let mut right = Counter::default();

        with_change(change(7), || {
            left.increment(2)?;
            left.decrement(1)?;
            Ok(())
        })
        .unwrap();
        with_change(change(7), || {
            right.increment(2)?;
            right.decrement(1)?;
            Ok(())
        })
        .unwrap();

        assert_eq!(left.operations, right.operations);
        assert_eq!(
            left.operations.keys().copied().collect::<Vec<_>>(),
            vec![change(7).operation(0), change(7).operation(1)]
        );
        assert_eq!(left.increment(1), Err(Error::NoChangeScope));
    }

    #[test]
    fn actor_slice_scope_cannot_nest_and_is_cleared_after_failure() {
        assert_eq!(
            with_change(change(1), || with_change(change(2), || Ok(()))),
            Err(Error::NestedChangeScope)
        );
        assert_eq!(
            with_change(change(3), || Err::<(), _>(Error::IndexOutOfBounds)),
            Err(Error::IndexOutOfBounds)
        );

        let mut value = Value::default();
        with_change(change(4), || value.set("ready")).unwrap();
        assert_eq!(value.visible_id(), Some(change(4).operation(0)));
    }

    #[test]
    fn text_uses_one_stable_operation_per_unicode_scalar() {
        let mut text = Text::default();
        with_change(change(5), || text.insert(0, "A👋")).unwrap();

        assert_eq!(text.as_string(), "A👋");
        assert_eq!(
            text.chars.elements.keys().copied().collect::<Vec<_>>(),
            vec![change(5).operation(0), change(5).operation(1)]
        );
    }

    #[test]
    fn concurrent_counter_increments_survive() {
        let mut a = Counter::default();
        let mut b = Counter::default();
        a.increment_with_id(change(1).operation(0), 2).unwrap();
        b.increment_with_id(change(2).operation(0), 3).unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(a.value(), 5);
        assert_eq!(b.value(), 5);
    }

    #[test]
    fn scalar_winner_converges_and_conflict_remains_visible() {
        let mut a = Value::new_with_id(change(1).operation(0), "a");
        let mut b = Value::new_with_id(change(2).operation(0), "b");
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(a.get(), b.get());
        assert_eq!(a.conflicts().copied().collect::<Vec<_>>(), vec!["a"]);
    }

    #[test]
    fn observed_remove_set_is_add_wins() {
        let mut a = Set::default();
        a.insert_with_id(change(1).operation(0), "task").unwrap();
        let mut b = a.clone();
        a.remove(&"task");
        b.insert_with_id(change(2).operation(0), "task").unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert!(a.contains(&"task"));
        assert!(b.contains(&"task"));
    }

    #[test]
    fn concurrent_list_and_text_edits_converge() {
        let mut a = List::default();
        a.push_with_id(change(1).operation(0), 'a').unwrap();
        let mut b = a.clone();
        a.push_with_id(change(2).operation(0), 'x').unwrap();
        b.push_with_id(change(3).operation(0), 'y').unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(
            a.iter().copied().collect::<Vec<_>>(),
            b.iter().copied().collect::<Vec<_>>()
        );

        let mut ta = Text::default();
        let mut tb = Text::default();
        ta.insert_with_change(0, change(4), "Hi").unwrap();
        tb.insert_with_change(0, change(5), "👋").unwrap();
        ta.merge(&tb).unwrap();
        tb.merge(&ta).unwrap();
        assert_eq!(ta.as_string(), tb.as_string());
    }

    #[test]
    fn map_retains_concurrent_value_conflicts() {
        let mut a = Map::default();
        let mut b = Map::default();
        a.insert_with_id(change(1).operation(0), "title", "one")
            .unwrap();
        b.insert_with_id(change(2).operation(0), "title", "two")
            .unwrap();
        a.merge(&b).unwrap();
        b.merge(&a).unwrap();
        assert_eq!(a.get(&"title"), b.get(&"title"));
        assert_eq!(a.conflicts(&"title").count(), 1);
    }

    #[test]
    fn scalar_operation_retry_is_idempotent_and_divergence_is_rejected() {
        let original = change(1).operation(0);
        let concurrent = change(2).operation(0);
        let mut value = Value::new_with_id(original, "one");
        value.merge(&Value::new_with_id(concurrent, "two")).unwrap();
        value.set_with_id(original, "one").unwrap();
        assert_eq!(value.versions().count(), 2);
        assert_eq!(
            value.set_with_id(original, "different"),
            Err(Error::DivergentOperation(original))
        );
        assert_eq!(value.versions().count(), 2);
    }

    #[test]
    fn collection_operation_ids_bind_their_exact_contents() {
        let id = change(7).operation(0);

        let mut set = Set::default();
        set.insert_with_id(id, "left").unwrap();
        assert_eq!(
            set.insert_with_id(id, "right"),
            Err(Error::DivergentOperation(id))
        );
        assert_eq!(set.iter().copied().collect::<Vec<_>>(), vec!["left"]);

        let mut left = Map::default();
        left.insert_with_id(id, "left", 1).unwrap();
        let mut right = Map::default();
        right.insert_with_id(id, "right", 1).unwrap();
        assert_eq!(left.merge(&right), Err(Error::DivergentOperation(id)));
        assert_eq!(left.get(&"left"), Some(&1));
        assert_eq!(left.get(&"right"), None);
    }

    #[test]
    fn failed_merges_leave_materialized_state_unchanged() {
        let divergent = change(9).operation(0);

        let mut map = Map::default();
        map.insert_with_id(divergent, "z", 1).unwrap();
        let mut other_map = Map::default();
        other_map
            .insert_with_id(change(1).operation(0), "a", 2)
            .unwrap();
        other_map.insert_with_id(divergent, "z", 3).unwrap();
        assert_eq!(
            map.merge(&other_map),
            Err(Error::DivergentOperation(divergent))
        );
        assert_eq!(
            map.iter().map(|(k, v)| (*k, *v)).collect::<Vec<_>>(),
            vec![("z", 1)]
        );

        let mut list = List::default();
        list.push_with_id(divergent, 'a').unwrap();
        let mut other_list = List::default();
        other_list
            .push_with_id(change(1).operation(0), 'x')
            .unwrap();
        other_list.push_with_id(divergent, 'b').unwrap();
        assert_eq!(
            list.merge(&other_list),
            Err(Error::DivergentOperation(divergent))
        );
        assert_eq!(list.iter().copied().collect::<Vec<_>>(), vec!['a']);

        let mut counter = Counter::default();
        counter.increment_with_id(divergent, 1).unwrap();
        let mut other_counter = Counter::default();
        other_counter
            .increment_with_id(change(1).operation(0), 5)
            .unwrap();
        other_counter.increment_with_id(divergent, 2).unwrap();
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
            Value::new_with_id(change(1).operation(0), "a"),
            Value::new_with_id(change(2).operation(0), "b"),
            Value::new_with_id(change(3).operation(0), "c"),
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
            .insert_with_id(change(1).operation(0), "title", "a")
            .unwrap();
        maps[1]
            .insert_with_id(change(2).operation(0), "title", "b")
            .unwrap();
        maps[2]
            .insert_with_id(change(3).operation(0), "other", "c")
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
        base_set
            .insert_with_id(change(4).operation(0), "x")
            .unwrap();
        let mut sets = [base_set.clone(), base_set.clone(), base_set];
        sets[0].remove(&"x");
        sets[1].insert_with_id(change(5).operation(0), "x").unwrap();
        sets[2].insert_with_id(change(6).operation(0), "y").unwrap();
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
        base_list.push_with_id(change(7).operation(0), 'a').unwrap();
        let mut lists = [base_list.clone(), base_list.clone(), base_list];
        lists[0].push_with_id(change(8).operation(0), 'x').unwrap();
        lists[1].push_with_id(change(9).operation(0), 'y').unwrap();
        lists[2].push_with_id(change(10).operation(0), 'z').unwrap();
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
        base_text.insert_with_change(0, change(11), "A").unwrap();
        let mut texts = [base_text.clone(), base_text.clone(), base_text];
        texts[0].insert_with_change(1, change(12), "x").unwrap();
        texts[1].insert_with_change(1, change(13), "y").unwrap();
        texts[2].insert_with_change(1, change(14), "z").unwrap();
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
            .increment_with_id(change(15).operation(0), u64::MAX)
            .unwrap();
        counters[1]
            .decrement_with_id(change(16).operation(0), u64::MAX)
            .unwrap();
        counters[2]
            .add_with_id(change(17).operation(0), -7)
            .unwrap();
        for order in permutations {
            let mut merged = Counter::default();
            for index in order {
                merged.merge(&counters[index]).unwrap();
            }
            assert_eq!(merged.value(), -7);
        }
    }
}
