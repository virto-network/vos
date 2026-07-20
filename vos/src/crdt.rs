//! Beginner-facing CRDT field types for `#[actor(crdt)]`.
//!
//! The Merkle-DAG transports and persists causal changes; these payload types
//! supply the convergence rules. Operation identifiers are logical and stable
//! (change id + ordinal), never wall-clock timestamps.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
struct ChangeScope {
    change: ChangeId,
    next_ordinal: u32,
    operations: Vec<PendingOperation>,
}

#[derive(Debug, Clone)]
struct PendingOperation {
    field: crate::v2::Hash,
    id: OpId,
    payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CompletedChange {
    change: ChangeId,
    operations: Vec<PendingOperation>,
}

#[cfg(feature = "std")]
std::thread_local! {
    static CHANGE_SCOPE: core::cell::RefCell<Option<ChangeScope>> = const {
        core::cell::RefCell::new(None)
    };
    static COMPLETED_CHANGE: core::cell::RefCell<Option<CompletedChange>> = const {
        core::cell::RefCell::new(None)
    };
}

#[cfg(not(feature = "std"))]
struct GuestChangeScope(core::cell::UnsafeCell<Option<ChangeScope>>);

#[cfg(not(feature = "std"))]
unsafe impl Sync for GuestChangeScope {}

#[cfg(not(feature = "std"))]
static CHANGE_SCOPE: GuestChangeScope = GuestChangeScope(core::cell::UnsafeCell::new(None));

#[cfg(not(feature = "std"))]
struct GuestCompletedChange(core::cell::UnsafeCell<Option<CompletedChange>>);

#[cfg(not(feature = "std"))]
unsafe impl Sync for GuestCompletedChange {}

#[cfg(not(feature = "std"))]
static COMPLETED_CHANGE: GuestCompletedChange =
    GuestCompletedChange(core::cell::UnsafeCell::new(None));

/// Runtime identity assigned by generated `#[actor(crdt)]` glue. The tag is
/// deliberately absent from archived actor state: it is reconstructed from
/// the actor and field names after every create/restore.
#[doc(hidden)]
pub trait Field {
    fn __vos_init(&mut self, actor: &str, field: &str);
}

fn field_tag(actor: &str, field: &str) -> crate::v2::Hash {
    crate::v2::Hash::digest(
        b"vos/crdt-field-tag/v2",
        &[actor.as_bytes(), field.as_bytes()],
    )
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

    /// Derive the actor-local allocator namespace for one scheduler dispatch.
    /// The outer v2 change remains the batch identity; this scoped identifier
    /// prevents actor re-entry from reusing `(change, ordinal)` in field state.
    #[doc(hidden)]
    pub fn for_dispatch(
        change: crate::v2::ChangeId,
        actor: crate::v2::ActorId,
        dispatch_ordinal: u32,
    ) -> Self {
        Self(crate::crypto::blake2b_hash::<32>(
            b"vos/crdt-actor-dispatch/v2",
            &[&change.0, &actor.0, &dispatch_ordinal.to_le_bytes()],
        ))
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
    NoChangeScope,
    NestedChangeScope,
    OperationOverflow,
    NoCompletedChange,
    ChangeMismatch,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DivergentOperation(id) => {
                write!(f, "CRDT operation {id:?} has divergent contents")
            }
            Self::LogicalClockOverflow => f.write_str("CRDT logical clock overflow"),
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
            Self::NoCompletedChange => {
                f.write_str("the CRDT execution slice did not produce a completed change")
            }
            Self::ChangeMismatch => {
                f.write_str("the completed CRDT change does not match the actor slice")
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
    let result = f();
    if result.is_ok() {
        complete_change();
    }
    result
}

/// Replace the allocator namespace restored inside a suspended actor VM.
///
/// A JAR snapshot intentionally preserves the active Rust stack, including
/// this scope. The resume token names the new execution slice, so resumption
/// must reset both its change identity and operation ordinal before the guest
/// executes any post-await mutation.
#[doc(hidden)]
pub fn rebind_change(change: ChangeId) -> Result<(), Error> {
    #[cfg(feature = "std")]
    {
        CHANGE_SCOPE.with(|scope| rebind_change_in(scope.borrow_mut().as_mut(), change))
    }
    #[cfg(not(feature = "std"))]
    {
        // SAFETY: PVM guests are single-threaded and resume one actor at a
        // flushed protocol boundary.
        let scope = unsafe { &mut *CHANGE_SCOPE.0.get() };
        rebind_change_in(scope.as_mut(), change)
    }
}

fn rebind_change_in(scope: Option<&mut ChangeScope>, change: ChangeId) -> Result<(), Error> {
    let scope = scope.ok_or(Error::NoChangeScope)?;
    scope.change = change;
    scope.next_ordinal = 0;
    // Pre-await operations belong to the checkpointed slice. The resumed
    // slice receives a fresh outer change/dispatch namespace and must only
    // report mutations executed after the restored protocol boundary.
    scope.operations.clear();
    Ok(())
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
            operations: Vec::new(),
        });
        COMPLETED_CHANGE.with(|completed| *completed.borrow_mut() = None);
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
        operations: Vec::new(),
    });
    // SAFETY: the guest is single-threaded and this slot is paired with the
    // active change scope above.
    unsafe { *COMPLETED_CHANGE.0.get() = None };
    Ok(())
}

#[cfg(feature = "std")]
fn complete_change() {
    CHANGE_SCOPE.with(|scope| {
        let Some(scope) = scope.borrow_mut().take() else {
            return;
        };
        COMPLETED_CHANGE.with(|completed| {
            *completed.borrow_mut() = Some(CompletedChange {
                change: scope.change,
                operations: scope.operations,
            });
        });
    });
}

#[cfg(not(feature = "std"))]
fn complete_change() {
    // SAFETY: see `begin_change`; both slots are guest-local and serialized.
    let Some(scope) = (unsafe { &mut *CHANGE_SCOPE.0.get() }).take() else {
        return;
    };
    unsafe {
        *COMPLETED_CHANGE.0.get() = Some(CompletedChange {
            change: scope.change,
            operations: scope.operations,
        });
    }
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

fn record_operation(field: crate::v2::Hash, id: OpId, payload: Vec<u8>) -> Result<(), Error> {
    debug_assert!(!payload.is_empty());
    #[cfg(feature = "std")]
    {
        CHANGE_SCOPE
            .with(|scope| record_operation_in(scope.borrow_mut().as_mut(), field, id, payload))
    }
    #[cfg(not(feature = "std"))]
    {
        // SAFETY: see `begin_change`; actor mutation is single-threaded.
        let scope = unsafe { &mut *CHANGE_SCOPE.0.get() };
        record_operation_in(scope.as_mut(), field, id, payload)
    }
}

fn record_operation_in(
    scope: Option<&mut ChangeScope>,
    field: crate::v2::Hash,
    id: OpId,
    payload: Vec<u8>,
) -> Result<(), Error> {
    let scope = scope.ok_or(Error::NoChangeScope)?;
    if id.change != scope.change {
        return Err(Error::ChangeMismatch);
    }
    scope
        .operations
        .push(PendingOperation { field, id, payload });
    Ok(())
}

/// Take the concrete operations emitted by the last successful actor slice.
/// The returned order is the actor's mutation-emission order.
#[doc(hidden)]
pub fn take_operations(
    actor: crate::v2::ActorId,
    dispatch: crate::v2::CrdtDispatchV2,
) -> Result<Vec<crate::v2::CrdtOperationV2>, Error> {
    #[cfg(feature = "std")]
    let completed = COMPLETED_CHANGE.with(|completed| completed.borrow_mut().take());
    #[cfg(not(feature = "std"))]
    // SAFETY: see `begin_change`; the actor entrypoint consumes this once.
    let completed = unsafe { (&mut *COMPLETED_CHANGE.0.get()).take() };

    let completed = completed.ok_or(Error::NoCompletedChange)?;
    let scoped_change = ChangeId::for_dispatch(dispatch.change, actor, dispatch.ordinal);
    if completed.change != scoped_change {
        return Err(Error::ChangeMismatch);
    }
    let operations = completed
        .operations
        .into_iter()
        .map(|operation| crate::v2::CrdtOperationV2 {
            actor,
            dispatch_ordinal: dispatch.ordinal,
            field: operation.field,
            ordinal: operation.id.ordinal,
            id: dispatch.change.operation(
                actor,
                dispatch.ordinal,
                operation.field,
                operation.id.ordinal,
            ),
            payload: operation.payload,
        })
        .collect::<Vec<_>>();
    if operations
        .iter()
        .enumerate()
        .any(|(ordinal, operation)| operation.ordinal as usize != ordinal)
    {
        return Err(Error::ChangeMismatch);
    }
    Ok(operations)
}

fn operation_payload(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(tag);
    payload.extend_from_slice(&(parts.len() as u32).to_le_bytes());
    for part in parts {
        payload.extend_from_slice(&(part.len() as u64).to_le_bytes());
        payload.extend_from_slice(part);
    }
    payload
}

fn encode_op_ids(ids: impl IntoIterator<Item = OpId>) -> Vec<u8> {
    let ids = ids.into_iter().collect::<Vec<_>>();
    let mut encoded = Vec::with_capacity(4 + ids.len() * 36);
    encoded.extend_from_slice(&(ids.len() as u32).to_le_bytes());
    for id in ids {
        encoded.extend_from_slice(&id.change.0);
        encoded.extend_from_slice(&id.ordinal.to_le_bytes());
    }
    encoded
}

fn encode_optional_op_id(id: Option<OpId>) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(37);
    match id {
        Some(id) => {
            encoded.push(1);
            encoded.extend_from_slice(&id.change.0);
            encoded.extend_from_slice(&id.ordinal.to_le_bytes());
        }
        None => encoded.push(0),
    }
    encoded
}

/// Multi-value register. The visible value is selected deterministically by
/// operation id; concurrent alternatives remain available through
/// [`conflicts`](Self::conflicts).
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize, Debug, Clone)]
#[rkyv(crate = rkyv)]
pub struct Value<T> {
    values: BTreeMap<OpId, T>,
    removed: BTreeSet<OpId>,
    #[rkyv(with = rkyv::with::Skip)]
    field: crate::v2::Hash,
}

impl<T> Default for Value<T> {
    fn default() -> Self {
        Self {
            values: BTreeMap::new(),
            removed: BTreeSet::new(),
            field: crate::v2::Hash::ZERO,
        }
    }
}

impl<T> Field for Value<T> {
    fn __vos_init(&mut self, actor: &str, field: &str) {
        self.field = field_tag(actor, field);
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
    pub fn set(&mut self, value: T) -> Result<(), Error>
    where
        T: crate::Encode,
    {
        let id = next_operation()?;
        let observed = encode_op_ids(
            self.values
                .keys()
                .filter(|observed| !self.removed.contains(observed))
                .copied(),
        );
        let encoded_value = crate::Encode::encode(&value);
        self.set_with_id(id, value)?;
        record_operation(
            self.field,
            id,
            operation_payload(0, &[&observed, &encoded_value]),
        )
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
    #[rkyv(with = rkyv::with::Skip)]
    field: crate::v2::Hash,
}

impl<K, V> Default for Map<K, V> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            operation_keys: BTreeMap::new(),
            field: crate::v2::Hash::ZERO,
        }
    }
}

impl<K, V> Field for Map<K, V> {
    fn __vos_init(&mut self, actor: &str, field: &str) {
        self.field = field_tag(actor, field);
    }
}

impl<K: Ord, V: Clone + PartialEq> Map<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> Result<(), Error>
    where
        K: Clone + PartialEq + crate::Encode,
        V: crate::Encode,
    {
        let id = next_operation()?;
        let observed = encode_op_ids(
            self.entries
                .get(&key)
                .into_iter()
                .flat_map(Value::versions)
                .map(|(id, _)| id),
        );
        let encoded_key = crate::Encode::encode(&key);
        let encoded_value = crate::Encode::encode(&value);
        self.insert_with_id(id, key, value)?;
        record_operation(
            self.field,
            id,
            operation_payload(1, &[&observed, &encoded_key, &encoded_value]),
        )
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

    pub fn remove(&mut self, key: &K) -> Result<bool, Error>
    where
        K: crate::Encode,
    {
        let Some(value) = self.entries.get_mut(key) else {
            return Ok(false);
        };
        let observed_ids = value.versions().map(|(id, _)| id).collect::<Vec<_>>();
        let existed = !observed_ids.is_empty();
        if !existed {
            return Ok(false);
        }
        let id = next_operation()?;
        let observed = encode_op_ids(observed_ids);
        let encoded_key = crate::Encode::encode(key);
        value.remove_observed();
        record_operation(
            self.field,
            id,
            operation_payload(2, &[&observed, &encoded_key]),
        )?;
        Ok(true)
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
    #[rkyv(with = rkyv::with::Skip)]
    field: crate::v2::Hash,
}

impl<T> Default for Set<T> {
    fn default() -> Self {
        Self {
            operations: BTreeMap::new(),
            removed: BTreeSet::new(),
            field: crate::v2::Hash::ZERO,
        }
    }
}

impl<T> Field for Set<T> {
    fn __vos_init(&mut self, actor: &str, field: &str) {
        self.field = field_tag(actor, field);
    }
}

impl<T: Ord + Clone + PartialEq> Set<T> {
    pub fn insert(&mut self, value: T) -> Result<bool, Error>
    where
        T: crate::Encode,
    {
        let id = next_operation()?;
        let encoded_value = crate::Encode::encode(&value);
        let inserted = self.insert_with_id(id, value)?;
        record_operation(self.field, id, operation_payload(3, &[&encoded_value]))?;
        Ok(inserted)
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

    pub fn remove(&mut self, value: &T) -> Result<bool, Error>
    where
        T: crate::Encode,
    {
        let observed: Vec<_> = self
            .operations
            .iter()
            .filter(|(id, candidate)| !self.removed.contains(id) && *candidate == value)
            .map(|(id, _)| *id)
            .collect();
        let existed = !observed.is_empty();
        if !existed {
            return Ok(false);
        }
        let id = next_operation()?;
        let encoded_observed = encode_op_ids(observed.iter().copied());
        let encoded_value = crate::Encode::encode(value);
        self.removed.extend(observed);
        record_operation(
            self.field,
            id,
            operation_payload(4, &[&encoded_observed, &encoded_value]),
        )?;
        Ok(true)
    }

    #[doc(hidden)]
    pub fn remove_observed(&mut self, value: &T) -> bool {
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
    #[rkyv(with = rkyv::with::Skip)]
    field: crate::v2::Hash,
}

impl<T> Default for List<T> {
    fn default() -> Self {
        Self {
            elements: BTreeMap::new(),
            removed: BTreeSet::new(),
            field: crate::v2::Hash::ZERO,
        }
    }
}

impl<T> Field for List<T> {
    fn __vos_init(&mut self, actor: &str, field: &str) {
        self.field = field_tag(actor, field);
    }
}

impl<T: PartialEq> List<T> {
    pub fn push(&mut self, value: T) -> Result<(), Error>
    where
        T: crate::Encode,
    {
        let id = next_operation()?;
        let after = self.ordered_ids().last().copied();
        let encoded_after = encode_optional_op_id(after);
        let encoded_value = crate::Encode::encode(&value);
        self.insert_after_with_id(id, after, value)?;
        record_operation(
            self.field,
            id,
            operation_payload(5, &[&encoded_after, &encoded_value]),
        )
    }

    #[doc(hidden)]
    pub fn push_with_id(&mut self, id: OpId, value: T) -> Result<(), Error> {
        let after = self.ordered_ids().last().copied();
        self.insert_after_with_id(id, after, value)
    }

    pub fn insert(&mut self, index: usize, value: T) -> Result<(), Error>
    where
        T: crate::Encode,
    {
        let visible = self.visible_ids();
        if index > visible.len() {
            return Err(Error::IndexOutOfBounds);
        }
        let id = next_operation()?;
        let after = index.checked_sub(1).and_then(|i| visible.get(i).copied());
        let encoded_after = encode_optional_op_id(after);
        let encoded_value = crate::Encode::encode(&value);
        self.insert_after_with_id(id, after, value)?;
        record_operation(
            self.field,
            id,
            operation_payload(5, &[&encoded_after, &encoded_value]),
        )
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
        let removal = next_operation()?;
        let target = encode_op_ids([id]);
        let value = self
            .elements
            .get(&id)
            .map(|element| element.value.clone())
            .ok_or(Error::IndexOutOfBounds)?;
        record_operation(self.field, removal, operation_payload(6, &[&target]))?;
        self.removed.insert(id);
        Ok(value)
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
    #[rkyv(with = rkyv::with::Skip)]
    field: crate::v2::Hash,
}

impl Field for Text {
    fn __vos_init(&mut self, actor: &str, field: &str) {
        self.field = field_tag(actor, field);
    }
}

impl Text {
    pub fn insert(&mut self, index: usize, text: &str) -> Result<(), Error> {
        if index > self.len() {
            return Err(Error::IndexOutOfBounds);
        }
        let mut staged = self.clone();
        for (offset, ch) in text.chars().enumerate() {
            let visible = staged.chars.visible_ids();
            let insert_at = index + offset;
            let after = insert_at
                .checked_sub(1)
                .and_then(|i| visible.get(i).copied());
            let id = next_operation()?;
            let encoded_after = encode_optional_op_id(after);
            let mut utf8 = [0; 4];
            let encoded_char = ch.encode_utf8(&mut utf8).as_bytes();
            staged.chars.insert_after_with_id(id, after, ch)?;
            record_operation(
                self.field,
                id,
                operation_payload(7, &[&encoded_after, encoded_char]),
            )?;
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
        let mut staged = self.clone();
        for _ in 0..count {
            let target = staged
                .chars
                .visible_ids()
                .get(index)
                .copied()
                .ok_or(Error::IndexOutOfBounds)?;
            let removal = next_operation()?;
            staged.chars.removed.insert(target);
            let encoded_target = encode_op_ids([target]);
            record_operation(
                self.field,
                removal,
                operation_payload(8, &[&encoded_target]),
            )?;
        }
        *self = staged;
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
    #[rkyv(with = rkyv::with::Skip)]
    field: crate::v2::Hash,
}

impl Field for Counter {
    fn __vos_init(&mut self, actor: &str, field: &str) {
        self.field = field_tag(actor, field);
    }
}

impl Counter {
    pub fn increment(&mut self, amount: u64) -> Result<(), Error> {
        let id = next_operation()?;
        self.increment_with_id(id, amount)?;
        record_operation(
            self.field,
            id,
            operation_payload(9, &[&(amount as i128).to_le_bytes()]),
        )
    }

    #[doc(hidden)]
    pub fn increment_with_id(&mut self, id: OpId, amount: u64) -> Result<(), Error> {
        self.apply(id, amount as i128)
    }

    pub fn decrement(&mut self, amount: u64) -> Result<(), Error> {
        let id = next_operation()?;
        self.decrement_with_id(id, amount)?;
        record_operation(
            self.field,
            id,
            operation_payload(9, &[&(-(amount as i128)).to_le_bytes()]),
        )
    }

    #[doc(hidden)]
    pub fn decrement_with_id(&mut self, id: OpId, amount: u64) -> Result<(), Error> {
        self.apply(id, -(amount as i128))
    }

    pub fn add(&mut self, delta: i64) -> Result<(), Error> {
        let id = next_operation()?;
        self.add_with_id(id, delta)?;
        record_operation(
            self.field,
            id,
            operation_payload(9, &[&(delta as i128).to_le_bytes()]),
        )
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
        with_change(change(4), || value.set(String::from("ready"))).unwrap();
        assert_eq!(value.visible_id(), Some(change(4).operation(0)));
    }

    #[test]
    fn restored_scope_rebinds_before_post_await_mutations() {
        let mut counter = Counter::default();
        with_change(change(1), || {
            counter.increment(1)?;
            rebind_change(change(2))?;
            counter.increment(1)?;
            Ok(())
        })
        .unwrap();

        assert_eq!(
            counter.operations.keys().copied().collect::<Vec<_>>(),
            vec![change(1).operation(0), change(2).operation(0)]
        );
        assert_eq!(counter.value(), 2);
    }

    #[test]
    fn scheduler_dispatches_have_distinct_actor_local_namespaces() {
        let batch = crate::v2::ChangeId([9; 32]);
        let actor = crate::v2::ActorId([8; 32]);
        assert_ne!(
            ChangeId::for_dispatch(batch, actor, 0),
            ChangeId::for_dispatch(batch, actor, 1)
        );
        assert_ne!(
            ChangeId::for_dispatch(batch, actor, 0),
            ChangeId::for_dispatch(batch, crate::v2::ActorId([7; 32]), 0)
        );
    }

    #[test]
    fn completed_slice_exposes_field_scoped_consensus_operations() {
        let mut counter = Counter::default();
        Field::__vos_init(&mut counter, "Board", "edits");
        let actor = crate::v2::ActorId([4; 32]);
        let change = crate::v2::ChangeId([7; 32]);
        let dispatch = crate::v2::CrdtDispatchV2 { change, ordinal: 3 };
        let scoped = ChangeId::for_dispatch(change, actor, dispatch.ordinal);

        with_change(scoped, || {
            counter.increment(2)?;
            counter.decrement(1)?;
            Ok(())
        })
        .unwrap();
        let operations = take_operations(actor, dispatch).unwrap();

        let field = field_tag("Board", "edits");
        assert_eq!(operations.len(), 2);
        assert!(operations.iter().all(|operation| operation.field == field));
        assert!(
            operations
                .iter()
                .all(|operation| operation.dispatch_ordinal == dispatch.ordinal)
        );
        let ordinals = operations
            .iter()
            .map(|operation| {
                assert_eq!(
                    operation.id,
                    change.operation(actor, dispatch.ordinal, field, operation.ordinal)
                );
                operation.ordinal
            })
            .collect::<Vec<_>>();
        assert_eq!(ordinals, vec![0, 1]);
        assert_eq!(
            take_operations(actor, dispatch),
            Err(Error::NoCompletedChange)
        );
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
    fn change_ids_frame_variable_length_inputs() {
        assert_ne!(ChangeId::derive(b"ab", b"c"), ChangeId::derive(b"a", b"bc"));
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
        a.remove_observed(&"task");
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
    fn sequential_list_and_text_inserts_preserve_requested_positions() {
        let mut list = List::default();
        list.push_with_id(change(1).operation(0), 'A').unwrap();
        list.push_with_id(change(1).operation(1), 'C').unwrap();
        list.insert_with_id(1, change(2).operation(0), 'B').unwrap();
        list.insert_with_id(0, change(3).operation(0), 'Z').unwrap();
        assert_eq!(
            list.iter().copied().collect::<Vec<_>>(),
            vec!['Z', 'A', 'B', 'C']
        );

        let mut text = Text::default();
        text.insert_with_change(0, change(4), "AC").unwrap();
        text.insert_with_change(1, change(5), "B").unwrap();
        text.insert_with_change(0, change(6), "Z").unwrap();
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
        sets[0].remove_observed(&"x");
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
