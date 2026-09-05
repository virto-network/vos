//! Adversarial fixture: a Merge method tries to mutate fresh Linear state.

use vos::prelude::*;

#[cfg(not(feature = "valid"))]
#[actor(agent)]
pub struct LaneEscape {
    linear: u64,
    changes: crdt::Counter,
    #[state(local)]
    private: u64,
}

#[cfg(not(feature = "valid"))]
#[messages(agent)]
impl LaneEscape {
    fn new() -> Self {
        Self {
            linear: 0,
            changes: crdt::Counter::default(),
            private: 7,
        }
    }

    #[msg]
    fn leak_local_from_shared_query(&self) -> u64 {
        self.private
    }

    #[msg(merge)]
    fn escape(&mut self) {
        self.linear = 1;
        self.changes
            .increment(1)
            .expect("one stable operation per slice");
    }
}

/// Compile-pass coverage for the complete macro-side lane surface. Package
/// admission remains a separate runtime gate, so this fixture is checked with
/// Cargo directly rather than packaged with `vosx agent build`.
#[cfg(feature = "valid")]
#[actor(agent)]
pub struct LaneSurface {
    #[state(const)]
    namespace: u64,
    linear: u64,
    changes: crdt::Counter,
    #[state(local)]
    private: u64,
    #[state(skip)]
    derived: u64,
    #[storage(linear, committed, prefix = "rows/linear/")]
    committed: vos::storage::CommittedMap<u64, u64>,
    #[storage(merge, prefix = "rows/merge/")]
    merge_rows: vos::storage::StorageMap<u64, u64>,
    #[storage(local, prefix = "rows/local/")]
    local_rows: vos::storage::StorageMap<u64, u64>,
}

#[cfg(feature = "valid")]
#[messages(agent)]
impl LaneSurface {
    fn new(namespace: u64) -> Self {
        Self {
            namespace,
            linear: 0,
            changes: crdt::Counter::default(),
            private: 0,
            derived: 0,
            committed: vos::storage::CommittedMap::default(),
            merge_rows: vos::storage::StorageMap::default(),
            local_rows: vos::storage::StorageMap::default(),
        }
    }

    #[msg(linear)]
    fn linear_write(&mut self, key: u64, value: u64) -> u64 {
        self.linear = value;
        self.derived = self.namespace;
        self.committed.insert(&key, &value);
        let _ = self.merge_rows.get(&key);
        self.linear
    }

    #[msg(merge)]
    fn merge_write(&mut self, key: u64, value: u64) {
        self.derived = self.namespace;
        self.merge_rows.insert(&key, &value);
        self.changes
            .increment(1)
            .expect("one stable operation per slice");
    }

    #[msg(local)]
    fn local_write(&mut self, key: u64, value: u64) -> u64 {
        self.private = value;
        self.derived = self.linear;
        self.local_rows.insert(&key, &value);
        let _ = self.committed.get(&key);
        self.private
    }

    #[msg]
    fn shared_query(&self, key: u64) -> u64 {
        self.committed.get(&key).unwrap_or(self.namespace) + self.changes.value() as u64
    }

    #[msg(local_query)]
    fn local_query(&self, key: u64) -> u64 {
        self.local_rows.get(&key).unwrap_or(self.private)
    }
}

#[cfg(feature = "valid")]
#[test]
fn merge_message_codec_is_generated() {
    let installation = vos::value::Args::new().with("namespace", 7u64).encode();
    let actor = LaneSurface::__vos_create_with_args(&installation);
    assert_eq!(actor.namespace, 7);

    fn require<T: vos::agent::schema::AfterCommitMergeMessage<LaneSurface>>() {}
    require::<MergeWrite>();
    let message = <MergeWrite as vos::agent::schema::AfterCommitMergeMessage<LaneSurface>>::into_dynamic(
        MergeWrite { key: 1, value: 2 },
    );
    assert_eq!(message.name, "merge_write");
}
