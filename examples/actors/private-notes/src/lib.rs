//! Merge-only notes suitable for a Private Agent.
//!
//! Encryption, owner-node admission, revocation, and epoch rotation belong to
//! the Private Agent host. The actor sees ordinary plaintext only while it is
//! executing; its durable fields are all CRDT values and therefore require no
//! Linear lane.

use vos::prelude::*;

#[actor(agent)]
pub struct PrivateNotes {
    notes: crdt::Map<u64, String>,
    edits: crdt::Counter,
}

#[messages(agent)]
impl PrivateNotes {
    fn new() -> Self {
        Self {
            notes: crdt::Map::default(),
            edits: crdt::Counter::default(),
        }
    }

    #[msg(merge)]
    fn put(&mut self, id: u64, text: String) {
        self.notes
            .insert(id, text)
            .expect("one stable note operation per invocation");
        self.edits
            .increment(1)
            .expect("one stable edit operation per invocation");
    }

    #[msg(merge)]
    fn remove(&mut self, id: u64) -> bool {
        let removed = self
            .notes
            .remove(&id)
            .expect("one stable note operation per invocation");
        if removed {
            self.edits
                .increment(1)
                .expect("one stable edit operation per invocation");
        }
        removed
    }

    #[msg(query)]
    fn note(&self, id: u64) -> String {
        self.notes.get(&id).cloned().unwrap_or_default()
    }

    #[msg(query)]
    fn edit_count(&self) -> i64 {
        self.edits.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_notes_converge_without_a_linear_lane() {
        let mut left = PrivateNotes::new();
        let mut right = PrivateNotes::new();

        left.notes
            .insert_with_id(crdt::ChangeId([1; 32]).operation(0), 1, "left".into())
            .unwrap();
        left.edits
            .increment_with_id(crdt::ChangeId([1; 32]).operation(1), 1)
            .unwrap();
        right
            .notes
            .insert_with_id(crdt::ChangeId([2; 32]).operation(0), 2, "right".into())
            .unwrap();
        right
            .edits
            .increment_with_id(crdt::ChangeId([2; 32]).operation(1), 1)
            .unwrap();

        let mut left_first: PrivateNotes = vos::Decode::decode(&left.encode());
        <PrivateNotes as vos::Actor>::__merge_crdt(&mut left_first, &right).unwrap();
        let mut right_first: PrivateNotes = vos::Decode::decode(&right.encode());
        <PrivateNotes as vos::Actor>::__merge_crdt(&mut right_first, &left).unwrap();

        assert_eq!(left_first.notes.get(&1).map(String::as_str), Some("left"));
        assert_eq!(left_first.notes.get(&2).map(String::as_str), Some("right"));
        assert_eq!(left_first.edits.value(), 2);
        assert_eq!(left_first.encode(), right_first.encode());
    }
}
