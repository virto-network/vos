//! A shared board whose field types declare their merge behavior explicitly.

use vos::prelude::*;

#[actor(crdt)]
pub struct Board {
    title: crdt::Value<String>,
    tasks: crdt::Map<u64, String>,
    order: crdt::List<u64>,
    notes: crdt::Text,
    edits: crdt::Counter,

    #[crdt(const)]
    space: [u8; 32],

    #[crdt(skip)]
    cached_summary: Option<String>,
}

#[messages]
impl Board {
    fn new() -> Self {
        Self {
            title: crdt::Value::default(),
            tasks: crdt::Map::default(),
            order: crdt::List::default(),
            notes: crdt::Text::default(),
            edits: crdt::Counter::default(),
            space: [0; 32],
            cached_summary: None,
        }
    }

    #[msg]
    fn set_title(&mut self, title: String) {
        self.title
            .set(title)
            .expect("one stable operation per slice");
    }

    #[msg]
    fn add_task(&mut self, id: u64, text: String) {
        self.tasks
            .insert(id, text)
            .expect("one stable operation per slice");
        self.order.push(id).expect("one stable operation per slice");
        self.edits
            .increment(1)
            .expect("one stable operation per slice");
    }

    #[msg]
    fn insert_note(&mut self, index: u32, text: String) {
        self.notes
            .insert(index as usize, &text)
            .expect("one stable operation per slice");
        self.edits
            .increment(1)
            .expect("one stable operation per slice");
    }

    #[msg]
    fn edit_count(&self) -> i64 {
        self.edits.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_replicas_merge_map_list_text_and_counter_changes() {
        let left_change = crdt::ChangeId([1; 32]);
        let right_change = crdt::ChangeId([2; 32]);
        let mut left = Board::new();
        let mut right = Board::new();

        left.tasks
            .insert_with_id(left_change.operation(0), 1, "write".into())
            .unwrap();
        left.order
            .push_with_id(left_change.operation(1), 1)
            .unwrap();
        left.notes.insert_with_change(0, left_change, "A").unwrap();
        left.edits
            .increment_with_id(left_change.operation(3), 1)
            .unwrap();

        right
            .tasks
            .insert_with_id(right_change.operation(0), 2, "review".into())
            .unwrap();
        right
            .order
            .push_with_id(right_change.operation(1), 2)
            .unwrap();
        right
            .notes
            .insert_with_change(0, right_change, "B")
            .unwrap();
        right
            .edits
            .increment_with_id(right_change.operation(3), 1)
            .unwrap();

        let mut left_first: Board = vos::Decode::decode(&left.encode());
        <Board as vos::Actor>::__merge_crdt(&mut left_first, &right).unwrap();
        let mut right_first: Board = vos::Decode::decode(&right.encode());
        <Board as vos::Actor>::__merge_crdt(&mut right_first, &left).unwrap();

        assert_eq!(left_first.tasks.get(&1).map(String::as_str), Some("write"));
        assert_eq!(left_first.tasks.get(&2).map(String::as_str), Some("review"));
        assert_eq!(left_first.edits.value(), 2);
        assert_eq!(left_first.notes.as_string(), right_first.notes.as_string());
        assert_eq!(
            left_first.order.iter().copied().collect::<Vec<_>>(),
            right_first.order.iter().copied().collect::<Vec<_>>()
        );
    }
}
