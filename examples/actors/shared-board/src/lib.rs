//! A shared board whose field types declare their merge behavior explicitly.

use vos::prelude::*;

/// Board-local permissions. Viewers may read and contribute mergeable work;
/// moderators additionally control the linear title.
#[derive(
    vos::rkyv::Archive,
    vos::rkyv::Serialize,
    vos::rkyv::Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
#[rkyv(crate = vos::rkyv)]
#[repr(u8)]
pub enum BoardRole {
    Viewer = 0,
    Moderator = 1,
}

impl vos::RoleByte for BoardRole {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Viewer),
            1 => Some(Self::Moderator),
            _ => None,
        }
    }

    fn as_byte(self) -> u8 {
        self as u8
    }
}

const BOARD_SPACE_ROLE_MAP: vos::SpaceRoleMap<BoardRole> = vos::SpaceRoleMap {
    admin: Some(BoardRole::Moderator),
    developer: Some(BoardRole::Moderator),
    member: Some(BoardRole::Viewer),
    guest: Some(BoardRole::Viewer),
};

#[actor(
    role = BoardRole,
    default_role = BoardRole::Viewer,
    space_role_map = BOARD_SPACE_ROLE_MAP
)]
pub struct Board {
    title: String,
    tasks: crdt::Map<u64, String>,
    order: crdt::List<u64>,
    notes: crdt::Text,
    edits: crdt::Counter,
}

fn bounded_note_index(index: u32, len: usize) -> usize {
    core::cmp::min(index as usize, len)
}

#[messages]
impl Board {
    fn new() -> Self {
        Self {
            title: String::new(),
            tasks: crdt::Map::default(),
            order: crdt::List::default(),
            notes: crdt::Text::default(),
            edits: crdt::Counter::default(),
        }
    }

    #[msg(linear, role = BoardRole::Moderator)]
    fn set_title(&mut self, title: String) {
        self.title = title;
    }

    #[msg]
    fn title(&self) -> String {
        self.title.clone()
    }

    #[msg(merge)]
    fn add_task(&mut self, id: u64, text: String) -> String {
        self.tasks
            .insert(id, text)
            .expect("one stable operation per slice");
        self.order.push(id).expect("one stable operation per slice");
        self.edits
            .increment(1)
            .expect("one stable operation per slice");
        // Merge handlers see the pinned Linear snapshot selected by the
        // agent, so causal work can be interpreted against ordered policy or
        // configuration without moving that configuration into the CRDT.
        self.title.clone()
    }

    #[msg(merge)]
    fn insert_note(&mut self, index: u32, text: String) {
        let index = bounded_note_index(index, self.notes.len());
        self.notes
            .insert(index, &text)
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

    #[test]
    fn note_index_past_the_end_appends() {
        assert_eq!(bounded_note_index(u32::MAX, 4), 4);
        assert_eq!(bounded_note_index(2, 4), 2);
    }
}
