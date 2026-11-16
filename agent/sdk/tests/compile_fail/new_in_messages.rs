use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    /// A new instance has no rows: nothing a `new()` could set.
    pub fn new() -> Self {
        Self {
            value: Cell::default(),
        }
    }

    #[msg]
    pub async fn value(&self) -> u64 {
        self.value.get_or_default()
    }
}

fn main() {}
