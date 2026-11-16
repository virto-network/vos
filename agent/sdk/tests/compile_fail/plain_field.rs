use vos_sdk::prelude::*;

/// An actor's state is its rows: a value in the struct is refused, a
/// `Cell<u64>` taken.
#[actor]
pub struct Counter {
    value: u64,
}

#[messages]
impl Counter {
    #[msg]
    pub async fn value(&self) -> u64 {
        self.value
    }
}

fn main() {}
