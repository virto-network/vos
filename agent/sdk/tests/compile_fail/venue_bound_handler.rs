use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    #[msg(venue_bound)]
    pub async fn add(&mut self, by: u64) -> u64 {
        self.value.set(&(self.value.get_or_default() + by));
        self.value.get_or_default()
    }
}

fn main() {}
