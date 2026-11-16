use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    #[msg]
    pub async fn peek(&self, ctx: &mut Command<Self>) -> u64 {
        self.value.get_or_default()
    }
}

fn main() {}
