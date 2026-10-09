use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: u64,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self { value: 0 }
    }

    #[msg]
    pub async fn bump(&mut self) -> u64 {
        self.value += 1;
        self.value
    }

    /// A query may call only queries: `bump` is a command.
    #[msg]
    pub async fn sneaky(&self, ctx: &Query<Self>) -> u64 {
        ctx.call(Ref::<Counter>::new(InstanceId(1)), counter::Bump {})
            .await
            .unwrap_or(0)
    }
}

fn main() {}
