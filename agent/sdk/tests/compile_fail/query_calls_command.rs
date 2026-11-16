use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    value: Cell<u64>,
}

#[messages]
impl Counter {
    #[msg]
    pub async fn bump(&mut self) -> u64 {
        self.value.set(&(self.value.get_or_default() + 1));
        self.value.get_or_default()
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
