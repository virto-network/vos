use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    entries: CommittedMap<u32, u64>,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self {
            entries: CommittedMap::default(),
        }
    }

    /// A rootless method reads no rows at a cut.
    #[workflow]
    pub async fn read(ctx: &mut Workflow<Self>, by: u64) -> Result<u64, AttestError> {
        ctx.attest_at_cut(counter::Double { by }).await
    }

    #[attestable]
    pub fn double(by: u64) -> u64 {
        by * 2
    }
}

fn main() {}
