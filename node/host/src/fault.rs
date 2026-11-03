//! Why a batch, an apply or a query produced nothing ([`vos_exec::Fault`]),
//! and the applied state's reads that fail with it.

use vos_wire::Decode;
use vos_wire::ids::AgentId;
use vos_wire::records::unstored;

use crate::executor::Panicked;
use crate::store::Snapshot;

pub(crate) use vos_exec::Fault;

/// A root builder's error, as the leader's fault.
impl From<crate::roots::Error> for Fault {
    fn from(error: crate::roots::Error) -> Self {
        Fault::Infrastructure(format!("a cut's proofs: {error}"))
    }
}

/// A panic on an executor is the node's fault.
impl From<Panicked> for Fault {
    fn from(panicked: Panicked) -> Self {
        Fault::Infrastructure(format!("panicked: {}", panicked.0))
    }
}

/// A value of an agent's applied state; `None` when absent or unreadable.
pub(crate) fn read<T: Decode>(
    snapshot: &Snapshot,
    agent: AgentId,
    key: &[u8],
) -> Result<Option<T>, Fault> {
    let bytes = snapshot.get(agent, key)?;
    Ok(bytes.and_then(|bytes| T::decode(unstored(&bytes)?).ok().map(|(value, _)| value)))
}

#[cfg(test)]
mod tests {
    use std::panic::catch_unwind;

    use super::*;

    /// A panic on an executor is a fault that keeps only a literal message.
    #[test]
    fn an_executor_panic_keeps_only_a_literal_message() {
        let secret = 0x5eed_u32;
        let formatted = catch_unwind(|| panic!("a value {secret}")).unwrap_err();
        let fault = Fault::from(Panicked(crate::panic_message(&*formatted)));
        assert_eq!(fault.message(), "panicked: its message withheld");
    }
}
