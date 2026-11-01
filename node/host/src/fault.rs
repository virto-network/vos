//! Why a batch, an apply or a query produced nothing, and the applied
//! state's reads that fail with it.

use vos_pvm::ExitReason;
use vos_wire::Decode;
use vos_wire::ids::AgentId;
use vos_wire::records::unstored;

use crate::executor::Panicked;
use crate::store::Snapshot;

/// Why a batch produced nothing.
#[derive(Debug)]
pub(crate) enum Fault {
    /// The agent program trapped, ran out of gas or answered nonsense:
    /// something in the batch may cause it.
    Agent(String),
    /// The node failed: a read, a backend or an executor. No input causes
    /// it, and it may pass.
    Infrastructure(String),
    /// A commit failed. fjall then refuses every later commit, so the node
    /// stops.
    Storage(String),
    /// The agent's state disagrees with its leader's: that agent stops.
    Invariant(String),
}

impl Fault {
    pub(crate) fn message(&self) -> &str {
        match self {
            Fault::Agent(message)
            | Fault::Infrastructure(message)
            | Fault::Storage(message)
            | Fault::Invariant(message) => message,
        }
    }
}

impl From<vos_pvm::refine::RefineError> for Fault {
    fn from(error: vos_pvm::refine::RefineError) -> Self {
        Fault::Infrastructure(format!("{error:?}"))
    }
}

impl From<fjall::Error> for Fault {
    fn from(error: fjall::Error) -> Self {
        Fault::Infrastructure(error.to_string())
    }
}

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

/// How a run stopped, by its kind alone: a page fault's address may follow
/// the run's values, and a fault's text reaches the log and a query's
/// answer.
pub(crate) fn stopped(exit: &ExitReason) -> &'static str {
    match exit {
        ExitReason::Halt => "a halt",
        ExitReason::Panic => "a panic",
        ExitReason::OutOfGas => "out of gas",
        ExitReason::PageFault(_) => "a page fault",
        ExitReason::HostCall(_) => "a host call",
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

    /// A fault's text names how a run stopped, never a page fault's address
    /// or a host call's number.
    #[test]
    fn a_stop_is_named_by_its_kind_alone() {
        for exit in [
            ExitReason::PageFault(0x5eed_f000),
            ExitReason::HostCall(0x5eed),
        ] {
            let text = Fault::Agent(format!("refine stopped: {}", stopped(&exit)))
                .message()
                .to_string();
            assert!(!text.contains("5eed"), "{text}");
            assert!(!text.contains(&0x5eed_f000u32.to_string()), "{text}");
        }
    }

    /// An output that does not decode is named so, none of its bytes.
    #[test]
    fn an_undecodable_output_names_none_of_its_bytes() {
        let Err(fault) = crate::pvm::decode::<(u64, u64)>(&[0x5e]) else {
            panic!("one byte decodes as two numbers");
        };
        assert_eq!(fault.message(), "its output does not decode");
    }

    /// A caught panic's formatted message is withheld; a literal one is
    /// kept.
    #[test]
    fn a_formatted_panic_message_is_withheld() {
        let secret = 0x5eed_u32;
        let formatted = catch_unwind(|| panic!("a value {secret}")).unwrap_err();
        let fault = Fault::from(Panicked(crate::panic_message(&*formatted)));
        assert_eq!(fault.message(), "panicked: its message withheld");
        let literal = catch_unwind(|| panic!("a literal")).unwrap_err();
        assert_eq!(crate::panic_message(&*literal), "a literal");
    }
}
