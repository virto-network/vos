//! Why a run of the agent program produced nothing.

use vos_pvm::ExitReason;
use vos_wire::Decode;

/// Why a batch, an apply, a query or a merge produced nothing.
#[derive(Debug)]
pub enum Fault {
    /// The agent program trapped, ran out of gas or answered nonsense:
    /// something in the batch may cause it.
    Agent(String),
    /// The host failed: a read, a backend or an executor. No input causes
    /// it, and it may pass.
    Infrastructure(String),
    /// A commit failed. fjall then refuses every later commit, so the host
    /// stops.
    Storage(String),
    /// The agent's state disagrees with its leader's: that agent stops.
    Invariant(String),
}

impl Fault {
    pub fn message(&self) -> &str {
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

/// How a run stopped, by its kind alone: a page fault's address may follow
/// the run's values, and a fault's text reaches the log and a query's
/// answer.
pub fn stopped(exit: &ExitReason) -> &'static str {
    match exit {
        ExitReason::Halt => "a halt",
        ExitReason::Panic => "a panic",
        ExitReason::OutOfGas => "out of gas",
        ExitReason::PageFault(_) => "a page fault",
        ExitReason::HostCall(_) => "a host call",
    }
}

/// Decode the agent program's output as `T`.
pub fn decode<T: Decode>(bytes: &[u8]) -> Result<T, Fault> {
    T::decode(bytes)
        .map(|(value, _)| value)
        .map_err(|_| Fault::Agent("its output does not decode".into()))
}

/// What a caught panic said, for a log or an answer: its message when it
/// is a literal, and never a formatted one, as an assertion's values or an
/// error's may be a run's. Neither names the place. Standard error is
/// another carrier: outside a proof the default hook prints the place and
/// the whole message there.
pub fn panic_message(panic: &(dyn std::any::Any + Send)) -> &'static str {
    panic
        .downcast_ref::<&'static str>()
        .copied()
        .unwrap_or("its message withheld")
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
        let Err(fault) = decode::<(u64, u64)>(&[0x5e]) else {
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
        assert_eq!(panic_message(&*formatted), "its message withheld");
        let literal = catch_unwind(|| panic!("a literal")).unwrap_err();
        assert_eq!(panic_message(&*literal), "a literal");
    }
}
