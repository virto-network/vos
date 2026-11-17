//! Why a device program is not made, a run of it not proved, or a proof of
//! it refused. Every variant is value-free by construction, so any may be
//! logged: none holds a value of a run, its witness, its trace or its
//! proof. A program's own numbers (a format's, a chip's index and the log
//! size its public reference run needs) are not a run's; no witness path
//! returns one.

/// Why a device program is not made, or a run of it not proved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No device format of the number in this build ([`crate::FORMATS`]):
    /// the app or the node must update.
    Format(u32),
    /// The program a release artifact names is not the one its kernel,
    /// chips and log sizes make: another id.
    IdMismatch,
    /// The kernel is not a standard program, its code does not decode, or
    /// its layout's regions overlap.
    Layout,
    /// The chips a release artifact names are not the ones the kernel's
    /// code reaches.
    Chips,
    /// A run does not reach its halt within its gas, or its output is not
    /// readable where its registers name it: the kernel's, or the reference
    /// program's.
    Halt,
    /// The arguments are not the ones the run reads: past the witness
    /// input's cap, or not read whole.
    Arguments,
    /// The reference program returns more than the arguments alone.
    Reference,
    /// The reference run does not trace over the device chips.
    Trace,
    /// A log size more or fewer than the program's chips.
    Sizes,
    /// Chip `chip` (its index in `DEVICE_ORDER`) under its floor.
    Floor { chip: usize },
    /// Chip `chip` (its index in `DEVICE_ORDER`) at log size `needs`,
    /// past the device format's ceiling (`DEVICE_MAX_LOG_SIZE`).
    Ceiling { chip: usize, needs: u32 },
    /// The format's masking does not fit the chips.
    Masking,
    /// A run past the program's shape: a witness that does not fit it
    /// (`light-node.md` §4.4). Which chip, and by how much, depends on the
    /// witness, and is not said.
    Fit,
    /// The run's trace breaks a constraint of the device AIR: a kernel the
    /// chips do not prove as it ran, which no attempt passes.
    Unsatisfied,
    /// The prover failed: Stwo refused otherwise, R1 refused every
    /// attempt's masks, or the operating system's randomness is
    /// unavailable. Another attempt may pass.
    Prove,
}

impl Error {
    /// Whether the failure is the kernel's own, failing every time for its
    /// bytes, as against the prover's, which another attempt may pass, or
    /// the build's (a format it does not prove).
    pub fn is_of_the_kernel(&self) -> bool {
        match self {
            Self::IdMismatch
            | Self::Layout
            | Self::Chips
            | Self::Halt
            | Self::Arguments
            | Self::Reference
            | Self::Trace
            | Self::Sizes
            | Self::Floor { .. }
            | Self::Ceiling { .. }
            | Self::Masking
            | Self::Fit
            | Self::Unsatisfied => true,
            Self::Format(_) | Self::Prove => false,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format(number) => write!(f, "no device format {number} in this build"),
            Self::IdMismatch => f.write_str("the release's program id is not its program's"),
            Self::Layout => f.write_str("the kernel is not a standard program"),
            Self::Chips => f.write_str("the chips are not the kernel's code's"),
            Self::Halt => f.write_str("the run does not halt within its gas"),
            Self::Arguments => f.write_str("the arguments are not the ones the run reads"),
            Self::Reference => f.write_str("the reference returns no arguments alone"),
            Self::Trace => f.write_str("the reference run does not trace over the device chips"),
            Self::Sizes => f.write_str("a log size more or fewer than the chips"),
            Self::Floor { chip } => write!(f, "chip {chip} under its floor"),
            Self::Ceiling { chip, needs } => {
                write!(
                    f,
                    "chip {chip} at log size {needs}, past the device format's"
                )
            }
            Self::Masking => f.write_str("the format's masking does not fit the chips"),
            Self::Fit => f.write_str("the run does not fit the program's shape"),
            Self::Unsatisfied => f.write_str("the run breaks a constraint of the device AIR"),
            Self::Prove => f.write_str("the prover failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Why a device proof's bytes are refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Longer than [`crate::MAX_PROOF_BYTES`].
    Length,
    /// Not exactly one proof's encoding: it does not decode, holds bytes
    /// after it, or is not its canonical form.
    Decode,
    /// Of another format, configuration or log sizes than the program's.
    Format,
    /// The interaction PoW nonce falls short.
    InteractionPow,
    /// A field element out of its range.
    Noncanonical,
    /// Its trees, samples or FRI layers are not the program's shape.
    Shape,
    /// Of another program: its preprocessed root.
    Program,
    /// Its claimed sums do not cancel, or the io-hash's is not the one the
    /// claim fixes.
    Logup,
    /// The STARK does not verify.
    Stark,
}

impl Refusal {
    /// The device refusal of the masked verifier's `error`.
    pub(crate) fn of(error: vos_pvm_final_verifier::Error) -> Self {
        use vos_pvm_final_verifier::Error;
        match error {
            Error::Length => Self::Length,
            Error::Decode => Self::Decode,
            Error::Format => Self::Format,
            Error::InteractionPow => Self::InteractionPow,
            Error::Noncanonical => Self::Noncanonical,
            Error::Shape(_) | Error::PublicWords => Self::Shape,
            Error::Circuit => Self::Program,
            Error::Logup => Self::Logup,
            Error::Stark(_) => Self::Stark,
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Length => "the bytes are longer than a device proof",
            Self::Decode => "the bytes are not one device proof",
            Self::Format => "the proof is not of the program's format",
            Self::InteractionPow => "the interaction PoW nonce falls short",
            Self::Noncanonical => "the proof holds a value out of its field",
            Self::Shape => "the proof's shape is not the program's",
            Self::Program => "the proof is of another program",
            Self::Logup => "the claimed sums do not cancel against the claim",
            Self::Stark => "the STARK does not verify",
        })
    }
}

impl std::error::Error for Refusal {}
