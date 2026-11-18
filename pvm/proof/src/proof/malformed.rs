//! Why the segment verifier refuses a proof before its STARK is checked:
//! its format, its structure against the protocol's bounds, its
//! dimensions against the AIR, its query positions, its interaction PoW,
//! its security count. Value-free by construction but for the security
//! count's numbers, which are the format's and the proof's parameters, a
//! public configuration: no variant holds a value of a run.

use crate::format::Refused;

/// Why a segment proof is refused before its STARK is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Malformed {
    /// The proof's format is refused: its number, and why.
    Format { number: u32, refused: Refused },
    /// The Stark proof is on another channel than its format's.
    Channel,
    /// The component count is outside the protocol's bounds.
    Components,
    /// The components', log sizes' and claimed sums' counts differ.
    Lengths,
    /// A log size outside the protocol's bounds.
    LogSize,
    /// The outer and the embedded PCS configurations differ.
    Config,
    /// FRI's log blowup is outside Stwo's 1..=16.
    Blowup,
    /// FRI's last-layer degree bound exceeds 10.
    LastLayerBound,
    /// FRI's fold step is not the protocol's, 1.
    FoldStep,
    /// FRI's query count is outside its bounds.
    Queries,
    /// The PCS's proof-of-work bits exceed 31.
    PowBits,
    /// The extended trace's log size exceeds the protocol's bound.
    ExtendedLogSize,
    /// The lifting log size does not cover the trace or the composition
    /// within the protocol's bound, or is not the AIR's.
    Lifting,
    /// Not the protocol's four commitment trees.
    Trees,
    /// A tree's columns, sampled or queried, past the protocol's bound or
    /// other than the AIR's.
    Columns,
    /// A column's samples past the protocol's bound or other than the
    /// AIR's mask.
    Samples,
    /// Queried values past FRI's queries, of uneven rows, or none.
    QueriedValues,
    /// A trace Merkle witness past the protocol's bound.
    MerkleWitness,
    /// FRI's inner layers past the protocol's bound or other than the
    /// composition's folds.
    FriLayers,
    /// A FRI layer's witness past the protocol's bound.
    FriWitness,
    /// The proof's nested payload past its bound.
    Payload,
    /// FRI's last layer of another length than its degree bound's.
    LastLayer,
    /// A noncanonical M31 limb.
    Noncanonical,
    /// The composition's degree cannot be split, lifted or folded.
    Composition,
    /// The AIR's layout of the trees is not the protocol's.
    Layout,
    /// The queried rows are not the Fiat–Shamir query positions.
    QueryPositions,
    /// Duplicate preprocessed query positions carry different values.
    PreprocessedQueries,
    /// The interaction PoW nonce falls short.
    InteractionPow,
    /// The proof's security count falls short, or its parameters are not
    /// its format's.
    Security(SecurityError),
}

/// Why a proof's parameters are refused by its format's security floors.
/// Its numbers are the format's and the proof's configuration's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecurityError {
    /// The parameters are outside the security analysis.
    Outside,
    /// The conjectured count, `bits`, below format `format`'s `floor`.
    Conjectured { format: u32, bits: u32, floor: u32 },
    /// The proven count, `bits`, below format `format`'s `floor`.
    Proven { format: u32, bits: u32, floor: u32 },
    /// The proof's parameters are not format `format`'s.
    Parameters { format: u32 },
}

impl core::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Outside => f.write_str("parameters outside the security analysis"),
            Self::Conjectured {
                format,
                bits,
                floor,
            } => write!(
                f,
                "proof counts {bits} conjectured bits, below format {format}'s floor of {floor}"
            ),
            Self::Proven {
                format,
                bits,
                floor,
            } => write!(
                f,
                "proof counts {bits} proven bits, below format {format}'s floor of {floor}"
            ),
            Self::Parameters { format } => {
                write!(f, "proof parameters differ from format {format}'s")
            }
        }
    }
}

impl core::error::Error for SecurityError {}

impl core::fmt::Display for Malformed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let reason = match self {
            Self::Format { number, refused } => {
                return write!(f, "proof format {number} {refused}");
            }
            Self::Security(error) => return error.fmt(f),
            Self::Channel => "the proof's Stark proof is on another channel than its format's",
            Self::Components => "proof component cardinality is outside protocol bounds",
            Self::Lengths => "proof component/log-size/claimed-sum lengths differ",
            Self::LogSize => "a proof log size is outside the protocol's bounds",
            Self::Config => "outer and embedded pcs_config differ",
            Self::Blowup => "FRI log blowup is outside Stwo's 1..=16 bound",
            Self::LastLayerBound => "FRI last-layer degree bound exceeds 10",
            Self::FoldStep => "FRI fold_step must equal the protocol value 1",
            Self::Queries => "FRI query count is outside its bounds",
            Self::PowBits => "PCS proof-of-work bits exceed the supported bound 31",
            Self::ExtendedLogSize => "the extended trace log size exceeds the protocol bound",
            Self::Lifting => "the PCS lifting log size is not the protocol's",
            Self::Trees => "the Stwo proof does not hold the protocol's commitment trees",
            Self::Columns => "a tree's column count is not the protocol's or the AIR's",
            Self::Samples => "a column's sample count is not the protocol's or the AIR mask's",
            Self::QueriedValues => "the queried values are not the configured queries'",
            Self::MerkleWitness => "trace Merkle witness exceeds protocol bound",
            Self::FriLayers => "the FRI inner-layer count is not the composition's",
            Self::FriWitness => "FRI layer witness exceeds protocol bound",
            Self::Payload => "the proof's nested payload exceeds its bound",
            Self::LastLayer => "the FRI last-layer polynomial is not its degree bound's length",
            Self::Noncanonical => "proof contains a noncanonical M31 field limb",
            Self::Composition => "the composition's degree does not split, lift or fold",
            Self::Layout => "the AIR-derived proof layout is not the protocol's",
            Self::QueryPositions => "queried-value rows differ from Fiat-Shamir query positions",
            Self::InteractionPow => "the interaction PoW nonce falls short",
            Self::PreprocessedQueries => {
                "duplicate preprocessed query positions carry different values"
            }
        };
        f.write_str(reason)
    }
}

impl core::error::Error for Malformed {}

impl From<Malformed> for stwo::core::verifier::VerificationError {
    fn from(refusal: Malformed) -> Self {
        Self::InvalidStructure(alloc::string::ToString::to_string(&refusal))
    }
}

impl From<SecurityError> for stwo::core::verifier::VerificationError {
    fn from(refusal: SecurityError) -> Self {
        Self::InvalidStructure(alloc::string::ToString::to_string(&refusal))
    }
}
