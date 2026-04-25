use core::fmt;

pub use zkpvm_derive::{AirColumn, PreprocessedAirColumn};

pub mod empty;

/// Trait used for column indexing during constraints evaluation and trace generation.
pub trait AirColumn: 'static + Copy + fmt::Debug {
    /// Total number of columns in the trace.
    const COLUMNS_NUM: usize;

    /// Static slice of all enum variants.
    const ALL_VARIANTS: &'static [Self];

    /// Returns the number of columns corresponding to the variant.
    fn size(self) -> usize;

    /// Returns the starting offset for the variant.
    fn offset(self) -> usize;

    /// Returns `true` if the column requires mask values at the offset [0, 1].
    fn mask_next_row(self) -> bool;
}

/// An extension of [`AirColumn`] for preprocessed columns with unique identifiers.
pub trait PreprocessedAirColumn: AirColumn {
    /// Static slice of all preprocessed columns identifiers.
    const PREPROCESSED_IDS: &'static [&'static str];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preprocessed_prefix_derive() {
        #[derive(Debug, Copy, Clone, PreprocessedAirColumn)]
        #[preprocessed_prefix = "abc"]
        enum Test {
            #[size = 4]
            A,
            #[size = 5]
            B,
            #[size = 6]
            C,
        }

        assert!(Test::PREPROCESSED_IDS
            .iter()
            .all(|id| id.starts_with("abc")));
    }
}
