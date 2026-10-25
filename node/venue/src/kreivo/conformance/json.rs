//! The vectors' file as JSON: its schema, and how a step's bytes, deltas
//! and masked values are written in it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::{account_id, hex};
use crate::kreivo::mock::keys;
use crate::kreivo::mock::types::{DispatchError, PALLET_INDEX};
use crate::kreivo::mock::{Constants, Origin, Verdict};

/// The vectors' file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    pub about: Vec<String>,
    pub constants: ConstantsJson,
    /// Raw keys whose writes a harness leaves out of every step's storage:
    /// items the design lets a pallet keep that the mock does not
    /// (`PruneCursor`).
    pub unpinned: Vec<String>,
    /// Labels of the accounts and anchor keys the vectors use.
    pub names: BTreeMap<String, String>,
    pub vectors: Vec<Vector>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantsJson {
    pub pallet_index: u8,
    /// `twox128("Spaces")`.
    pub storage_prefix: String,
    pub pallet_id: String,
    pub venue: String,
    pub existential_deposit: String,
    pub registration_deposit: String,
    pub submit_deposit: String,
    pub fee_bound: String,
    pub default_spend_per_window: String,
    pub forfeit_to: String,
    pub program_change_delay_ms: u64,
    pub max_authorities: u8,
    pub max_anchor_keys: u8,
    pub max_genesis_len: usize,
    pub max_statement_len: usize,
    pub max_proof_len: usize,
}

impl ConstantsJson {
    pub(super) fn of(constants: &Constants) -> Self {
        Self {
            pallet_index: PALLET_INDEX,
            storage_prefix: hex(&keys::twox128(keys::PALLET)),
            pallet_id: String::from_utf8(constants.pallet_id.to_vec()).expect("ASCII"),
            venue: hex(&constants.venue.0),
            existential_deposit: constants.existential_deposit.to_string(),
            registration_deposit: constants.registration_deposit.to_string(),
            submit_deposit: constants.submit_deposit.to_string(),
            fee_bound: constants.fee_bound.to_string(),
            default_spend_per_window: constants.default_spend_per_window.to_string(),
            forfeit_to: hex(&constants.forfeit_to),
            program_change_delay_ms: constants.program_change_delay_ms,
            max_authorities: constants.max_authorities,
            max_anchor_keys: constants.max_anchor_keys,
            max_genesis_len: constants.bounds.genesis,
            max_statement_len: constants.bounds.statement,
            max_proof_len: constants.bounds.proof,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vector {
    pub id: String,
    pub title: String,
    /// Kreivo's runtime with `ChargeSpaceFee`, not the pallet's mock
    /// runtime.
    pub fees: bool,
    pub pre: Pre,
    pub steps: Vec<Step>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pre {
    pub now_ms: u64,
    pub accounts: Vec<AccountJson>,
    pub storage: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountJson {
    pub account: String,
    pub free: String,
    pub held_registration: String,
    pub held_submit: String,
    pub providers: u32,
    pub consumers: u32,
}

/// A raw storage entry; `None` a removal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub key: String,
    pub value: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginJson {
    Signed(#[serde(with = "account_hex")] [u8; 32]),
    Root,
    Programs,
    Emergency,
    Status,
}

mod account_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(account: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::hex(account))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        Ok(super::account_id(&String::deserialize(deserializer)?))
    }
}

impl From<Origin> for OriginJson {
    fn from(origin: Origin) -> Self {
        match origin {
            Origin::Signed(who) => Self::Signed(who),
            Origin::Root => Self::Root,
            Origin::Programs => Self::Programs,
            Origin::Emergency => Self::Emergency,
            Origin::Status => Self::Status,
        }
    }
}

impl From<OriginJson> for Origin {
    fn from(origin: OriginJson) -> Self {
        match origin {
            OriginJson::Signed(who) => Self::Signed(who),
            OriginJson::Root => Self::Root,
            OriginJson::Programs => Self::Programs,
            OriginJson::Emergency => Self::Emergency,
            OriginJson::Status => Self::Status,
        }
    }
}

/// A part of a call's bytes: hex, a range of a kit fixture file, or one
/// byte repeated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Part {
    Hex(String),
    Fixture {
        fixture: String,
        from: usize,
        to: usize,
    },
    Repeat {
        /// The byte, in hex.
        repeat: String,
        count: usize,
    },
}

/// The shortest run of one byte a call's parts write as [`Part::Repeat`].
const RUN: usize = 256;

/// `bytes` as parts: hex, each run of [`RUN`] or more of one byte a repeat.
pub(super) fn hex_parts(bytes: &[u8]) -> Vec<Part> {
    let mut out = Vec::new();
    let (mut at, mut plain) = (0, 0);
    while at < bytes.len() {
        let run = bytes[at..]
            .iter()
            .take_while(|byte| **byte == bytes[at])
            .count();
        if run >= RUN {
            if plain < at {
                out.push(Part::Hex(hex(&bytes[plain..at])));
            }
            let repeat = hex(&[bytes[at]]);
            assert_eq!(repeat.len(), 2, "a repeat of one byte");
            out.push(Part::Repeat { repeat, count: run });
            plain = at + run;
        }
        at += run;
    }
    if plain < bytes.len() || out.is_empty() {
        out.push(Part::Hex(hex(&bytes[plain..])));
    }
    out
}

/// A call's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultJson {
    Ok,
    /// `DispatchError::Module { index: 90, error: [i, 0, 0, 0] }`.
    Module(u8),
    BadOrigin,
    /// `DispatchError::Token(FundsUnavailable)`.
    FundsUnavailable,
    /// `InvalidTransaction::Payment`, in `validate`: never included.
    InvalidPayment,
    /// The call's bytes do not decode: never included.
    Undecodable,
}

impl From<&Verdict> for ResultJson {
    fn from(verdict: &Verdict) -> Self {
        match verdict {
            Verdict::Ok => Self::Ok,
            Verdict::Err(DispatchError::Module(error)) => Self::Module(error.error[0]),
            Verdict::Err(DispatchError::BadOrigin) => Self::BadOrigin,
            Verdict::Err(DispatchError::Token(_)) => Self::FundsUnavailable,
            Verdict::Payment => Self::InvalidPayment,
            Verdict::Undecodable => Self::Undecodable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub now_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call: Option<Vec<Part>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub on_idle: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ResultJson>,
    pub events: Vec<String>,
    pub storage: Vec<Entry>,
    pub balances: Vec<Delta>,
    /// Who paid the fee, in a `fees` vector: `sovereign` or `signer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
}

/// An account's balance deltas: exact (`+5`, `-5`), or by sign (`+`,
/// `-`, `0`) for a `fees` vector's free balance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    pub account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_registration: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_submit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<i64>,
}

pub(super) fn delta(before: u128, after: u128) -> Option<String> {
    match after.cmp(&before) {
        std::cmp::Ordering::Equal => None,
        std::cmp::Ordering::Greater => Some(format!("+{}", after - before)),
        std::cmp::Ordering::Less => Some(format!("-{}", before - after)),
    }
}

pub(super) fn sign(before: u128, after: u128) -> String {
    match after.cmp(&before) {
        std::cmp::Ordering::Equal => "0",
        std::cmp::Ordering::Greater => "+",
        std::cmp::Ordering::Less => "-",
    }
    .to_string()
}

/// A `Budget` value in a `fees` vector: its `window` in hex, its `spent`
/// (which sums the fees, Kreivo's weights) `?` for each nibble.
pub(super) fn masked_spend(value: &[u8]) -> String {
    let window = &value[..value.len().min(8)];
    format!(
        "{}{}",
        hex(window),
        "?".repeat(2 * value.len().saturating_sub(8))
    )
}
