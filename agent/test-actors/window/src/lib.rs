//! An actor that states settlement windows: its attestable method checks a
//! space's pseudo-account rows against the committed-map roots of a window's
//! two anchors, by a vos-tree multiproof each, checked from its encoding as
//! it is read (`vos_tree::verify_encoded`), then runs
//! `cipher_clerk::settlement::window` over them. The kernel derived from it
//! is what a proof of a window proves.
//!
//! A row is keyed by its account's id under the hashed transform
//! (`vos_tree::keys::hashed`), and its value is cipher-clerk's encoding of
//! the account. The tree hashes through the BLAKE2b compression precompile;
//! cipher-clerk derives the pseudo-accounts' ids with the `blake2` crate.

#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use cipher_clerk::codec;
use cipher_clerk::kernel::Value;
use cipher_clerk::settlement::{Anchor, NetFlow, Reads};
use cipher_clerk::types::Account;
use vos_sdk::prelude::*;
use vos_tree::{Blake2b, Hash, Salt, keys};

/// A value does not decode.
pub const MALFORMED: u8 = 1;
/// The rows are not in strictly increasing key order.
pub const UNORDERED: u8 = 2;
/// The proof at the first anchor refuses the rows.
pub const REFUSED_I: u8 = 3;
/// The proof at the second anchor refuses the rows.
pub const REFUSED_J: u8 = 4;
/// `window` refused the rows: this plus its error's index.
pub const WINDOW: u8 = 16;

/// A row as a version of the tree holds it: its leaf's salt and its value.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Read {
    pub salt: Salt,
    pub value: Vec<u8>,
}

/// One pseudo-account's rows at the window's anchors: at the first unless
/// the account was created inside the window, and at the second. Rows come
/// in their keys' order.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Row {
    pub at_i: Option<Read>,
    pub at_j: Read,
}

#[actor]
pub struct Window {
    statements: u64,
}

#[messages]
impl Window {
    pub fn new() -> Self {
        Self { statements: 0 }
    }

    /// Attest the window over the witnessed rows: the kernel's output.
    #[msg(gas = 100_000_000)]
    #[allow(clippy::too_many_arguments)]
    pub async fn state(
        &mut self,
        ctx: &mut Command<Self>,
        space: [u8; 32],
        window_i: u64,
        root_i: [u8; 32],
        window_j: u64,
        root_j: [u8; 32],
        rows: Vec<Row>,
        proof_i: Vec<u8>,
        proof_j: Vec<u8>,
    ) -> Vec<u8> {
        let output = ctx
            .attest(window::Settle {
                space,
                window_i,
                root_i,
                window_j,
                root_j,
                rows,
                proof_i,
                proof_j,
            })
            .await
            .unwrap_or_default();
        self.statements += 1;
        output
    }

    /// The window statement over the rows, each anchor's proof a
    /// `vos_tree::BatchProof`'s encoding: a status byte, `0` followed by the
    /// `NetFlow`'s encoding, or why there is none.
    #[attestable]
    #[allow(clippy::too_many_arguments)]
    pub fn settle(
        space: [u8; 32],
        window_i: u64,
        root_i: [u8; 32],
        window_j: u64,
        root_j: [u8; 32],
        rows: Vec<Row>,
        proof_i: Vec<u8>,
        proof_j: Vec<u8>,
    ) -> Vec<u8> {
        let anchor_i = Anchor {
            window: window_i,
            root: root_i,
        };
        let anchor_j = Anchor {
            window: window_j,
            root: root_j,
        };
        match statement(space, anchor_i, anchor_j, &rows, &proof_i, &proof_j) {
            Ok(flow) => {
                let mut out = vec![0];
                out.extend_from_slice(&codec::to_bytes(&flow));
                out
            }
            Err(status) => vec![status],
        }
    }
}

/// A read's account, and the claim its key's leaf makes: the commitment
/// to its value under its salt.
fn account(read: &Read) -> Result<(Account<Value>, Hash), u8> {
    let account = codec::from_bytes::<Account<Value>>(&read.value).ok_or(MALFORMED)?;
    Ok((
        account,
        vos_tree::value_hash(&Blake2b, &read.salt, &read.value),
    ))
}

/// The window statement over the rows, each checked against its anchor's
/// root: present at the second anchor, and at the first, or absent there.
fn statement(
    space: [u8; 32],
    anchor_i: Anchor,
    anchor_j: Anchor,
    rows: &[Row],
    proof_i: &[u8],
    proof_j: &[u8],
) -> Result<NetFlow, u8> {
    let mut keys = Vec::with_capacity(rows.len());
    let mut commitments = Vec::with_capacity(rows.len());
    let mut reads = Vec::with_capacity(rows.len());
    for row in rows {
        let (at_j, commitment_j) = account(&row.at_j)?;
        let (at_i, commitment_i) = match &row.at_i {
            Some(read) => {
                let (at_i, commitment_i) = account(read)?;
                (Some(at_i), Some(commitment_i))
            }
            None => (None, None),
        };
        keys.push(keys::hashed(&Blake2b, &at_j.id.0));
        commitments.push((commitment_i, commitment_j));
        reads.push(Reads { at_i, at_j });
    }
    if !keys.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(UNORDERED);
    }
    let claims = |at: fn(&(Option<Hash>, Hash)) -> Option<Hash>| -> Vec<(&[u8], Option<Hash>)> {
        keys.iter()
            .zip(&commitments)
            .map(|(key, commitment)| (key.as_slice(), at(commitment)))
            .collect()
    };
    vos_tree::verify_encoded(
        &Blake2b,
        proof_i,
        &anchor_i.root,
        &claims(|(at_i, _)| *at_i),
    )
    .map_err(|_| REFUSED_I)?;
    vos_tree::verify_encoded(
        &Blake2b,
        proof_j,
        &anchor_j.root,
        &claims(|(_, at_j)| Some(*at_j)),
    )
    .map_err(|_| REFUSED_J)?;
    cipher_clerk::settlement::window(space, anchor_i, anchor_j, &reads)
        .map_err(|error| WINDOW + error as u8)
}
