//! An actor that states settlement windows: its attestable method runs
//! `cipher_clerk::settlement::window` over pseudo-account rows it checks
//! against the anchors' roots, so the kernel derived from it is what a
//! proof of a window proves.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

#[actor]
pub struct Settlements {
    statements: u64,
}

#[messages]
impl Settlements {
    pub fn new() -> Self {
        Self { statements: 0 }
    }

    /// Attest the window over the witnessed rows: the kernel's output.
    #[msg]
    #[allow(clippy::too_many_arguments)]
    pub async fn state(
        &mut self,
        ctx: &mut Command<Self>,
        space: [u8; 32],
        window_i: u64,
        root_i: [u8; 32],
        window_j: u64,
        root_j: [u8; 32],
        rows: Vec<u8>,
        proof_i: Vec<u8>,
        proof_j: Vec<u8>,
    ) -> Vec<u8> {
        let output = ctx
            .attest(settlements::Window {
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

    /// The window statement over pseudo-account rows read at two anchors,
    /// each row's vos-tree path checked against its anchor's root: a
    /// status byte, then the `NetFlow`'s encoding.
    #[attestable]
    #[allow(clippy::too_many_arguments)]
    pub fn window(
        space: [u8; 32],
        window_i: u64,
        root_i: [u8; 32],
        window_j: u64,
        root_j: [u8; 32],
        rows: Vec<u8>,
        proof_i: Vec<u8>,
        proof_j: Vec<u8>,
    ) -> Vec<u8> {
        window_kernel::settle(
            space, window_i, root_i, window_j, root_j, &rows, &proof_i, &proof_j,
        )
    }
}
