//! Experimental guest transport for state blocks. The state tree, not this
//! transport, authenticates returned bytes under its pinned scope/root.
//! Missing/unavailable blocks must never become successful absence responses.

#[cfg(any(target_arch = "riscv64", test))]
use crate::{state_blocks::BlockRef, state_tree::TreeError};

#[cfg(any(target_arch = "riscv64", test))]
fn fetch_with(
    reference: BlockRef,
    output: &mut [u8],
    call: impl FnOnce(&[u8; 32], &mut [u8]) -> (u64, u64),
) -> Result<bool, TreeError> {
    if output.len() != reference.byte_len() as usize {
        return Err(TreeError::InvalidValue);
    }
    let (status, length) = call(reference.hash().as_bytes(), output);
    if status != 0 || length != u64::from(reference.byte_len()) {
        return Err(TreeError::Storage);
    }
    // This is transport success only. The caller MUST verify the scoped hash.
    Ok(true)
}

/// Lane-selected guest transport; the runtime owns admission and per-operation
/// ReadBudget. No native mock/fallback is installed for this type.
#[cfg(target_arch = "riscv64")]
pub struct PvmBlockReader {
    lane: crate::StateLane,
}

#[cfg(target_arch = "riscv64")]
impl PvmBlockReader {
    pub const fn new(lane: crate::StateLane) -> Self {
        Self { lane }
    }
}

#[cfg(target_arch = "riscv64")]
impl crate::state_tree::BlockReader for PvmBlockReader {
    fn read(&mut self, reference: BlockRef, output: &mut [u8]) -> Result<bool, TreeError> {
        fetch_with(reference, output, |hash, output| {
            let status: u64;
            let length: u64;
            // SAFETY: the hash and exact-length writable output remain live
            // through this synchronous call. The compiler must consider memory
            // modified (no nomem/readonly option). The experimental host ABI
            // changes only a0/a1, and its errors terminate the invocation.
            unsafe {
                core::arch::asm!(
                    "li t0, {call_id}",
                    "csrw 0x801, zero",
                    "ecall",
                    call_id = const crate::state_blocks::STATE_BLOCK_FETCH_CALL,
                    lateout("t0") _,
                    inlateout("a0") hash.as_ptr() as u64 => status,
                    inlateout("a1") output.len() as u64 => length,
                    in("a2") output.as_mut_ptr() as u64,
                    in("a3") output.len() as u64,
                    in("a4") self.lane as u64,
                    options(nostack),
                );
            }
            (status, length)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AgentId, Hash, SpaceId, StateLane,
        state_blocks::{BlockError, BlockScope, ReadBudget},
    };
    fn scope() -> BlockScope {
        BlockScope::new(
            SpaceId([1; 32]),
            AgentId([2; 32]),
            Hash([3; 32]),
            StateLane::Linear,
        )
        .unwrap()
    }

    #[test]
    fn only_exact_success_is_transport_success() {
        let reference = scope().reference(b"data").unwrap();
        let mut output = [0; 4];
        assert_eq!(
            fetch_with(reference, &mut output, |hash, output| {
                assert_eq!(hash, reference.hash().as_bytes());
                output.copy_from_slice(b"data");
                (0, 4)
            }),
            Ok(true)
        );
        assert_eq!(output, *b"data");
        for result in [(1, 4), (u64::MAX, 0), (0, 0), (0, 3), (0, 5)] {
            assert_eq!(
                fetch_with(reference, &mut output, |_, _| result),
                Err(TreeError::Storage)
            );
        }
        assert_eq!(
            fetch_with(reference, &mut [0; 3], |_, _| panic!(
                "invalid buffer must not call host"
            )),
            Err(TreeError::InvalidValue)
        );
    }

    #[test]
    fn successful_transport_does_not_bypass_guest_hash_verification() {
        let scope = scope();
        let reference = scope.reference(b"data").unwrap();
        let mut output = [0; 4];
        let mut budget = ReadBudget::new(1, 4);
        let permit = budget.begin_fetch(scope, reference).unwrap();
        let available = fetch_with(reference, &mut output, |_, bytes| {
            bytes.copy_from_slice(b"fake");
            (0, 4)
        })
        .unwrap();
        assert_eq!(
            permit.verify(available.then_some(output.as_slice())),
            Err(BlockError::HashMismatch)
        );
    }
}
