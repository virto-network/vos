//! The authentication statement a device proves, as attestable methods:
//! membership of a space without saying which member, and a nullifier.
//!
//! - `auth`, over a vos-tree (BLAKE2b, salted values, the agent root's
//!   format): the member's row checked against the map's root by a one-key
//!   multiproof read from its encoding; its value commits to the member's
//!   secret; the output is the nullifier for a scope. The root, the scope
//!   and the binding are public arguments, so the io-hash states them, as
//!   pin I's auth words do.
//! - `auth_p2`, over the credential actor's Poseidon2 tree through the
//!   `0x402` call (`proving.md` §8, S21): pin J's device kernel, its public
//!   arguments auth's `CredentialPublic` (the kind byte, then `map_root`,
//!   `scope`, `nullifier` and `binding`), its output empty; 36
//!   compressions. A lean kernel: its arguments read where the witness
//!   input left them ([`InPlace`], the siblings first, so page-aligned), never
//!   copied, and the path walked in place in one lane (sibling, node,
//!   sibling), each level's call reading the half the slot's bit picks by
//!   its address, never a branch, and writing the parent over the node.

#![no_std]

extern crate alloc;

use vos_sdk::prelude::*;

pub const TAG_MEMBER: &[u8] = b"vos/auth/member";
pub const TAG_NULLIFIER: &[u8] = b"vos/auth/nullifier";

/// A member's row value: the commitment to its secret.
pub fn member_value(secret: &[u8; 32]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(TAG_MEMBER, &[secret])
}

/// The nullifier of `secret` for `scope`.
pub fn nullifier(secret: &[u8; 32], scope: &[u8; 32]) -> [u8; 32] {
    vos_pvm_precompiles::blake2b_hash::<32>(TAG_NULLIFIER, &[secret, scope])
}

/// Whether the member keyed `key` holds the row committing to `secret`
/// under `salt` at `root`, by the encoded multiproof `proof`.
pub fn member_of(
    root: &[u8; 32],
    key: &[u8],
    secret: &[u8; 32],
    salt: &[u8; 16],
    proof: &[u8],
) -> bool {
    let commitment = vos_tree::value_hash(&vos_tree::Blake2b, salt, &member_value(secret));
    vos_tree::verify_encoded(&vos_tree::Blake2b, proof, root, &[(key, Some(commitment))]).is_ok()
}

/// `N` bytes of a kernel's arguments where its witness input left them,
/// in the argument pages, which hold them for the whole run: decoded
/// without a copy, valid only while the bytes it was decoded from live (a
/// kernel's arguments, for its run). Its encoding is the bytes'.
#[derive(Clone, Copy)]
pub struct InPlace<const N: usize>(*const u8);

impl<const N: usize> InPlace<N> {
    /// The bytes.
    ///
    /// # Safety
    ///
    /// The bytes it was decoded from must still live.
    pub unsafe fn bytes(&self) -> &[u8; N] {
        // SAFETY: decoded from at least `N` bytes, live by the contract.
        unsafe { &*self.0.cast::<[u8; N]>() }
    }

    fn ptr(&self) -> *const u8 {
        self.0
    }
}

impl<const N: usize> Decode for InPlace<N> {
    fn decode(data: &[u8]) -> Result<(Self, usize), vos_sdk::scale::DecodeError> {
        if data.len() < N {
            return Err(vos_sdk::scale::DecodeError::UnexpectedEof);
        }
        Ok((Self(data.as_ptr()), N))
    }
}

impl<const N: usize> Encode for InPlace<N> {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        // SAFETY: a kernel encodes its public arguments during its run,
        // while the argument pages hold them.
        buf.extend_from_slice(unsafe { self.bytes() });
    }
}

/// The `0x402` call on the sixteen words at `input`, its eight out at
/// `output`; a host that does not serve it traps the kernel. `input` may
/// overlap `output`: the call reads all of its input before it writes.
///
/// # Safety
///
/// `input` must point at 64 readable bytes and `output` at 32 writable ones,
/// each 4-aligned.
#[inline(always)]
unsafe fn p2(input: *const u64, output: *mut u64) {
    #[cfg(target_arch = "riscv64")]
    unsafe {
        let answer: u64;
        core::arch::asm!(
            "li t0, 0x402",
            "csrw 0x801, zero",
            "ecall",
            out("t0") _,
            inlateout("a0") input as u64 => answer,
            in("a1") output as u64,
            in("a2") 0u64,
            in("a3") 0u64,
            options(nostack),
        );
        if answer == u64::MAX - 1 {
            core::arch::asm!("unimp", options(noreturn));
        }
    }
    #[cfg(not(target_arch = "riscv64"))]
    unsafe {
        let words: [u32; 16] = core::ptr::read_unaligned(input.cast());
        let out = vos_pvm_precompiles::poseidon2_compress_block(&words);
        core::ptr::write_unaligned(output.cast::<[u32; 8]>(), out);
    }
}

/// A tag's block, as four little-endian `u64`s.
const fn tag(tag: vos_wire::credentials::Tag) -> [u64; 4] {
    [tag.word() as u64, 0, 0, 0]
}

/// The 32 bytes at `from`, any alignment, as four little-endian `u64`s.
///
/// # Safety
///
/// `from` must point at 32 readable bytes.
#[inline(always)]
unsafe fn unaligned(from: *const u8) -> [u64; 4] {
    unsafe {
        core::array::from_fn(|i| u64::from_le(core::ptr::read_unaligned(from.add(8 * i).cast())))
    }
}

/// The 32 bytes at `from`, 8-aligned, as four `u64`s.
///
/// # Safety
///
/// `from` must point at 32 readable bytes, 8-aligned.
#[inline(always)]
unsafe fn aligned(from: *const u8) -> [u64; 4] {
    unsafe { core::array::from_fn(|i| *from.cast::<u64>().add(i)) }
}

/// The root `secret`'s leaf gives at `slot` by the 32 siblings at
/// `siblings` (the leaf's level first, 8-aligned), and the nullifier for
/// the scope at `scope`: the leaf `C(T(leaf), C(T(member), s))`, one call a
/// level in the lane `[sibling, node, sibling]` at the offset the slot's
/// bit picks (the node a right child reads `sibling ‖ node`), the parent
/// written over the node; the nullifier `C(C(T(nf), s), scope)`.
///
/// # Safety
///
/// `siblings` must point at 1,024 readable bytes, `secret` at 32, both
/// 8-aligned, and `scope` at 32 of any alignment.
pub unsafe fn auth_p2_lean(
    secret: *const u8,
    slot: u32,
    siblings: *const u8,
    scope: *const u8,
) -> ([u64; 4], [u64; 4]) {
    use vos_wire::credentials::Tag;
    let mut head = [0u64; 8];
    let mut lane = [0u64; 12];
    let mut nullifier = [0u64; 4];
    // One pointer each, every access through it: the call reads and
    // writes the same buffer.
    let (head, lane) = (head.as_mut_ptr(), lane.as_mut_ptr());
    unsafe {
        let s = aligned(secret);
        let put =
            |at: *mut u64, words: &[u64; 4]| core::ptr::copy_nonoverlapping(words.as_ptr(), at, 4);
        put(head, &tag(Tag::Nf));
        put(head.add(4), &s);
        p2(head, head);
        put(head.add(4), &unaligned(scope));
        p2(head, nullifier.as_mut_ptr());
        put(head, &tag(Tag::Member));
        put(head.add(4), &s);
        p2(head, head.add(4));
        put(head, &tag(Tag::Leaf));
        p2(head, lane.add(4));
        for level in 0..32 {
            let sibling = aligned(siblings.add(32 * level));
            core::ptr::copy_nonoverlapping(sibling.as_ptr(), lane, 4);
            core::ptr::copy_nonoverlapping(sibling.as_ptr(), lane.add(8), 4);
            let left = 4 - 4 * ((slot as usize >> level) & 1);
            p2(lane.add(left), lane.add(4));
        }
        let mut root = [0u64; 4];
        core::ptr::copy_nonoverlapping(lane.add(4), root.as_mut_ptr(), 4);
        (root, nullifier)
    }
}

/// Whether the four words `ours` are the 32 bytes at `theirs`, any
/// alignment, by every word, never stopping early.
///
/// # Safety
///
/// `theirs` must point at 32 readable bytes.
unsafe fn same(ours: &[u64; 4], theirs: *const u8) -> u64 {
    let theirs = unsafe { unaligned(theirs) };
    let differ = (0..4).fold(0, |acc, i| acc | (ours[i] ^ theirs[i]));
    u64::from(differ == 0)
}

#[actor]
pub struct Statements {
    count: u64,
}

#[messages]
impl Statements {
    pub fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    pub async fn count(&mut self) -> u64 {
        self.count += 1;
        self.count
    }

    /// Membership under `root` of the member keyed `key`, whose row commits
    /// to `secret`: the nullifier for `scope`. A refused path traps.
    #[attestable(gas = 50_000_000)]
    pub fn auth(
        #[public] root: [u8; 32],
        #[public] scope: [u8; 32],
        #[public] binding: [u8; 32],
        key: Vec<u8>,
        secret: [u8; 32],
        salt: [u8; 16],
        proof: Vec<u8>,
    ) -> [u8; 32] {
        let _ = binding;
        assert!(member_of(&root, &key, &secret, &salt, &proof), "a member");
        nullifier(&secret, &scope)
    }

    /// Auth over the Poseidon2 tree: `secret`'s leaf at `slot` under
    /// `map_root` by `siblings`, and `nullifier` its nullifier for `scope`.
    /// Anything else traps. The siblings come first, so they lie
    /// page-aligned where the witness input left them, and the secret
    /// 8-aligned after them.
    #[attestable(gas = 50_000_000)]
    #[allow(clippy::too_many_arguments)]
    pub fn auth_p2(
        siblings: InPlace<1024>,
        secret: InPlace<32>,
        slot: u32,
        #[public] kind: u8,
        #[public] map_root: InPlace<32>,
        #[public] scope: InPlace<32>,
        #[public] nullifier: InPlace<32>,
        #[public] binding: InPlace<32>,
    ) {
        let _ = binding;
        assert!(
            (siblings.ptr() as usize | secret.ptr() as usize) & 7 == 0,
            "8-aligned arguments"
        );
        // SAFETY: each `InPlace` points at its bytes in the argument pages,
        // the siblings and the secret 8-aligned.
        let matched = unsafe {
            let (root, derived) = auth_p2_lean(secret.ptr(), slot, siblings.ptr(), scope.ptr());
            u64::from(kind == 0) & same(&root, map_root.ptr()) & same(&derived, nullifier.ptr())
        };
        assert!(matched == 1, "a member");
    }
}
