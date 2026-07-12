//! VOS ZK actor-IO ABI — TAGLESS binding.
//!
//! A framework-level convention for binding a zkpvm proof of an actor
//! handler to the specific `(public_inputs, return_value)` tuple a
//! caller asserts it ran on — placing that tuple's hash in
//! `final_state.registers` (φ[9..12]) so the caller can assert this
//! proof corresponds to this exact `(public, return)`. (SOUNDNESS
//! CAVEAT below: the register binding is currently complete only
//! against an honest prover — see step 2.)
//!
//! ## What the hash binds (and what it deliberately does NOT)
//!
//! The binding hash contains ONLY a domain/version separator and the
//! I/O bytes:
//!
//! ```text
//! H = blake2b_256( b"vos/zk/io/v1" || H_field(public) || H_field(return) )
//! ```
//!
//! It is **tagless**: no actor/message identity enters the hash.  That
//! is by design — identity lives where it can be *proven*, not merely
//! *claimed*:
//!
//! - **Which program** ran is established by the proof's *program
//!   commitment* (the preprocessed-trace Merkle root, see
//!   `zkpvm::program_commitment_of_proof`).  The verifier supplies a
//!   trusted commitment to `verify_standalone`, which rejects any proof
//!   of a different program.  A name-tag in the hash would be a third,
//!   redundant copy of identity — and a *claim* (a tag can be reused for
//!   different code) rather than a *proof* (a commitment cannot).
//! - **The human name** (a program's catalog name) belongs in the
//!   provenance / catalog layer (program_id → trusted commitment), where
//!   naming, versioning, and governance actually live.
//! - **Which operation** within a multi-handler program, when a protocol
//!   needs to distinguish, is just another *public input* the actor
//!   folds into `public` — one concept (public inputs), not a separate
//!   "msg tag".
//!
//! So a complete identity check is `verify_standalone(proof, commitment)`
//! (which program — cryptographic) **AND** `proof.public_io_hash() ==
//! compute_io_hash(public, return)` (which I/O).  The two are composed in
//! the `prover` host extension's `verify`; there is intentionally no
//! standalone binding-only check here (using one without the other is
//! the footgun the composed form retires).
//!
//! ## How it fits together
//!
//! 1. The guest actor binds its `(public, return)` with [`bind_io`]
//!    (or computes the hash directly with [`compute_io_hash_typed`]).
//! 2. The actor's halt sequence places that hash into the final-state
//!    register window φ[9..12] (RISC-V `a2..a5`) via inline-asm `in`
//!    operands on the halting `ecall` (see `actors::run`'s
//!    `halt_with_output_bound`).  Phase Z0's closing chip pins the
//!    final-register columns and the verifier's boundary-binding check
//!    (`zkpvm::boundary_binding`) equates `final_state.registers` to
//!    them — no new ECALL, no prover changes.  That equality binds the
//!    public registers to the committed closing-chip columns, and those
//!    columns are pinned to the trace's true final registers by
//!    `RegisterMemoryChip` read-consistency — a cross-row
//!    `#[mask_next_row]` `prev_value` binding, a range-checked
//!    `(reg, ts)` sortedness gadget, and an `is_write` tuple limb — so a
//!    forged closing read (and hence a forged io-hash) is rejected
//!    in-circuit, sound against a from-scratch prover (gate:
//!    `zkpvm/tests/ledger_readconsistency_gate.rs`).
//! 3. The host verifier reconstructs the hash from the proof via
//!    [`zkpvm::Proof::public_io_hash`] and compares it against a locally
//!    recomputed [`compute_io_hash`] — alongside the STARK validity
//!    check against the trusted program commitment.
//!
//! The ABI version lives in the hash domain separator (`b"vos/zk/io/v1"`),
//! not in `PROOF_FORMAT_VERSION` (which is constraint-shape only): old
//! proofs leave φ[9..13] at their cold-start zero, so their
//! `public_io_hash` is `[0u8; 32]` and naturally fails the equality
//! check.

/// Sparse-Merkle state commitments (`anchor_kind 0x02` math): fixed-
/// depth SMT roots, single-key proofs, and the [`state::BatchProof`]
/// multiproof over any fixed key width.
pub mod state;

/// Domain separator + ABI version for the (outer) actor-IO hash.  Bumping
/// the trailing version rotates the binding so old proofs and old
/// verifiers cleanly fail the equality check rather than silently
/// cross-validating.
const IO_DOMAIN: &[u8] = b"vos/zk/io/v1";

/// Domain separator for the per-field inner hash.  Distinct from
/// [`IO_DOMAIN`] so a field digest can never be confused with a full
/// io-hash.
const IO_FIELD_DOMAIN: &[u8] = b"vos/zk/io-field/v1";

/// Inner reduction of one I/O field to a fixed-width 32-byte digest.
///
/// Hashing each field to a fixed width *before* combining is what makes
/// [`compute_io_hash`] injective at the public/return boundary: with raw
/// concatenation, `(public="AB", return="C")` and `(public="A",
/// return="BC")` would hash identically; with fixed-width inner digests
/// they cannot collide (short of a blake2b collision).
fn field_hash(bytes: &[u8]) -> [u8; 32] {
    crate::crypto::blake2b::blake2b_hash::<32>(IO_FIELD_DOMAIN, &[bytes])
}

/// Compute the 32-byte tagless actor-IO binding hash from the
/// already-encoded `public` and `return` bytes:
///
/// ```text
/// H = blake2b_256(
///       b"vos/zk/io/v1"            // domain + ABI version
///    || field_hash(public_bytes)   // 32 bytes, injective reduction
///    || field_hash(return_bytes)   // 32 bytes
/// )
/// ```
///
/// This is the canonical primitive: the guest binds with the same bytes
/// the host verifier recomputes from.  `public_bytes` / `return_bytes`
/// are whatever encoding the actor and caller agree on — in practice the
/// rkyv archive of the typed values (see [`compute_io_hash_typed`], which
/// is exactly `compute_io_hash(&public.encode(), &return_value.encode())`).
/// An empty slice is the well-defined "no asserted public / return"
/// value (the default a non-binding actor binds).
pub fn compute_io_hash(public_bytes: &[u8], return_bytes: &[u8]) -> [u8; 32] {
    let ph = field_hash(public_bytes);
    let rh = field_hash(return_bytes);
    crate::crypto::blake2b::blake2b_hash::<32>(IO_DOMAIN, &[ph.as_slice(), rh.as_slice()])
}

/// Typed convenience over [`compute_io_hash`]: rkyv-encode `public` and
/// `return_value`, then hash.  This is the encoding contract the guest
/// and host verifier share — a host that holds the typed values computes
/// the identical hash a guest that called [`bind_io`] bound, and a host
/// that holds only the wire bytes calls [`compute_io_hash`] directly with
/// those bytes.
///
/// e.g. `compute_io_hash_typed(&public, &1u8)`.
pub fn compute_io_hash_typed<P, R>(public: &P, return_value: &R) -> [u8; 32]
where
    P: crate::Encode,
    R: crate::Encode,
{
    compute_io_hash(&public.encode(), &return_value.encode())
}

// ── Witness-injection convention (`__VOS_WITNESS`) ───────────────────
//
// A provable actor takes its witness from a fixed, conventionally-named
// static buffer `__VOS_WITNESS` that the host `prover` extension patches
// with OPAQUE bytes (found by ELF symbol name) before tracing.  The
// prover never interprets the bytes — the actor owns its own layout — so
// the prover is program-agnostic.  The conventional payload layout (which
// [`read_witness_buffer`] and the prover's `encode_witness` agree on) is
// little-endian length-prefixed `(public, secret)`:
//
//   `[u32 public_len][public][u32 secret_len][secret]`
//
// Actors declare the buffer with the [`witness_buffer!`] macro instead of
// hand-rolling the `#[no_mangle] static mut`.

/// A `(public_bytes, secret_bytes)` witness read from a `__VOS_WITNESS`
/// buffer.  Both halves are opaque to the framework — the actor decodes
/// them with whatever scheme it bound (rkyv in practice).
pub type Witness = (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>);

/// Read a length-prefixed `(public, secret)` witness from a guest witness
/// buffer of capacity `cap` bytes starting at `ptr` (the
/// [`witness_buffer!`]-emitted `__VOS_WITNESS`).  Layout (little-endian):
/// `[u32 public_len][public][u32 secret_len][secret]`.
///
/// Returns `None` when the buffer is unpatched (leading length zero) or
/// malformed (a declared length runs past `cap`) — the actor then falls
/// back to whatever default it chooses.  Uses volatile reads so a
/// zero-initialised `.bss` buffer isn't optimised away on the guest.
///
/// # Safety
/// `ptr` must point to at least `cap` readable bytes for the duration of
/// the call (satisfied by the `witness_buffer!`-emitted static).
pub unsafe fn read_witness_buffer(ptr: *const u8, cap: usize) -> Option<Witness> {
    use alloc::vec::Vec;
    if cap < 8 {
        return None;
    }
    // SAFETY: caller guarantees `cap` readable bytes at `ptr`; every
    // offset below is bounds-checked against `cap` before the read.
    let public_len = unsafe { core::ptr::read_volatile(ptr as *const u32) } as usize;
    if public_len == 0 || 4usize.checked_add(public_len)?.checked_add(4)? > cap {
        return None;
    }
    let mut public = Vec::with_capacity(public_len);
    for i in 0..public_len {
        public.push(unsafe { core::ptr::read_volatile(ptr.add(4 + i)) });
    }
    let secret_off = 4 + public_len;
    let secret_len =
        unsafe { core::ptr::read_volatile(ptr.add(secret_off) as *const u32) } as usize;
    if secret_len == 0 || secret_off.checked_add(4)?.checked_add(secret_len)? > cap {
        return None;
    }
    let mut secret = Vec::with_capacity(secret_len);
    for i in 0..secret_len {
        secret.push(unsafe { core::ptr::read_volatile(ptr.add(secret_off + 4 + i)) });
    }
    Some((public, secret))
}

/// Host-side: find the flat-memory address of the `__VOS_WITNESS` symbol
/// in a provable actor's ELF — the offset the host `prover` extension
/// patches opaque witness bytes into before tracing. `None` if the file
/// isn't an ELF, the symbol is absent, or its address is `0` (unresolved).
///
/// The transpiled PVM blob preserves the ELF's flat-memory layout, so this
/// address equals the blob offset `zkpvm::actor::trace_blob_with_patches`
/// (and hence the prover's `prove` / `prove_chain`) expects. A caller that
/// holds an actor ELF transpiles it and locates the witness buffer here,
/// then hands both to the (ELF-agnostic) prover.
#[cfg(feature = "std")]
pub fn witness_addr(elf: &[u8]) -> Option<u64> {
    witness_symbol(elf).map(|(addr, _)| addr)
}

/// `(address, size)` of the `__VOS_WITNESS` buffer. The size is the
/// buffer's declared capacity — the host must refuse to patch an input
/// past it (a fixed static in the guest image; an over-capacity write
/// would silently overwrite adjacent `.bss`).
#[cfg(feature = "std")]
pub fn witness_symbol(elf: &[u8]) -> Option<(u64, u64)> {
    use object::{Object, ObjectSymbol};
    let obj = object::File::parse(elf).ok()?;
    for sym in obj.symbols() {
        if sym.name().ok() == Some("__VOS_WITNESS") {
            let addr = sym.address();
            if addr != 0 {
                return Some((addr, sym.size()));
            }
        }
    }
    None
}

/// Declare the standard ZK witness-injection buffer `__VOS_WITNESS` of
/// `$n` bytes, plus a `__vos_read_witness()` helper that reads the
/// conventional length-prefixed `(public, secret)` payload back (see
/// [`read_witness_buffer`]).
///
/// Every provable actor exposes a `#[no_mangle] static mut __VOS_WITNESS`
/// so the host `prover` extension can patch opaque witness bytes into it
/// (located by ELF symbol name) before tracing.  Using this macro keeps
/// the symbol name and buffer shape consistent across actors so the
/// prover stays program-agnostic.
///
/// ```ignore
/// vos::zk::witness_buffer!(1024);
/// // ... later, in a handler:
/// let (public_bytes, secret_bytes) = __vos_read_witness().unwrap_or_else(default_witness);
/// ```
#[macro_export]
macro_rules! witness_buffer {
    ($n:expr) => {
        /// Witness buffer the host prover patches before tracing — see
        /// `vos::zk::witness_buffer!`.  Lives in `.bss` (all zeros until
        /// patched).
        #[unsafe(no_mangle)]
        static mut __VOS_WITNESS: [u8; $n] = [0u8; $n];

        /// Read the `(public, secret)` witness the prover patched into
        /// `__VOS_WITNESS`; `None` when unpatched or malformed.
        fn __vos_read_witness() -> ::core::option::Option<$crate::zk::Witness> {
            // SAFETY: `__VOS_WITNESS` is a `$n`-byte static; the reader
            // stays within `$n` bytes.
            unsafe {
                $crate::zk::read_witness_buffer(
                    ::core::ptr::addr_of!(__VOS_WITNESS) as *const u8,
                    $n,
                )
            }
        }
    };
}

#[doc(inline)]
pub use crate::witness_buffer;

// ── Guest-side binding (halt-asm path) ───────────────────────────────
//
// A service actor binds its `(public, return)` by computing the io-hash
// during execution and stashing it here; `actors::run::run_refine_service`
// reads the stash just before halt and places it in φ[9..12] via
// `halt_with_output_bound` (see this module's docs).  When no actor binds
// explicitly, `run_refine_service` falls back to the empty-public/
// empty-return default, so every proof carries a well-defined io-hash
// (never the cold-start zero sentinel).

/// Single-slot stash for the pending io-hash, set by [`bind_io`] during
/// handler execution and drained by `run_refine_service` at halt.
///
/// SAFETY: the PVM guest is strictly single-threaded, so the `static mut`
/// is never concurrently accessed — same invariant the runtime relies on
/// for `ACTOR_HOLDER` / `OUTPUT_BUF` in `actors::run`.
#[cfg(feature = "pvm")]
static mut PENDING_IO_HASH: Option<[u8; 32]> = None;

/// Stash a precomputed io-hash for the halt binding.  Internal — actors
/// call [`bind_io`].
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub fn __set_pending_io_hash(hash: [u8; 32]) {
    let slot = core::ptr::addr_of_mut!(PENDING_IO_HASH);
    // SAFETY: single-threaded PVM; exclusive access via raw pointer.
    unsafe { *slot = Some(hash) };
}

/// Drain the pending io-hash.  Internal — `run_refine_service` calls this
/// once at halt.
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub fn __take_pending_io_hash() -> Option<[u8; 32]> {
    let slot = core::ptr::addr_of_mut!(PENDING_IO_HASH);
    // SAFETY: single-threaded PVM; exclusive access via raw pointer.
    unsafe { (*slot).take() }
}

/// Guest-side: bind this execution to the asserted `(public, return)`
/// tuple (tagless — see the module docs on why no actor/message identity
/// enters the hash).
///
/// Computes [`compute_io_hash_typed`] and stashes it; `run_refine_service`
/// places it into the Phase-Z0-bound final-state register window φ[9..12]
/// at halt, making it the proof's [`zkpvm::Proof::public_io_hash`].  The
/// host verifier checks it against a recomputed `compute_io_hash` over the
/// same `(public, return)`.
///
/// Call this from a handler after the work it proves, e.g.
/// `vos::zk::bind_io(&public, &1u8)`.  The last binding in a refine wins
/// (one handler per proof is the model).  Actors that never call it bind
/// the empty-public/empty-return default.  If a program exposes multiple
/// provable operations, fold an operation discriminator into `public`.
#[cfg(feature = "pvm")]
pub fn bind_io<P, R>(public: &P, return_value: &R)
where
    P: crate::Encode,
    R: crate::Encode,
{
    __set_pending_io_hash(compute_io_hash_typed(public, return_value));
}

/// Guest-side: bind this execution to an asserted `(public, return)`
/// tuple supplied as **already-encoded bytes** — the raw-bytes
/// counterpart to [`bind_io`].
///
/// The tagless io-ABI is fundamentally "bytes" (see [`compute_io_hash`]),
/// so an actor that owns an explicit, canonical encoding of its public
/// inputs (rather than relying on the rkyv archive [`bind_io`] derives)
/// binds via this. The host verifier recomputes
/// `compute_io_hash(public_bytes, return_bytes)` over the same bytes — so
/// guest and verifier agree by construction, with no rkyv-layout /
/// cross-crate coupling.
///
/// e.g. `vos::zk::bind_io_bytes(&my_public_bytes, &[1u8])`.
/// Same halt/φ[9..12] placement and last-binding-wins semantics as
/// [`bind_io`].
#[cfg(feature = "pvm")]
pub fn bind_io_bytes(public_bytes: &[u8], return_bytes: &[u8]) {
    __set_pending_io_hash(compute_io_hash(public_bytes, return_bytes));
}

/// App-level public bytes designated by a provable Task handler, awaiting
/// the framework's halt composition.
#[cfg(feature = "pvm")]
static mut PENDING_PUBLIC: Option<alloc::vec::Vec<u8>> = None;

/// Guest-side (**provable Tasks only**): designate this Task's
/// application-level PUBLIC inputs.
///
/// Unlike [`bind_io`], this does NOT compute a finished io-hash. For a
/// Task the framework composes the io-hash at halt over
/// `folded_public(anchor_kind, anchor, transition_digest, app_public)`
/// and the reply (`work-result-contract.md` §5), so the proof commits to
/// the state *transition* — the anchored input state plus the exact
/// applied effects — in addition to whatever bytes are added here.
/// Default (no call) = empty `app_public`: the transition itself is the
/// public statement. The finished-hash [`bind_io`] form is ignored for
/// Task blobs (the framework, not the handler, owns the composition).
#[cfg(feature = "pvm")]
pub fn bind_public<P: crate::Encode>(public: &P) {
    bind_public_bytes(&public.encode());
}

/// Raw-bytes counterpart to [`bind_public`] — the app-public bytes as an
/// explicit canonical encoding.
#[cfg(feature = "pvm")]
pub fn bind_public_bytes(public_bytes: &[u8]) {
    let slot = core::ptr::addr_of_mut!(PENDING_PUBLIC);
    // SAFETY: single-threaded PVM; exclusive access via raw pointer.
    unsafe { *slot = Some(public_bytes.to_vec()) };
}

/// Drain the pending app-public bytes. Internal — `run_task_service`
/// calls this once at halt.
#[cfg(feature = "pvm")]
#[doc(hidden)]
pub fn __take_pending_public() -> Option<alloc::vec::Vec<u8>> {
    let slot = core::ptr::addr_of_mut!(PENDING_PUBLIC);
    // SAFETY: single-threaded PVM; exclusive access via raw pointer.
    unsafe { (*slot).take() }
}

// ── Provable-program catalog (`vosx zk pin` artifact) ────────────────
//
// The catalog is the pinning artifact a `#[provable]` program publishes and
// verifiers consume as the ALLOWLIST SOURCE — replacing the drift-prone test
// constants ({C_0, C_1}, the canonical profile, the segment-step bound) that
// scatter through test files. `vosx zk pin` builds the program, transpiles it,
// traces one representative witness-injected run, and measures the fields below;
// verifiers load the catalog and feed `allowlist_concat()` /
// `unpatched_image_root_bytes()` straight into the prover extension's
// `verify_chain`. Format is TOML (human-diffable — this is checked-in
// provenance).

/// Provable-program catalog: the pinned proving parameters `vosx zk pin` emits
/// and verifiers read as the allowlist source. See the module comment above.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvableCatalog {
    /// Catalog format version (bump on a breaking field change).
    pub version: u32,
    /// One pin per published provable program.
    #[serde(rename = "program", default)]
    pub programs: alloc::vec::Vec<ProgramPin>,
}

/// One provable program's pinned measurements — the canonical-shape
/// commitment allowlist, forcing profile, segment-step bound, witness-buffer
/// address, and unpatched entering-image root.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProgramPin {
    /// Catalog identity (e.g. `"voucher-check"`) — the human name; program
    /// identity itself is the cryptographic `commitments`.
    pub name: alloc::string::String,
    /// Canonical-shape program-commitment ALLOWLIST — hex-encoded 32-byte
    /// preprocessed-trace Merkle roots (`{C_0, C_1, …}`), one per distinct
    /// canonical segment shape. Fed to `verify_chain` as `allowlist`.
    pub commitments: alloc::vec::Vec<alloc::string::String>,
    /// Canonical forcing profile (`[u32; zkpvm::chip_idx::COUNT]`, `0` = not
    /// forced). The prover pads each forcing-set chip up to this so every
    /// segment shares one `log_size` and lands in `commitments`.
    pub canonical_profile: alloc::vec::Vec<u32>,
    /// Per-segment step bound the profile + allowlist were measured against.
    pub seg_steps: u64,
    /// Flat-memory address of the program's `__VOS_WITNESS` buffer (its ELF
    /// symbol address); where the prover patches the witness before tracing.
    pub witness_addr: u64,
    /// Page-Merkle root of the UNPATCHED program image (hex, 32 bytes;
    /// `__VOS_WITNESS` all-zero). **Diagnostic only — NOT the verifier's
    /// entering-image pin.** A witness-injecting program's live segment-0 root is
    /// the PATCHED image root, which differs from this in the witness region, so
    /// a verifier cannot anchor against this value. The pinnable value is the
    /// MASKED image root (witness region excluded), pending the design in
    /// `docs/design/masked-image-root.md`; do not wire any verifier to this
    /// field. See `zkpvm::page_merkle::image_root`.
    pub unpatched_image_root: alloc::string::String,
}

/// Errors decoding, loading, or interpreting a [`ProvableCatalog`].
#[cfg(feature = "std")]
#[derive(Debug)]
pub enum CatalogError {
    /// The catalog file could not be read or written.
    Io(std::io::Error),
    /// The TOML failed to parse or serialize.
    Toml(alloc::string::String),
    /// A hex field was malformed or not the expected 32 bytes.
    Hex(alloc::string::String),
    /// No program with the requested name is pinned in the catalog.
    NotFound(alloc::string::String),
}

#[cfg(feature = "std")]
impl core::fmt::Display for CatalogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CatalogError::Io(e) => write!(f, "catalog io: {e}"),
            CatalogError::Toml(e) => write!(f, "catalog toml: {e}"),
            CatalogError::Hex(e) => write!(f, "catalog hex: {e}"),
            CatalogError::NotFound(n) => write!(f, "no pinned program named {n:?}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CatalogError {}

#[cfg(feature = "std")]
impl ProvableCatalog {
    /// The current catalog format version this build writes.
    pub const VERSION: u32 = 1;

    /// A fresh empty catalog at the current version.
    pub fn new() -> Self {
        ProvableCatalog { version: Self::VERSION, programs: alloc::vec::Vec::new() }
    }

    /// Parse a catalog from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, CatalogError> {
        toml::from_str(s).map_err(|e| CatalogError::Toml(alloc::string::ToString::to_string(&e)))
    }

    /// Serialize the catalog to a TOML string (pretty, checked-in-friendly).
    pub fn to_toml_string(&self) -> Result<alloc::string::String, CatalogError> {
        toml::to_string_pretty(self)
            .map_err(|e| CatalogError::Toml(alloc::string::ToString::to_string(&e)))
    }

    /// Load a catalog from a TOML file.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self, CatalogError> {
        let s = std::fs::read_to_string(path).map_err(CatalogError::Io)?;
        Self::from_toml_str(&s)
    }

    /// Write the catalog to a TOML file (creating or overwriting).
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> Result<(), CatalogError> {
        let s = self.to_toml_string()?;
        std::fs::write(path, s).map_err(CatalogError::Io)
    }

    /// The pin for `name`, or `None` if the program isn't cataloged.
    pub fn get(&self, name: &str) -> Option<&ProgramPin> {
        self.programs.iter().find(|p| p.name == name)
    }

    /// The pin for `name`, or a [`CatalogError::NotFound`].
    pub fn require(&self, name: &str) -> Result<&ProgramPin, CatalogError> {
        self.get(name)
            .ok_or_else(|| CatalogError::NotFound(alloc::string::ToString::to_string(&name)))
    }

    /// Insert or replace the pin for `program.name` (idempotent by name).
    pub fn upsert(&mut self, program: ProgramPin) {
        if let Some(slot) = self.programs.iter_mut().find(|p| p.name == program.name) {
            *slot = program;
        } else {
            self.programs.push(program);
        }
    }
}

#[cfg(feature = "std")]
impl Default for ProvableCatalog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "std")]
impl ProgramPin {
    /// Decode the hex `commitments` into 32-byte canonical program commitments.
    pub fn commitments_bytes(&self) -> Result<alloc::vec::Vec<[u8; 32]>, CatalogError> {
        self.commitments.iter().map(|h| hex_to_32(h)).collect()
    }

    /// The commitment allowlist in the concatenated `32·N`-byte form the prover
    /// extension's `verify_chain` accepts.
    pub fn allowlist_concat(&self) -> Result<alloc::vec::Vec<u8>, CatalogError> {
        let mut out = alloc::vec::Vec::with_capacity(32 * self.commitments.len());
        for c in self.commitments_bytes()? {
            out.extend_from_slice(&c);
        }
        Ok(out)
    }

    /// Decode the hex `unpatched_image_root` into 32 bytes.
    pub fn unpatched_image_root_bytes(&self) -> Result<[u8; 32], CatalogError> {
        hex_to_32(&self.unpatched_image_root)
    }
}

/// Lowercase-hex-encode bytes (catalog fields carry 32-byte roots/commitments
/// as hex strings so the TOML stays compact + human-diffable).
#[cfg(feature = "std")]
pub fn bytes_to_hex(bytes: &[u8]) -> alloc::string::String {
    use core::fmt::Write as _;
    let mut s = alloc::string::String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode a 64-char hex string into exactly 32 bytes; errors on a bad length or
/// non-hex digit.
#[cfg(feature = "std")]
fn hex_to_32(s: &str) -> Result<[u8; 32], CatalogError> {
    let s = s.trim();
    if s.len() != 64 {
        return Err(CatalogError::Hex(alloc::format!(
            "expected 64 hex chars (32 bytes), got {}",
            s.len()
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_digit(s.as_bytes()[2 * i])?;
        let lo = hex_digit(s.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

#[cfg(feature = "std")]
fn hex_digit(c: u8) -> Result<u8, CatalogError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(CatalogError::Hex(alloc::format!("invalid hex digit {:?}", c as char))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Encode;

    #[test]
    fn deterministic_and_nonzero() {
        let a = compute_io_hash_typed(&7u32, &1u8);
        let b = compute_io_hash_typed(&7u32, &1u8);
        assert_eq!(a, b, "same inputs must hash identically");
        assert_ne!(a, [0u8; 32], "a real binding is never the unbound sentinel");
    }

    #[test]
    fn public_value_changes_hash() {
        let a = compute_io_hash_typed(&7u32, &1u8);
        let b = compute_io_hash_typed(&8u32, &1u8);
        assert_ne!(a, b, "different public input must rebind");
    }

    #[test]
    fn return_value_changes_hash() {
        let a = compute_io_hash_typed(&7u32, &1u8);
        let b = compute_io_hash_typed(&7u32, &2u8);
        assert_ne!(a, b, "different return value must rebind");
    }

    #[test]
    fn empty_public_and_return_is_stable() {
        // The default a non-binding actor binds: empty public + empty
        // return still yields a stable, nonzero hash (it's the domain +
        // two field-hashes of empty, not the cold-start zero sentinel).
        let a = compute_io_hash(&[], &[]);
        assert_eq!(a, compute_io_hash(&[], &[]));
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn injective_across_field_boundary() {
        // Hash-then-combine must be injective at the public/return
        // boundary — the property raw concatenation lacked.
        let h1 = compute_io_hash(b"AB", b"C");
        let h2 = compute_io_hash(b"A", b"BC");
        assert_ne!(
            h1, h2,
            "(public=AB,return=C) must not collide with (public=A,return=BC)"
        );
    }

    #[test]
    fn typed_matches_byte_primitive() {
        // The exact contract the host verifier relies on: encoding the
        // typed values then hashing equals hashing the encoded bytes the
        // guest produced via `bind_io`.
        let public = 7u32;
        let ret = 1u8;
        assert_eq!(
            compute_io_hash_typed(&public, &ret),
            compute_io_hash(&public.encode(), &ret.encode()),
        );
    }

    /// `bind_io_bytes(a, b)` stashes exactly `compute_io_hash(a, b)` for
    /// the halt binding (and drains once). pvm-gated — the stash + drain
    /// helpers only exist on the guest tier. Run with `--features pvm`.
    #[cfg(feature = "pvm")]
    #[test]
    fn bind_io_bytes_stashes_compute_io_hash() {
        // No other test touches PENDING_IO_HASH, so the single-slot stash
        // is uncontended; clear any leftover defensively.
        let _ = __take_pending_io_hash();
        bind_io_bytes(b"explicit-public", b"\x01");
        assert_eq!(
            __take_pending_io_hash(),
            Some(compute_io_hash(b"explicit-public", b"\x01")),
            "bind_io_bytes must stash compute_io_hash of the same bytes"
        );
        assert_eq!(
            __take_pending_io_hash(),
            None,
            "the slot must drain after one take"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn hex_roundtrip_and_length_guard() {
        let bytes: [u8; 32] = core::array::from_fn(|i| i as u8);
        let s = bytes_to_hex(&bytes);
        assert_eq!(s.len(), 64);
        assert_eq!(hex_to_32(&s).unwrap(), bytes);
        assert!(hex_to_32("dead").is_err(), "short hex must error, not truncate");
        assert!(hex_to_32(&"g".repeat(64)).is_err(), "non-hex digit must error");
    }

    #[cfg(feature = "std")]
    #[test]
    fn catalog_toml_roundtrips_and_accessors() {
        let c0 = [0x6du8; 32];
        let c1 = [0x5cu8; 32];
        let root = [0xABu8; 32];
        let pin = ProgramPin {
            name: "voucher-check".to_string(),
            commitments: vec![bytes_to_hex(&c0), bytes_to_hex(&c1)],
            canonical_profile: vec![0, 14, 18, 4],
            seg_steps: 100_000,
            witness_addr: 0x1_2340,
            unpatched_image_root: bytes_to_hex(&root),
        };
        let mut cat = ProvableCatalog::new();
        cat.upsert(pin.clone());

        // TOML encode → decode is lossless.
        let toml = cat.to_toml_string().expect("encode");
        let back = ProvableCatalog::from_toml_str(&toml).expect("decode");
        assert_eq!(back, cat, "catalog must round-trip through TOML");

        // Accessors decode the hex fields into the shapes verifiers consume.
        let p = back.require("voucher-check").expect("lookup");
        assert_eq!(p.commitments_bytes().unwrap(), vec![c0, c1]);
        assert_eq!(p.allowlist_concat().unwrap().len(), 64, "allowlist is 32·N bytes");
        assert_eq!(&p.allowlist_concat().unwrap()[..32], &c0);
        assert_eq!(p.unpatched_image_root_bytes().unwrap(), root);

        // Lookups and idempotent upsert.
        assert!(back.get("missing").is_none());
        assert!(matches!(back.require("missing"), Err(CatalogError::NotFound(_))));
        cat.upsert(pin); // same name again → still one entry
        assert_eq!(cat.programs.len(), 1, "upsert is idempotent by name");
    }
}
