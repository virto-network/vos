//! JAR hostcall IDs.
//!
//! Each constant maps to a PVM `ecalli` instruction. The host traps
//! the call and dispatches based on the ID.
//!
//! Hostcall IDs 3–10 have different semantics depending on the execution
//! phase (refine vs accumulate). The `refine` and `accumulate` sub-modules
//! define the phase-specific IDs.

/// Shared hostcalls (same ID and semantics in both phases)
pub const GAS: u32 = 0;
pub const GROW_HEAP: u32 = 1;
pub const FETCH: u32 = 2;
pub const DEBUG_WRITE: u32 = 128;

/// Refine-phase hostcalls (PC=0 entry point, stateless computation).
pub mod refine {
    pub const HISTORICAL_LOOKUP: u32 = 3;
    pub const EXPORT: u32 = 4;
    pub const MACHINE: u32 = 5;
    pub const PEEK: u32 = 6;
    pub const POKE: u32 = 7; // disabled, returns HOST_WHAT
    pub const PAGES: u32 = 8;
    pub const INVOKE: u32 = 9;
    pub const EXPUNGE: u32 = 10;
}

/// Accumulate-phase hostcalls (PC=5 entry point, stateful effects).
pub mod accumulate {
    pub const LOOKUP: u32 = 3;
    pub const READ: u32 = 4;
    pub const WRITE: u32 = 5;
    pub const INFO: u32 = 6;
    pub const BLESS: u32 = 15;
    pub const ASSIGN: u32 = 16;
    pub const DESIGNATE: u32 = 17;
    pub const CHECKPOINT: u32 = 18;
    pub const NEW: u32 = 19;
    pub const UPGRADE: u32 = 20;
    pub const TRANSFER: u32 = 21;
    pub const EJECT: u32 = 22;
    pub const QUERY: u32 = 23;
    pub const SOLICIT: u32 = 24;
    pub const FORGET: u32 = 25;
    pub const YIELD: u32 = 26;
    pub const PROVIDE: u32 = 27;
}

// --- Deprecated flat aliases (accumulate IDs at old positions) ---
// These keep existing code compiling during the transition.

#[deprecated = "use accumulate::READ"]
pub const READ: u32 = accumulate::READ;
#[deprecated = "use accumulate::WRITE"]
pub const WRITE: u32 = accumulate::WRITE;
#[deprecated = "use accumulate::INFO"]
pub const INFO: u32 = accumulate::INFO;
#[deprecated = "use accumulate::BLESS"]
pub const BLESS: u32 = accumulate::BLESS;
#[deprecated = "use accumulate::ASSIGN"]
pub const ASSIGN: u32 = accumulate::ASSIGN;
#[deprecated = "use accumulate::DESIGNATE"]
pub const DESIGNATE: u32 = accumulate::DESIGNATE;
#[deprecated = "use accumulate::CHECKPOINT"]
pub const CHECKPOINT: u32 = accumulate::CHECKPOINT;
#[deprecated = "use accumulate::NEW"]
pub const NEW: u32 = accumulate::NEW;
#[deprecated = "use accumulate::UPGRADE"]
pub const UPGRADE: u32 = accumulate::UPGRADE;
#[deprecated = "use accumulate::TRANSFER"]
pub const TRANSFER: u32 = accumulate::TRANSFER;
#[deprecated = "use accumulate::EJECT"]
pub const EJECT: u32 = accumulate::EJECT;
#[deprecated = "use accumulate::QUERY"]
pub const QUERY: u32 = accumulate::QUERY;
#[deprecated = "use accumulate::SOLICIT"]
pub const SOLICIT: u32 = accumulate::SOLICIT;
#[deprecated = "use accumulate::FORGET"]
pub const FORGET: u32 = accumulate::FORGET;
#[deprecated = "use accumulate::YIELD"]
pub const YIELD: u32 = accumulate::YIELD;
#[deprecated = "use accumulate::PROVIDE"]
pub const PROVIDE: u32 = accumulate::PROVIDE;
