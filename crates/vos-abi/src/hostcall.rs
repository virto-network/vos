//! JAR hostcall IDs.
//!
//! Each constant maps to a PVM `ecalli` instruction. The host traps
//! the call and dispatches based on the ID.

pub const GAS: u32 = 0;
pub const GROW_HEAP: u32 = 1;
pub const FETCH: u32 = 2;
pub const READ: u32 = 3;
pub const WRITE: u32 = 4;
pub const INFO: u32 = 5;
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

/// vosx extension: debug output. vosx prints to stderr, JAR returns HOST_WHAT.
pub const DEBUG_WRITE: u32 = 128;
