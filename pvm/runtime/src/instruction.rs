//! PVM instruction set (Gray Paper v0.8.0 / Appendix A.5).
//!
//! Opcodes and instruction categories matching the specification exactly.

/// PVM opcodes (ζᵢ values from Appendix A.5).
///
/// Organized by instruction category matching the spec sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    // A.5.1: No arguments
    Trap = 0,
    Fallthrough = 1,
    Unlikely = 2,
    /// VOS capability-runtime extension for management ops and dynamic CALL.
    /// This discriminant is deliberately excluded from the Gray Paper opcode
    /// set decoded by [`Opcode::from_byte`].
    Ecall = 3,

    // A.5.2: One immediate
    Ecalli = 10,

    // A.5.3: One register + extended width immediate
    LoadImm64 = 20,

    // A.5.4: Two immediates
    StoreImmU8 = 30,
    StoreImmU16 = 31,
    StoreImmU32 = 32,
    StoreImmU64 = 33,

    // A.5.5: One offset
    Jump = 40,

    // A.5.6: One register + one immediate
    JumpInd = 50,
    LoadImm = 51,
    LoadU8 = 52,
    LoadI8 = 53,
    LoadU16 = 54,
    LoadI16 = 55,
    LoadU32 = 56,
    LoadI32 = 57,
    LoadU64 = 58,
    StoreU8 = 59,
    StoreU16 = 60,
    StoreU32 = 61,
    StoreU64 = 62,

    // A.5.7: One register + two immediates
    StoreImmIndU8 = 70,
    StoreImmIndU16 = 71,
    StoreImmIndU32 = 72,
    StoreImmIndU64 = 73,

    // A.5.8: One register + one immediate + one offset
    LoadImmJump = 80,
    BranchEqImm = 81,
    BranchNeImm = 82,
    BranchLtUImm = 83,
    BranchLeUImm = 84,
    BranchGeUImm = 85,
    BranchGtUImm = 86,
    BranchLtSImm = 87,
    BranchLeSImm = 88,
    BranchGeSImm = 89,
    BranchGtSImm = 90,

    // A.5.9: Two registers
    MoveReg = 100,
    CountSetBits64 = 101,
    CountSetBits32 = 102,
    LeadingZeroBits64 = 103,
    LeadingZeroBits32 = 104,
    TrailingZeroBits64 = 105,
    TrailingZeroBits32 = 106,
    SignExtend8 = 107,
    SignExtend16 = 108,
    ZeroExtend16 = 109,
    ReverseBytes = 110,

    // A.5.10: Two registers + one immediate
    StoreIndU8 = 120,
    StoreIndU16 = 121,
    StoreIndU32 = 122,
    StoreIndU64 = 123,
    LoadIndU8 = 124,
    LoadIndI8 = 125,
    LoadIndU16 = 126,
    LoadIndI16 = 127,
    LoadIndU32 = 128,
    LoadIndI32 = 129,
    LoadIndU64 = 130,
    AddImm32 = 131,
    AndImm = 132,
    XorImm = 133,
    OrImm = 134,
    MulImm32 = 135,
    SetLtUImm = 136,
    SetLtSImm = 137,
    ShloLImm32 = 138,
    ShloRImm32 = 139,
    SharRImm32 = 140,
    NegAddImm32 = 141,
    SetGtUImm = 142,
    SetGtSImm = 143,
    ShloLImmAlt32 = 144,
    ShloRImmAlt32 = 145,
    SharRImmAlt32 = 146,
    CmovIzImm = 147,
    CmovNzImm = 148,
    AddImm64 = 149,
    MulImm64 = 150,
    ShloLImm64 = 151,
    ShloRImm64 = 152,
    SharRImm64 = 153,
    NegAddImm64 = 154,
    ShloLImmAlt64 = 155,
    ShloRImmAlt64 = 156,
    SharRImmAlt64 = 157,
    RotR64Imm = 158,
    RotR64ImmAlt = 159,
    RotR32Imm = 160,
    RotR32ImmAlt = 161,

    // A.5.11: Two registers + one offset
    BranchEq = 170,
    BranchNe = 171,
    BranchLtU = 172,
    BranchLtS = 173,
    BranchGeU = 174,
    BranchGeS = 175,

    // A.5.12: Two registers + two immediates
    LoadImmJumpInd = 180,

    /// Synthetic marker for an invalid opcode at an instruction-start
    /// position. Never produced by `from_byte` (255 is not in the opcode
    /// table) — only the interpreter's predecoder emits it, so the fast
    /// execution loop panics at the invalid instruction exactly like the
    /// step path and the JIT do, instead of silently skipping it.
    Invalid = 255,

    // A.5.13: Three registers
    Add32 = 190,
    Sub32 = 191,
    Mul32 = 192,
    DivU32 = 193,
    DivS32 = 194,
    RemU32 = 195,
    RemS32 = 196,
    ShloL32 = 197,
    ShloR32 = 198,
    SharR32 = 199,
    Add64 = 200,
    Sub64 = 201,
    Mul64 = 202,
    DivU64 = 203,
    DivS64 = 204,
    RemU64 = 205,
    RemS64 = 206,
    ShloL64 = 207,
    ShloR64 = 208,
    SharR64 = 209,
    And = 210,
    Xor = 211,
    Or = 212,
    MulUpperSS = 213,
    MulUpperUU = 214,
    MulUpperSU = 215,
    SetLtU = 216,
    SetLtS = 217,
    CmovIz = 218,
    CmovNz = 219,
    RotL64 = 220,
    RotL32 = 221,
    RotR64 = 222,
    RotR32 = 223,
    AndInv = 224,
    OrInv = 225,
    Xnor = 226,
    Max = 227,
    MaxU = 228,
    Min = 229,
    MinU = 230,
}

/// Lookup table for the exact Gray Paper v0.8.0 opcode set `U`.
/// `OPCODE_TABLE[byte] = 1` iff the byte is a valid standard opcode.
static OPCODE_TABLE: [u8; 256] = {
    let mut t = [0u8; 256];
    let valid: &[u8] = &[
        0, 1, 2, 10, 20, 30, 31, 32, 33, 40, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
        70, 71, 72, 73, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 100, 101, 102, 103, 104, 105,
        106, 107, 108, 109, 110, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132,
        133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150,
        151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 170, 171, 172, 173, 174, 175, 180,
        190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
        208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
        226, 227, 228, 229, 230,
    ];
    let mut i = 0;
    while i < valid.len() {
        t[valid[i] as usize] = 1;
        i += 1;
    }
    t
};

impl Opcode {
    /// Try to decode an opcode from a byte (eq A.19). O(1) lookup.
    #[inline(always)]
    pub fn from_byte(byte: u8) -> Option<Self> {
        if OPCODE_TABLE[byte as usize] != 0 {
            // SAFETY: we verified the byte is a valid opcode via lookup table
            Some(unsafe { core::mem::transmute::<u8, Opcode>(byte) })
        } else {
            None
        }
    }

    /// Decode the frozen VOS capability-runtime ISA.
    ///
    /// In addition to opcode 3, capability-manifest artifacts predate the
    /// v0.8 removal of `sbrk` and the resulting unary-opcode renumbering.
    /// Keep that translation here, never in the standard decoder used by SPI
    /// programs or Refine inner machines.
    #[inline(always)]
    pub(crate) fn from_runtime_byte(byte: u8) -> Option<Self> {
        match byte {
            3 => Some(Self::Ecall),
            // The removed private `sbrk` instruction always trapped. Decode
            // it to the runtime's synthetic panic operation without exposing
            // `sbrk` as part of the public standard opcode enum.
            101 => Some(Self::Invalid),
            102 => Some(Self::CountSetBits64),
            103 => Some(Self::CountSetBits32),
            104 => Some(Self::LeadingZeroBits64),
            105 => Some(Self::LeadingZeroBits32),
            106 => Some(Self::TrailingZeroBits64),
            107 => Some(Self::TrailingZeroBits32),
            108 => Some(Self::SignExtend8),
            109 => Some(Self::SignExtend16),
            110 => Some(Self::ZeroExtend16),
            111 => Some(Self::ReverseBytes),
            _ => Self::from_byte(byte),
        }
    }

    /// Decode an encoded opcode under the selected execution profile.
    ///
    /// Capability-manifest programs retain the frozen pre-v0.8 unary
    /// numbering, while standard programs use the exact Gray Paper v0.8
    /// table. Proof tooling uses this entry point so trace construction and
    /// program-memory commitments cannot silently reinterpret a program
    /// under a different profile than the live executor.
    #[inline(always)]
    pub fn from_byte_in_mode(byte: u8, isa_mode: crate::IsaMode) -> Option<Self> {
        match isa_mode {
            crate::IsaMode::Jar => Self::from_runtime_byte(byte),
            crate::IsaMode::Conformance => Self::from_byte(byte),
        }
    }

    /// Instruction category determining the argument format.
    pub fn category(self) -> InstructionCategory {
        let b = self as u8;
        match b {
            0..=3 => InstructionCategory::NoArgs,
            10 => InstructionCategory::OneImm,
            20 => InstructionCategory::OneRegExtImm,
            30..=33 => InstructionCategory::TwoImm,
            40 => InstructionCategory::OneOffset,
            50..=62 => InstructionCategory::OneRegOneImm,
            70..=73 => InstructionCategory::OneRegTwoImm,
            80..=90 => InstructionCategory::OneRegImmOffset,
            100..=110 => InstructionCategory::TwoReg,
            120..=161 => InstructionCategory::TwoRegOneImm,
            170..=175 => InstructionCategory::TwoRegOneOffset,
            180 => InstructionCategory::TwoRegTwoImm,
            190..=230 => InstructionCategory::ThreeReg,
            _ => InstructionCategory::NoArgs, // unreachable for valid opcodes
        }
    }

    /// Gas cost for this instruction (ϱ∆). All instructions cost 1.
    pub fn gas_cost(self) -> u64 {
        1
    }

    /// Whether this opcode is a basic-block termination instruction (set T).
    #[cfg_attr(feature = "std", inline(always))]
    pub fn is_terminator(self) -> bool {
        matches!(
            self,
            Opcode::Trap
                | Opcode::Fallthrough
                | Opcode::Jump
                | Opcode::JumpInd
                | Opcode::LoadImmJump
                | Opcode::LoadImmJumpInd
                | Opcode::BranchEq
                | Opcode::BranchNe
                | Opcode::BranchLtU
                | Opcode::BranchLtS
                | Opcode::BranchGeU
                | Opcode::BranchGeS
                | Opcode::BranchEqImm
                | Opcode::BranchNeImm
                | Opcode::BranchLtUImm
                | Opcode::BranchLtSImm
                | Opcode::BranchLeUImm
                | Opcode::BranchLeSImm
                | Opcode::BranchGeUImm
                | Opcode::BranchGeSImm
                | Opcode::BranchGtUImm
                | Opcode::BranchGtSImm
        )
    }

    /// Capability-runtime block boundary predicate.
    ///
    /// Opcode 3 exits to that runtime and must therefore provide a resumable
    /// post-instruction entry. The standard Gray Paper set remains available
    /// through [`Self::is_terminator`].
    pub(crate) fn is_runtime_terminator(self) -> bool {
        self.is_terminator() || self == Self::Ecall
    }
}

/// Instruction argument category (determines how operands are decoded).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionCategory {
    /// A.5.1: No arguments (trap, fallthrough)
    NoArgs,
    /// A.5.2: One immediate (ecalli)
    OneImm,
    /// A.5.3: One register + extended width immediate (load_imm_64)
    OneRegExtImm,
    /// A.5.4: Two immediates (store_imm_*)
    TwoImm,
    /// A.5.5: One offset (jump)
    OneOffset,
    /// A.5.6: One register + one immediate
    OneRegOneImm,
    /// A.5.7: One register + two immediates
    OneRegTwoImm,
    /// A.5.8: One register + one immediate + one offset
    OneRegImmOffset,
    /// A.5.9: Two registers
    TwoReg,
    /// A.5.10: Two registers + one immediate
    TwoRegOneImm,
    /// A.5.11: Two registers + one offset
    TwoRegOneOffset,
    /// A.5.12: Two registers + two immediates
    TwoRegTwoImm,
    /// A.5.13: Three registers
    ThreeReg,
}

/// Pre-computed lookup table: opcode byte → InstructionCategory.
/// Eliminates the match in `Opcode::category()` from the hot compilation loop.
/// Invalid opcodes map to NoArgs (same as the fallback in category()).
static CATEGORY_LUT: [InstructionCategory; 256] = {
    let mut t = [InstructionCategory::NoArgs; 256];
    // OneImm
    t[10] = InstructionCategory::OneImm;
    // OneRegExtImm
    t[20] = InstructionCategory::OneRegExtImm;
    // TwoImm
    t[30] = InstructionCategory::TwoImm;
    t[31] = InstructionCategory::TwoImm;
    t[32] = InstructionCategory::TwoImm;
    t[33] = InstructionCategory::TwoImm;
    // OneOffset
    t[40] = InstructionCategory::OneOffset;
    // OneRegOneImm
    let mut i = 50;
    while i <= 62 {
        t[i] = InstructionCategory::OneRegOneImm;
        i += 1;
    }
    // OneRegTwoImm
    i = 70;
    while i <= 73 {
        t[i] = InstructionCategory::OneRegTwoImm;
        i += 1;
    }
    // OneRegImmOffset
    i = 80;
    while i <= 90 {
        t[i] = InstructionCategory::OneRegImmOffset;
        i += 1;
    }
    // TwoReg
    i = 100;
    while i <= 110 {
        t[i] = InstructionCategory::TwoReg;
        i += 1;
    }
    // TwoRegOneImm
    i = 120;
    while i <= 161 {
        t[i] = InstructionCategory::TwoRegOneImm;
        i += 1;
    }
    // TwoRegOneOffset
    i = 170;
    while i <= 175 {
        t[i] = InstructionCategory::TwoRegOneOffset;
        i += 1;
    }
    // TwoRegTwoImm
    t[180] = InstructionCategory::TwoRegTwoImm;
    // ThreeReg
    i = 190;
    while i <= 230 {
        t[i] = InstructionCategory::ThreeReg;
        i += 1;
    }
    t
};

impl InstructionCategory {
    /// Look up category from raw opcode byte via static table (O(1), no branching).
    #[inline(always)]
    pub fn from_opcode_byte(b: u8) -> Self {
        CATEGORY_LUT[b as usize]
    }
}

/// Combined opcode validation + category lookup in a single array access.
/// Returns (is_valid, category) packed into a u8: high bit = valid, low 4 bits = category.
static OPCODE_COMBINED: [u8; 256] = {
    let mut t = [0u8; 256]; // 0 = invalid
    // Build from OPCODE_TABLE (valid opcodes) and CATEGORY_LUT
    let mut i = 0;
    while i < 256 {
        if OPCODE_TABLE[i] != 0 {
            t[i] = 0x80 | (CATEGORY_LUT[i] as u8); // bit 7 = valid, low bits = category
        }
        i += 1;
    }
    t
};

/// Look up opcode validity and category in a single array access.
/// Returns None for invalid opcodes, Some((Opcode, InstructionCategory)) for valid ones.
#[inline(always)]
pub fn decode_opcode_fast(b: u8) -> Option<(Opcode, InstructionCategory)> {
    let entry = OPCODE_COMBINED[b as usize];
    if entry & 0x80 != 0 {
        // SAFETY: b is a valid Opcode discriminant — OPCODE_COMBINED[b] has bit 7 set
        // only for bytes that correspond to defined Opcode variants.
        let opcode = unsafe { core::mem::transmute::<u8, Opcode>(b) };
        let category = CATEGORY_LUT[b as usize];
        Some((opcode, category))
    } else {
        None
    }
}

/// [`decode_opcode_fast`] plus the capability-runtime opcode 3 extension.
#[inline(always)]
pub(crate) fn decode_runtime_opcode_fast(b: u8) -> Option<(Opcode, InstructionCategory)> {
    Opcode::from_runtime_byte(b).map(|opcode| (opcode, opcode.category()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_opcodes() {
        assert_eq!(Opcode::from_byte(0), Some(Opcode::Trap));
        assert_eq!(Opcode::from_byte(1), Some(Opcode::Fallthrough));
        assert_eq!(Opcode::from_byte(10), Some(Opcode::Ecalli));
        assert_eq!(Opcode::from_byte(40), Some(Opcode::Jump));
        assert_eq!(Opcode::from_byte(100), Some(Opcode::MoveReg));
        assert_eq!(Opcode::from_byte(101), Some(Opcode::CountSetBits64));
        assert_eq!(Opcode::from_byte(110), Some(Opcode::ReverseBytes));
        assert_eq!(Opcode::from_byte(200), Some(Opcode::Add64));
        assert_eq!(Opcode::from_byte(230), Some(Opcode::MinU));
    }

    #[test]
    fn test_invalid_opcodes() {
        assert_eq!(Opcode::from_byte(2), Some(Opcode::Unlikely));
        assert_eq!(Opcode::from_byte(3), None);
        assert_eq!(Opcode::from_runtime_byte(3), Some(Opcode::Ecall));
        assert_eq!(Opcode::from_byte(111), None);
        assert_eq!(Opcode::from_byte(254), None);
        assert_eq!(Opcode::from_byte(15), None);
        assert_eq!(Opcode::from_byte(255), None);
    }

    #[test]
    fn capability_runtime_renumbering_is_private() {
        assert_eq!(Opcode::from_runtime_byte(101), Some(Opcode::Invalid));
        assert_eq!(Opcode::from_runtime_byte(102), Some(Opcode::CountSetBits64));
        assert_eq!(Opcode::from_runtime_byte(111), Some(Opcode::ReverseBytes));
    }

    #[test]
    fn graypaper_terminator_set_excludes_markers_and_host_calls() {
        assert!(!Opcode::Unlikely.is_terminator());
        assert!(!Opcode::Ecalli.is_terminator());
        assert!(!Opcode::Ecall.is_terminator());
        assert!(Opcode::Trap.is_terminator());
        assert!(Opcode::Fallthrough.is_terminator());
        assert!(Opcode::Jump.is_terminator());
        assert!(Opcode::Ecall.is_runtime_terminator());
    }

    #[test]
    fn test_categories() {
        assert_eq!(Opcode::Trap.category(), InstructionCategory::NoArgs);
        assert_eq!(Opcode::Ecalli.category(), InstructionCategory::OneImm);
        assert_eq!(
            Opcode::LoadImm64.category(),
            InstructionCategory::OneRegExtImm
        );
        assert_eq!(Opcode::StoreImmU8.category(), InstructionCategory::TwoImm);
        assert_eq!(Opcode::Jump.category(), InstructionCategory::OneOffset);
        assert_eq!(
            Opcode::LoadImm.category(),
            InstructionCategory::OneRegOneImm
        );
        assert_eq!(
            Opcode::StoreImmIndU8.category(),
            InstructionCategory::OneRegTwoImm
        );
        assert_eq!(
            Opcode::LoadImmJump.category(),
            InstructionCategory::OneRegImmOffset
        );
        assert_eq!(Opcode::MoveReg.category(), InstructionCategory::TwoReg);
        assert_eq!(
            Opcode::AddImm32.category(),
            InstructionCategory::TwoRegOneImm
        );
        assert_eq!(
            Opcode::BranchEq.category(),
            InstructionCategory::TwoRegOneOffset
        );
        assert_eq!(
            Opcode::LoadImmJumpInd.category(),
            InstructionCategory::TwoRegTwoImm
        );
        assert_eq!(Opcode::Add64.category(), InstructionCategory::ThreeReg);
    }
}
