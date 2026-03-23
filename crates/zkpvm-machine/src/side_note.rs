use zkpvm_core::step::PvmStep;

/// Prover's side note used for tracking additional data for trace generation.
pub struct SideNote {
    /// The execution trace steps.
    pub steps: Vec<PvmStep>,
    /// Program bytecode.
    pub code: Vec<u8>,
    /// Bitmask for instruction validation.
    pub bitmask: Vec<u8>,
    /// Range check accumulator: counts of each byte value 0..255.
    pub range256_counts: Vec<u32>,
}

impl SideNote {
    pub fn new(steps: Vec<PvmStep>, code: Vec<u8>, bitmask: Vec<u8>) -> Self {
        Self {
            steps,
            code,
            bitmask,
            range256_counts: vec![0u32; 256],
        }
    }

    pub fn num_steps(&self) -> usize {
        self.steps.len()
    }

    /// Increment the range check counter for a byte value.
    pub fn add_range256(&mut self, value: u8) {
        self.range256_counts[value as usize] += 1;
    }
}
