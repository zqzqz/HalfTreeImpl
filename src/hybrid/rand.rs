//! F_Rand — coin-tossing ideal functionality.
//!
//! Both parties receive the same uniformly random λ-bit block.
//! In the real protocol this is realised from COT; here we simulate it.

pub trait RandOracle {
    /// Sample a shared random 16-byte block (one call to F_Rand).
    fn sample_block(&mut self) -> [u8; 16];
}

// ---------------------------------------------------------------------------
// Ideal (shared-seed) implementation — for testing
// ---------------------------------------------------------------------------

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct IdealRand {
    rng: ChaCha20Rng,
}

impl IdealRand {
    pub fn new(seed: u64) -> Self {
        IdealRand { rng: ChaCha20Rng::seed_from_u64(seed) }
    }
}

impl RandOracle for IdealRand {
    fn sample_block(&mut self) -> [u8; 16] {
        let mut block = [0u8; 16];
        self.rng.fill_bytes(&mut block);
        block
    }
}
