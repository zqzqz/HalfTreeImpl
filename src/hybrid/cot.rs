//! F_COT — Correlated Oblivious Transfer ideal functionality.
//!
//! In the paper, COT provides IT-MAC tuples:
//!   P₀ gets:  Δ  and  K[rᵢ]
//!   P₁ gets:  rᵢ  and  M[rᵢ] = K[rᵢ] ⊕ rᵢ·Δ
//!
//! The `CotOracle` trait abstracts this; `IdealCot` simulates it locally
//! (trusted third party — for testing only).

use crate::bits::xor_block;

/// One COT tuple from the receiver's (P₁'s) perspective.
#[derive(Clone, Debug)]
pub struct CotTuple {
    /// The receiver's choice bit.
    pub r: bool,
    /// The receiver's MAC value M[r] = K[r] ⊕ r·Δ.
    pub m: [u8; 16],
}

/// A batch of n COT tuples returned by one `extend` call.
#[derive(Clone, Debug)]
pub struct CotBatch {
    /// Sender's keys K[r₁], …, K[rₙ] (one per tuple).
    pub sender_keys: Vec<[u8; 16]>,
    /// Receiver's tuples (rᵢ, M[rᵢ]) for i ∈ [1,n].
    pub receiver: Vec<CotTuple>,
}

/// Abstract COT oracle (F_COT in the paper).
pub trait CotOracle {
    /// One-time initialisation: returns Δ to the sender (P₀).
    fn delta(&self) -> [u8; 16];

    /// Extend: generate `n` fresh COT tuples under the stored Δ.
    fn extend(&mut self, n: usize) -> CotBatch;
}

// ---------------------------------------------------------------------------
// Ideal (simulated) COT — trusted-dealer model, for testing
// ---------------------------------------------------------------------------

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

pub struct IdealCot {
    delta: [u8; 16],
    rng: ChaCha20Rng,
}

impl IdealCot {
    pub fn new(seed: u64) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut delta = [0u8; 16];
        rng.fill_bytes(&mut delta);
        delta[15] |= 1; // ensure LSB = 1
        IdealCot { delta, rng }
    }

    pub fn new_with_delta(delta: [u8; 16], seed: u64) -> Self {
        assert!(delta[15] & 1 == 1, "Δ must have LSB = 1");
        IdealCot { delta, rng: ChaCha20Rng::seed_from_u64(seed) }
    }
}

impl CotOracle for IdealCot {
    fn delta(&self) -> [u8; 16] { self.delta }

    fn extend(&mut self, n: usize) -> CotBatch {
        let mut sender_keys = Vec::with_capacity(n);
        let mut receiver = Vec::with_capacity(n);

        for _ in 0..n {
            let mut k = [0u8; 16];
            self.rng.fill_bytes(&mut k);

            let r: bool = (self.rng.next_u32() & 1) == 1;

            // M[r] = K[r] ⊕ r·Δ
            let m = if r { xor_block(&k, &self.delta) } else { k };

            sender_keys.push(k);
            receiver.push(CotTuple { r, m });
        }

        CotBatch { sender_keys, receiver }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cot_relation_holds() {
        let mut cot = IdealCot::new(42);
        let delta = cot.delta();
        let batch = cot.extend(16);

        for (k, tup) in batch.sender_keys.iter().zip(batch.receiver.iter()) {
            // M[r] = K[r] ⊕ r·Δ
            let expected = if tup.r { xor_block(k, &delta) } else { *k };
            assert_eq!(tup.m, expected);
        }
    }
}
