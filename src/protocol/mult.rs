//! Π_MULT — OLE-based multiplication sub-protocol (Figure 12 of the paper).
//!
//! Computes ⟨A·B⟩ from ⟨A⟩ and ⟨B⟩ using two precomputed OLE tuples.
//! Only needed for the general-ring path of Figure 10.

use crate::field::DpfRange;
use crate::hybrid::ole::OleOracle;

/// Run Π_MULT for both parties simultaneously (local simulation).
///
/// Returns `(share_p0, share_p1)` such that `share_p0 + share_p1 = a * b`.
pub fn run_mult<R: DpfRange, O: OleOracle<R>>(
    _ole: &mut O,
    _a0: R, _b0: R,  // P₀'s shares of A and B
    _a1: R, _b1: R,  // P₁'s shares of A and B
) -> (R, R) {
    // Step 1: get OLE randomness (x₀, z₀), (x₁, z₁) with z₀+z₁ = x₀·x₁.
    unimplemented!("Π_MULT not yet implemented; use binary-field path")
}
