//! F_OLE — Oblivious Linear Evaluation ideal functionality.
//!
//! Two parties receive additive shares of x₀ ⊙ x₁ (component-wise product).
//! Only needed for the general-ring path of Figure 10; not used in v1.

use crate::field::DpfRange;

pub trait OleOracle<R: DpfRange> {
    /// Returns (share_for_p0, share_for_p1) such that both sum to a·b.
    fn multiply(&mut self, a: R, b: R) -> (R, R);
}

/// Placeholder — panics if called; replace with a real OLE when needed.
pub struct DummyOle;

impl<R: DpfRange> OleOracle<R> for DummyOle {
    fn multiply(&mut self, _a: R, _b: R) -> (R, R) {
        unimplemented!("OLE is not yet implemented; use the binary-field path")
    }
}
