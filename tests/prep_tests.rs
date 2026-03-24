//! Tests for the Π_PREP preprocessing sub-protocol (Figure 11).

use half_tree_dpf::{
    hybrid::cot::IdealCot,
    protocol::prep::run_prep,
};

#[test]
fn delta_lsb_xor_is_one() {
    for seed in [0u64, 1, 42, 0xdead_beef] {
        let alpha = vec![true, false, true, true];
        let mut cot0 = IdealCot::new(seed);
        let mut cot1 = IdealCot::new(seed + 1000);
        let (p0, p1) = run_prep(&alpha, &mut cot0, &mut cot1);
        let xor_lsb = (p0.delta_share[15] ^ p1.delta_share[15]) & 1;
        assert_eq!(xor_lsb, 1, "lsb(⟨Δ⟩₀ ⊕ ⟨Δ⟩₁) must be 1 (seed={seed})");
    }
}

#[test]
fn output_lengths_equal_n() {
    for n in [1, 4, 8, 16] {
        let alpha = vec![false; n];
        let mut cot0 = IdealCot::new(7);
        let mut cot1 = IdealCot::new(13);
        let (p0, p1) = run_prep(&alpha, &mut cot0, &mut cot1);
        assert_eq!(p0.k_vals.len(), n);
        assert_eq!(p0.m_vals.len(), n);
        assert_eq!(p1.k_vals.len(), n);
        assert_eq!(p1.m_vals.len(), n);
    }
}
