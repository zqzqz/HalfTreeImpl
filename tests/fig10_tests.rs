//! End-to-end correctness tests for Π_DPF (Figure 10).
//!
//! Core invariant: for all x ∈ [0, N),
//!   eval(0, k0, x) + eval(1, k1, x) = β  if x = α
//!                                   = 0  otherwise.

use half_tree_dpf::{
    bits::decompose_bits_msb,
    dpf::eval::eval,
    field::F2,
    hash::XorExpander,
    hybrid::{cot::IdealCot, rand::IdealRand},
    protocol::fig10::gen_binary,
};

fn run_fig10_correctness_f2(n: usize, alpha: u128, cot_seed: u64, rand_seed: u64) {
    let expander = XorExpander::new([0xabu8; 16]);
    let mut cot0 = IdealCot::new(cot_seed);
    let mut cot1 = IdealCot::new(cot_seed + 1);
    let mut rand = IdealRand::new(rand_seed);

    let alpha_bits = decompose_bits_msb(alpha, n);
    let pair = gen_binary(&expander, &mut cot0, &mut cot1, &mut rand, &alpha_bits, F2(true));

    for x in 0u128..(1 << n) {
        let x_bits = decompose_bits_msb(x, n);
        let y0 = eval(false, &expander, &pair.key0, &x_bits);
        let y1 = eval(true,  &expander, &pair.key1, &x_bits);
        let y = y0 + y1;

        let expected = if x == alpha { F2(true) } else { F2(false) };
        assert_eq!(
            y, expected,
            "fig10 F2: n={n} alpha={alpha} x={x}: got {y:?} expected {expected:?}"
        );
    }
}

#[test]
fn fig10_f2_n1_all_alpha() {
    for alpha in 0u128..2 {
        run_fig10_correctness_f2(1, alpha, 100, 200);
    }
}

#[test]
fn fig10_f2_n2_all_alpha() {
    for alpha in 0u128..4 {
        run_fig10_correctness_f2(2, alpha, 300, 400);
    }
}

#[test]
fn fig10_f2_n4_exhaustive() {
    for alpha in 0u128..16 {
        run_fig10_correctness_f2(4, alpha, alpha as u64 * 17 + 1, alpha as u64 * 31 + 2);
    }
}

#[test]
fn fig10_f2_n8_spot_check() {
    for alpha in [0u128, 1, 127, 128, 255] {
        run_fig10_correctness_f2(8, alpha, 999, 888);
    }
}
