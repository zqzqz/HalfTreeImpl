//! Tests for the reference (dealer) DPF.Gen + DPF.Eval.
//!
//! These verify the standalone key generation and evaluation (Figure 8)
//! independent of the two-party protocol.

use half_tree_dpf::{
    bits::decompose_bits_msb,
    dpf::{eval::eval, gen_ref::gen},
    field::{DpfRange, F2, U64},
    hash::XorExpander,
};

fn check_dpf_correctness<R: DpfRange + std::fmt::Debug>(
    n: usize,
    alpha: u128,
    beta: R,
    expander: &XorExpander,
) {
    let alpha_bits = decompose_bits_msb(alpha, n);

    // random-looking but deterministic delta and root
    let mut delta = [0u8; 16];
    delta[0] = 0xde;
    delta[15] = 0x01; // LSB = 1

    let mut root0 = [0u8; 16];
    root0[0] = 0xca;
    root0[1] = 0xfe;

    let (k0, k1) = gen(expander, &alpha_bits, beta.clone(), delta, root0);

    for x in 0u128..(1 << n) {
        let x_bits = decompose_bits_msb(x, n);
        let y0 = eval(false, expander, &k0, &x_bits);
        let y1 = eval(true,  expander, &k1, &x_bits);
        let y = y0 + y1;

        let expected = if x == alpha { beta.clone() } else { R::zero() };
        assert_eq!(
            y, expected,
            "n={n} alpha={alpha} x={x}: got {y:?} expected {expected:?}"
        );
    }
}

#[test]
fn ref_dpf_f2_n1() {
    let exp = XorExpander::new([0x42u8; 16]);
    check_dpf_correctness(1, 0, F2(true), &exp);
    check_dpf_correctness(1, 1, F2(true), &exp);
}

#[test]
fn ref_dpf_f2_small() {
    let exp = XorExpander::new([0x11u8; 16]);
    for n in 2..=6usize {
        for alpha in 0u128..(1 << n) {
            check_dpf_correctness(n, alpha, F2(true), &exp);
        }
    }
}

#[test]
fn ref_dpf_u64_small() {
    let exp = XorExpander::new([0x55u8; 16]);
    for n in 1..=5usize {
        check_dpf_correctness(n, 0, U64(42), &exp);
        check_dpf_correctness(n, (1 << n) - 1, U64(999), &exp);
    }
}
