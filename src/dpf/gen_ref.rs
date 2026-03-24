//! Reference (trusted-dealer) DPF key generation — Figure 8 of the paper.
//!
//! This is a *non-interactive* centralised keygen for testing.
//! It is NOT the two-party protocol from Figure 10.
//!
//! Follows Figure 8 exactly:
//!   Intermediate levels (i ∈ [1, n-1]):
//!     CW_i   = H_S(node_P0) ⊕ H_S(node_P1) ⊕ α_i · Δ
//!     node_b := H_S(node_b) ⊕ α_i · node_b ⊕ t_b · CW_i
//!
//!   Last level (level n):
//!     (high_σ ‖ low_σ)_b := H_S(node_b ⊕ σ)  for σ ∈ {0,1}
//!     HCW  = ⟨high_{α_n}⟩_0 ⊕ ⟨high_{α_n}⟩_1
//!     LCW_σ = ⟨low_σ⟩_0 ⊕ ⟨low_σ⟩_1 ⊕ α_n  (with extra ⊕0 vs ⊕1 per the paper)
//!     node_b := (high_{α_n} ‖ low_{α_n})_b ⊕ t_{n-1,b} · (HCW ‖ LCW_{α_n})
//!
//!   Output CW:
//!     CW_{n+1} = (t_n_P0 − t_n_P1) · (ConvertR(s_n_P1) − ConvertR(s_n_P0) + β)

use crate::bits::{lsb, high_bits, xor_block, xor_block_inplace, set_lsb};
use crate::dpf::key::{DpfKey, LastCw, PrefixCw};
use crate::field::DpfRange;
use crate::hash::SeedExpander;
use crate::seed::Seed;

/// Generate a (k₀, k₁) DPF key pair for the point function f^{α,β}.
///
/// * `alpha_bits` — the special point α in MSB-first bits (length n)
/// * `beta`       — the non-zero output value β ∈ R
/// * `delta`      — global offset Δ (λ bits, LSB must be 1)
/// * `root0`      — P₀'s root share (λ bits); P₁'s root = root0 ⊕ Δ
pub fn gen<R: DpfRange, E: SeedExpander>(
    expander: &E,
    alpha_bits: &[bool],
    beta: R,
    delta: [u8; 16],
    root0: [u8; 16],
) -> (DpfKey<R>, DpfKey<R>) {
    let n = alpha_bits.len();
    assert!(n >= 1);
    assert!(lsb(&delta), "Δ must have LSB = 1");

    // root1 = root0 ⊕ Δ  (Fig. 8, line 3)
    let root1 = xor_block(&root0, &delta);

    // Current on-path node shares (full λ-bit block, tag in LSB).
    // Tags come from the random root blocks; do NOT force them to 0.
    let mut node0 = root0;
    let mut node1 = root1;

    let mut prefix_cws: Vec<PrefixCw> = Vec::with_capacity(n.saturating_sub(1));

    // ------------------------------------------------------------------
    // Intermediate levels 1 .. n-1  (Figure 8, lines 4-7)
    // ------------------------------------------------------------------
    for i in 0..(n.saturating_sub(1)) {
        let alpha_i = alpha_bits[i];
        let t0 = lsb(&node0);
        let t1 = lsb(&node1);

        let h0 = expander.hash(&node0);
        let h1 = expander.hash(&node1);

        // CW_i = H_S(node_P0) ⊕ H_S(node_P1) ⊕ α_i · Δ  (line 5)
        let mut cw = xor_block(&h0, &h1);
        if alpha_i {
            xor_block_inplace(&mut cw, &delta);
        }

        // Advance on-path nodes (lines 6-7):
        //   node_b := H_S(node_b) ⊕ α_i · node_b ⊕ t_b · CW_i
        let mut new0 = if alpha_i { xor_block(&h0, &node0) } else { h0 };
        if t0 { xor_block_inplace(&mut new0, &cw); }

        let mut new1 = if alpha_i { xor_block(&h1, &node1) } else { h1 };
        if t1 { xor_block_inplace(&mut new1, &cw); }

        node0 = new0;
        node1 = new1;
        prefix_cws.push(PrefixCw(cw));
    }

    // ------------------------------------------------------------------
    // Last level n  (Figure 8, lines 8-14)
    // ------------------------------------------------------------------
    let alpha_n = alpha_bits[n - 1];
    let t_prev0 = lsb(&node0);
    let t_prev1 = lsb(&node1);

    // (high_σ ‖ low_σ)_b := H_S(node_b ⊕ σ)  (lines 8-9)
    let (high0_s0, low0_s0, high0_s1, low0_s1) = expand_last_split(expander, &node0);
    let (high1_s0, low1_s0, high1_s1, low1_s1) = expand_last_split(expander, &node1);

    // HCW = ⟨high_{α_n}⟩_0 ⊕ ⟨high_{α_n}⟩_1  (line 10)
    let hcw = if alpha_n {
        xor_block(&high0_s1, &high1_s1)
    } else {
        xor_block(&high0_s0, &high1_s0)
    };

    // LCW_0 = ⟨low_0⟩_0 ⊕ ⟨low_0⟩_1 ⊕ α_n ⊕ 1  (the ⊕1 comes from Fig 10's
    //   share formula ⟨LCW_0⟩_b = ⟨X_{low,0}⟩_b ⊕ ⟨α_n⟩_b ⊕ b; the ⊕b
    //   contributes ⊕1 when the two shares are XOR-ed. Fig 8 line 11 is a typo.)
    // LCW_1 = ⟨low_1⟩_0 ⊕ ⟨low_1⟩_1 ⊕ α_n
    let lcw0 = low0_s0 ^ low1_s0 ^ alpha_n ^ true;
    let lcw1 = low0_s1 ^ low1_s1 ^ alpha_n;

    let last_cw = LastCw { hcw, lcw0, lcw1 };

    // Advance on-path nodes to level n (lines 13-14):
    //   node_b := (high_{α_n} ‖ low_{α_n})_b ⊕ t_{prev,b} · (HCW ‖ LCW_{α_n})
    let (mut sn0, mut tn0) = if alpha_n { (high0_s1, low0_s1) } else { (high0_s0, low0_s0) };
    if t_prev0 {
        xor_block_inplace(&mut sn0, &hcw);
        tn0 ^= if alpha_n { lcw1 } else { lcw0 };
    }

    let (mut sn1, mut tn1) = if alpha_n { (high1_s1, low1_s1) } else { (high1_s0, low1_s0) };
    if t_prev1 {
        xor_block_inplace(&mut sn1, &hcw);
        tn1 ^= if alpha_n { lcw1 } else { lcw0 };
    }

    // ------------------------------------------------------------------
    // Output correction word CW_{n+1}  (Figure 8, line 15)
    // CW_{n+1} = (t_n_P0 − t_n_P1) · (ConvertR(s_n_P1) − ConvertR(s_n_P0) + β)
    // In binary-field arithmetic − = +, and (bool − bool) is nonzero iff they differ.
    // The formula simplifies to: if t_n_P0 ≠ t_n_P1, one party holds β; otherwise 0.
    // ------------------------------------------------------------------
    let out_cw: R = if tn0 == tn1 {
        // Tags agree → no correction needed for the output.
        // (The signs cancel.)
        R::zero()
    } else {
        // (t_n_P0 − t_n_P1) is ±1; (ConvertR(s1) − ConvertR(s0) + β) is computed.
        let diff = R::convert(&sn1) - R::convert(&sn0) + beta.clone();
        if tn0 {
            // t_n_P0=1, t_n_P1=0 → factor is +1
            diff
        } else {
            // t_n_P0=0, t_n_P1=1 → factor is -1
            -diff
        }
    };

    // ------------------------------------------------------------------
    // Assemble keys  (Figure 8, line 16)
    // k_b = (root_b, {CW_i}, CW_{n+1})
    // ------------------------------------------------------------------
    let key0 = DpfKey {
        root: Seed(root0),
        prefix_cws: prefix_cws.clone(),
        last_cw: last_cw.clone(),
        out_cw: out_cw.clone(),
    };
    let key1 = DpfKey {
        root: Seed(root1),
        prefix_cws,
        last_cw,
        out_cw,
    };

    (key0, key1)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Expand a node at the last level: returns (high0, low0, high1, low1)
/// where high_σ = high bits of H_S(node ⊕ σ), low_σ = LSB.
fn expand_last_split<E: SeedExpander>(
    expander: &E,
    node: &[u8; 16],
) -> ([u8; 16], bool, [u8; 16], bool) {
    let ex = expander.expand_last(node);
    (ex.high0(), ex.low0(), ex.high1(), ex.low1())
}
