//! `DPF.Eval` — evaluate a single DPF key at one input point.
//!
//! Follows Figure 8 of the paper exactly.
//!
//! Key formulas:
//!   Intermediate levels (i ∈ [1, n-1]):
//!     node_b := H_S(prev_b) ⊕ x_i · prev_b ⊕ t_{prev,b} · CW_i
//!
//!   Last level (level n):
//!     (high ‖ low)_b := H_S(prev_b ⊕ x_n)
//!     node_b := (high ‖ low)_b ⊕ t_{prev,b} · (HCW ‖ LCW_{x_n})
//!
//!   Output:
//!     y_b := (-1)^b · (ConvertR(s_n_b) + t_n_b · CW_{n+1})

use crate::bits::{lsb, high_bits, xor_block, xor_block_inplace, set_lsb};
use crate::dpf::key::DpfKey;
use crate::field::DpfRange;
use crate::hash::SeedExpander;
use crate::seed::{Seed, SeedTag, Tag};

/// Evaluate the DPF key held by party `b` at input `x` (MSB-first bits).
/// Returns the party's additive share of the output: y_b ∈ R.
pub fn eval<R: DpfRange, E: SeedExpander>(
    party: bool,       // b ∈ {0, 1}
    expander: &E,
    key: &DpfKey<R>,
    x_bits: &[bool],   // length n, MSB first
) -> R {
    let n = x_bits.len();
    assert!(!x_bits.is_empty(), "domain depth must be >= 1");
    assert_eq!(
        key.prefix_cws.len(),
        n.saturating_sub(1),
        "key has wrong number of prefix correction words"
    );

    // Current on-path node (full λ-bit block = seed ‖ tag in LSB).
    // The root block includes the tag in its LSB — preserve it as-is.
    let mut node: [u8; 16] = key.root.0;

    // ---------------------------------------------------------------
    // Intermediate levels 1 .. n-1  (Figure 8, lines 2-3)
    // node_b := H_S(node_b) ⊕ x_i · node_b ⊕ t_{node_b} · CW_i
    // ---------------------------------------------------------------
    for (i, cw) in key.prefix_cws.iter().enumerate() {
        let t = lsb(&node);
        let h = expander.hash(&node);

        // Select child: H_S(node) ⊕ x_i · node
        let mut child = if x_bits[i] {
            xor_block(&h, &node)   // right child
        } else {
            h                      // left child
        };

        // Apply correction if parent tag == 1.
        if t {
            xor_block_inplace(&mut child, &cw.0);
        }

        node = child;
    }

    // ---------------------------------------------------------------
    // Last level n  (Figure 8, lines 4-5)
    // (high ‖ low)_b := H_S(node_b ⊕ x_n)
    // node_b := (high ‖ low)_b ⊕ t_{prev} · (HCW ‖ LCW_{x_n})
    // ---------------------------------------------------------------
    let t_prev = lsb(&node);
    {
        let x_n = x_bits[n - 1];
        let cw = &key.last_cw;

        // H_S(node ⊕ x_n)  — flip LSB if x_n = 1
        let mut tweaked = node;
        if x_n { tweaked[15] ^= 0x01; }
        let hashed = expander.hash(&tweaked);

        // Split into (high, low): high = λ-1 bits (LSB cleared), low = LSB.
        let mut s = high_bits(&hashed);
        let mut t = lsb(&hashed);

        // Apply (HCW ‖ LCW_{x_n}) when parent tag == 1.
        if t_prev {
            xor_block_inplace(&mut s, &cw.hcw);
            t ^= if x_n { cw.lcw1 } else { cw.lcw0 };
        }

        // Pack back into a full block.
        set_lsb(&mut s, t);
        node = s;
    }

    // ---------------------------------------------------------------
    // Output  (Figure 8, line 6)
    // y_b := (-1)^b · (ConvertR(s_n) + t_n · CW_{n+1})
    // ---------------------------------------------------------------
    let s_n = high_bits(&node);   // seed = high λ-1 bits
    let t_n = lsb(&node);         // tag  = LSB

    let convert = R::convert(&s_n);
    let tag_part = key.out_cw.clone() * t_n;
    let raw = convert + tag_part;

    if party { -raw } else { raw }
}
