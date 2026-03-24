//! `DPF.NextLevel` — expand one tree level given the current node shares and
//! the corresponding public correction word.
//!
//! Follows the recursive structure of DPF.Gen / DPF.Eval in Figure 8 of the
//! paper, adapted for the distributed (two-party share) setting in Figure 10.

use crate::bits::xor_block_inplace;
use crate::dpf::key::{LastCw, PrefixCw};
use crate::hash::SeedExpander;
use crate::seed::{Seed, SeedTag, Tag};

/// Expand one intermediate level (levels 1 .. n-1).
///
/// `prev` holds the 2^{i-1} parent shares.
/// Returns the 2^i child shares in left-right order.
pub fn next_level_prefix<E: SeedExpander>(
    expander: &E,
    prev: &[SeedTag],
    cw: &PrefixCw,
) -> Vec<SeedTag> {
    let mut out = Vec::with_capacity(prev.len() * 2);

    for node in prev {
        // Pass the full (seed ‖ tag) block; expand uses the half-tree formula:
        //   left  = H_S(block)
        //   right = H_S(block) ⊕ block
        let block = node.to_block();
        let ex = expander.expand(&block);

        // If tag == 1, XOR the correction word into both children (full block).
        let (mut left, mut right) = (ex.left, ex.right);
        if node.tag.0 {
            xor_block_inplace(&mut left, &cw.0);
            xor_block_inplace(&mut right, &cw.0);
        }

        out.push(SeedTag::from_block(left));
        out.push(SeedTag::from_block(right));
    }

    out
}

/// Expand the last level (level n-1 → level n).
///
/// Uses the structured correction word (HCW, LCW₀, LCW₁) and the path bit
/// `alpha_n` (the n-th bit of α, which selects which child is "on-path").
///
/// Returns the 2^n leaf shares.
pub fn next_level_last<E: SeedExpander>(
    expander: &E,
    prev: &[SeedTag],
    cw: &LastCw,
    _alpha_n: bool,
) -> Vec<SeedTag> {
    let mut out = Vec::with_capacity(prev.len() * 2);

    for node in prev {
        let block = node.to_block();
        let ex = expander.expand_last(&block);

        // sigma=0 child
        let mut s0 = ex.high0();
        let mut t0 = ex.low0();
        // sigma=1 child
        let mut s1 = ex.high1();
        let mut t1 = ex.low1();

        if node.tag.0 {
            xor_block_inplace(&mut s0, &cw.hcw);
            xor_block_inplace(&mut s1, &cw.hcw);
            t0 ^= cw.lcw0;
            t1 ^= cw.lcw1;
        }

        // sigma=0 → left child, sigma=1 → right child
        let mut left = s0;
        crate::bits::set_lsb(&mut left, t0);
        let mut right = s1;
        crate::bits::set_lsb(&mut right, t1);

        out.push(SeedTag::from_block(left));
        out.push(SeedTag::from_block(right));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::XorExpander;

    fn make_node(seed: [u8; 16], tag: bool) -> SeedTag {
        SeedTag { seed: Seed(seed), tag: Tag(tag) }
    }

    #[test]
    fn prefix_level_doubles_count() {
        let exp = XorExpander::new([0u8; 16]);
        let nodes = vec![make_node([1u8; 16], false)];
        let cw = PrefixCw([0u8; 16]);
        let out = next_level_prefix(&exp, &nodes, &cw);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn last_level_doubles_count() {
        let exp = XorExpander::new([0u8; 16]);
        let nodes = vec![make_node([1u8; 16], false)];
        let cw = LastCw { hcw: [0u8; 16], lcw0: false, lcw1: false };
        let out = next_level_last(&exp, &nodes, &cw, false);
        assert_eq!(out.len(), 2);
    }
}
