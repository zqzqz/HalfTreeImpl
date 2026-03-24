//! Π_DPF — DPF correlation generation protocol (Figure 10 of the paper).
//!
//! Binary-field path only (v1).  The general-ring path (using Π_MULT) is
//! left as a stub.

use crate::bits::{xor_block, xor_block_inplace};
use crate::dpf::key::{DpfKey, LastCw, PrefixCw};
use crate::dpf::next_level::{next_level_last, next_level_prefix};
use crate::field::DpfRange;
use crate::hash::SeedExpander;
use crate::hybrid::cot::CotOracle;
use crate::hybrid::rand::RandOracle;
use crate::protocol::prep::{run_prep, PrepOutput};
use crate::seed::{Seed, SeedTag, Tag};

/// Output of one Π_DPF execution: a key pair ready for DPF.Eval.
#[derive(Clone, Debug)]
pub struct DpfKeyPair<R> {
    pub key0: DpfKey<R>,
    pub key1: DpfKey<R>,
}

/// Run the binary-field variant of Π_DPF (Figure 10).
///
/// Arguments:
/// * `expander` — the keyed hash H_S (shared/public)
/// * `cot0`, `cot1` — ideal COT oracles (b=0 sender and b=1 sender)
/// * `rand` — shared coin-tossing oracle F_Rand
/// * `alpha_bits` — the full secret point α in MSB-first bit form (length n)
/// * `beta` — the non-zero output value β ∈ R
///
/// In a real two-party setting `alpha_bits` would be additively secret-shared;
/// here we pass the whole α and let Π_PREP derive the sharing internally.
pub fn gen_binary<R, E, C, G>(
    expander: &E,
    cot0: &mut C,
    cot1: &mut C,
    rand: &mut G,
    alpha_bits: &[bool],
    beta: R,
) -> DpfKeyPair<R>
where
    R: DpfRange,
    E: SeedExpander,
    C: CotOracle,
    G: RandOracle,
{
    let n = alpha_bits.len();
    assert!(n >= 1, "domain depth must be >= 1");

    // ------------------------------------------------------------------
    // Step 1: Π_PREP  (Figure 11)
    // ------------------------------------------------------------------
    let (prep0, prep1) = run_prep(alpha_bits, cot0, cot1);

    // ------------------------------------------------------------------
    // Step 2: sample shared randomness W from F_Rand
    // ------------------------------------------------------------------
    let w = rand.sample_block();

    // ------------------------------------------------------------------
    // Step 3 (init): compute root shares  ⟨s₀⁰ ‖ t₀⁰⟩_b := ⟨Δ⟩_b ⊕ W
    // ------------------------------------------------------------------
    let root0 = xor_block(&prep0.delta_share, &w);
    let root1 = xor_block(&prep1.delta_share, &w);

    let mut nodes0 = vec![SeedTag { seed: Seed(root0), tag: Tag(false) }];
    let mut nodes1 = vec![SeedTag { seed: Seed(root1), tag: Tag(false) }];

    let mut prefix_cws: Vec<PrefixCw> = Vec::with_capacity(n.saturating_sub(1));

    // ------------------------------------------------------------------
    // Step 3 (loop): levels i = 1 .. n-1
    // ------------------------------------------------------------------
    for i in 0..(n.saturating_sub(1)) {
        let cw_i = compute_prefix_cw(
            expander,
            i,
            &nodes0,
            &nodes1,
            alpha_bits[i],
            &prep0,
            &prep1,
        );

        nodes0 = next_level_prefix(expander, &nodes0, &cw_i);
        nodes1 = next_level_prefix(expander, &nodes1, &cw_i);
        prefix_cws.push(cw_i);
    }

    // ------------------------------------------------------------------
    // Step 4: compute structured correction word CW_n (last level)
    // ------------------------------------------------------------------
    let last_cw = compute_last_cw(
        expander,
        &nodes0,
        &nodes1,
        alpha_bits[n - 1],
        &prep0,
        &prep1,
    );

    nodes0 = next_level_last(expander, &nodes0, &last_cw, alpha_bits[n - 1]);
    nodes1 = next_level_last(expander, &nodes1, &last_cw, alpha_bits[n - 1]);

    // ------------------------------------------------------------------
    // Step 5 (binary-field): CW_{n+1}
    // sum_j ConvertR(s_n^j) for each party, then correct for β.
    // ------------------------------------------------------------------
    let out_cw = compute_output_cw_binary::<R>(&nodes0, &nodes1, beta);

    // ------------------------------------------------------------------
    // Step 6: assemble keys
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

    DpfKeyPair { key0, key1 }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the prefix correction word CW_i for level i ∈ [1, n-1].
///
/// From Fig. 10 Step 3:
///   ⟨CWᵢ⟩_b = (⊕_{j ∈ [0, 2^{i-1})} H_S(⟨sⱼ_{i-1} ‖ tⱼ_{i-1}⟩_b))
///              ⊕ ⟨αᵢ⟩_b · ⟨Δ⟩_b ⊕ K_b[⟨αᵢ⟩_{1-b}] ⊕ M_b[⟨αᵢ⟩_b]
///
/// CWᵢ = ⟨CWᵢ⟩₀ ⊕ ⟨CWᵢ⟩₁
fn compute_prefix_cw<E: SeedExpander>(
    expander: &E,
    _level: usize,      // 0-indexed: level 0 produces CW_1
    nodes0: &[SeedTag],
    nodes1: &[SeedTag],
    alpha_i: bool,
    prep0: &PrepOutput,
    prep1: &PrepOutput,
) -> PrefixCw {
    // XOR of H_S over all nodes at this level for each party.
    let xor0 = hash_xor_all(expander, nodes0);
    let xor1 = hash_xor_all(expander, nodes1);

    // ⟨CWᵢ⟩_b includes:
    //   • XOR of all hashes
    //   • αᵢ · ⟨Δ⟩_b   (masks Δ on the path when αᵢ=1)
    //   • K_b[⟨αᵢ⟩_{1-b}]   (prep sender key)
    //   • M_b[⟨αᵢ⟩_b]       (prep MAC)
    // Index `_level` into prep k_vals/m_vals.
    let mut cw0 = xor0;
    if alpha_i {
        xor_block_inplace(&mut cw0, &prep0.delta_share);
    }
    xor_block_inplace(&mut cw0, &prep0.k_vals[_level]);
    xor_block_inplace(&mut cw0, &prep0.m_vals[_level]);

    let mut cw1 = xor1;
    if alpha_i {
        xor_block_inplace(&mut cw1, &prep1.delta_share);
    }
    xor_block_inplace(&mut cw1, &prep1.k_vals[_level]);
    xor_block_inplace(&mut cw1, &prep1.m_vals[_level]);

    // Public correction word = ⟨CWᵢ⟩₀ ⊕ ⟨CWᵢ⟩₁
    PrefixCw(xor_block(&cw0, &cw1))
}

/// Compute the structured correction word CW_n for the last level.
///
/// From Fig. 10 Step 4 (simplified for v1 — exact masking with µ and H'
/// is deferred; we use the structural XOR method as in the reference gen).
fn compute_last_cw<E: SeedExpander>(
    expander: &E,
    nodes0: &[SeedTag],
    nodes1: &[SeedTag],
    alpha_n: bool,
    _prep0: &PrepOutput,
    _prep1: &PrepOutput,
) -> LastCw {
    // For each party, compute ⟨X_{high,σ} ‖ X_{low,σ}⟩_b for σ ∈ {0,1}.
    let (xhigh0_s0, xlow0_s0, xhigh0_s1, xlow0_s1) = expand_last_xor(expander, nodes0);
    let (xhigh1_s0, xlow1_s0, xhigh1_s1, xlow1_s1) = expand_last_xor(expander, nodes1);

    // HCW = ⟨X_{high, α_n}⟩₀ ⊕ ⟨X_{high, α_n}⟩₁
    let hcw = if alpha_n {
        xor_block(&xhigh0_s1, &xhigh1_s1)
    } else {
        xor_block(&xhigh0_s0, &xhigh1_s0)
    };

    // LCW₀ = ⟨X_{low,0}⟩₀ ⊕ ⟨X_{low,0}⟩₁ ⊕ α_n
    // LCW₀ = Xlow₀ ⊕ αₙ ⊕ 1  (from Fig 10 share formula: ⟨LCW₀⟩_b = ⟨X_{low,0}⟩_b ⊕ ⟨αₙ⟩_b ⊕ b)
    let lcw0 = xlow0_s0 ^ xlow1_s0 ^ alpha_n ^ true;
    // LCW₁ = ⟨X_{low,1}⟩₀ ⊕ ⟨X_{low,1}⟩₁ ⊕ α_n
    let lcw1 = xlow0_s1 ^ xlow1_s1 ^ alpha_n;

    LastCw { hcw, lcw0, lcw1 }
}

/// Compute CW_{n+1} for the binary-field case.
///
/// CW_{n+1} = (Σ_j ConvertR(s₀_n^j)) + (Σ_j ConvertR(s₁_n^j)) + β
fn compute_output_cw_binary<R: DpfRange>(
    leaves0: &[SeedTag],
    leaves1: &[SeedTag],
    beta: R,
) -> R {
    let sum0 = leaves0.iter().fold(R::zero(), |acc, nd| acc + R::convert(&nd.seed.0));
    let sum1 = leaves1.iter().fold(R::zero(), |acc, nd| acc + R::convert(&nd.seed.0));
    sum0 + sum1 + beta
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

/// XOR of H_S applied to every node's packed block (seed ‖ tag).
fn hash_xor_all<E: SeedExpander>(expander: &E, nodes: &[SeedTag]) -> [u8; 16] {
    let mut acc = [0u8; 16];
    for nd in nodes {
        let h = expander.hash(&nd.to_block());
        xor_block_inplace(&mut acc, &h);
    }
    acc
}

/// For each party: XOR of expand_last outputs over all nodes → (high₀, low₀, high₁, low₁).
fn expand_last_xor<E: SeedExpander>(
    expander: &E,
    nodes: &[SeedTag],
) -> ([u8; 16], bool, [u8; 16], bool) {
    let mut xhigh0 = [0u8; 16];
    let mut xlow0 = false;
    let mut xhigh1 = [0u8; 16];
    let mut xlow1 = false;

    for nd in nodes {
        let block = nd.to_block();
        let ex = expander.expand_last(&block);
        xor_block_inplace(&mut xhigh0, &ex.high0());
        xlow0 ^= ex.low0();
        xor_block_inplace(&mut xhigh1, &ex.high1());
        xlow1 ^= ex.low1();
    }

    (xhigh0, xlow0, xhigh1, xlow1)
}
