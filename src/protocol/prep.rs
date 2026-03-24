//! Π_PREP — Preprocessing sub-protocol (Figure 11 of the paper).
//!
//! Executed once (initialise) and then once per Gen call (extend).
//! Produces:
//!   • ⟨Δ⟩_b      — each party's share of the global offset Δ
//!   • K_b[⟨αᵢ⟩_{1-b}] — sender key for the other party's i-th path bit
//!   • M_b[⟨αᵢ⟩_b]     — MAC for own i-th path bit
//! for i ∈ [1, n].

use crate::bits::xor_block;
use crate::hybrid::cot::CotOracle;

/// Per-party output of Π_PREP.
#[derive(Clone, Debug)]
pub struct PrepOutput {
    /// This party's share ⟨Δ⟩_b (λ bits).
    pub delta_share: [u8; 16],
    /// K_b[⟨αᵢ⟩_{1-b}] for i ∈ [1,n] — "sender keys" for opposite path bits.
    pub k_vals: Vec<[u8; 16]>,
    /// M_b[⟨αᵢ⟩_b]     for i ∈ [1,n] — IT-MAC values for own path bits.
    pub m_vals: Vec<[u8; 16]>,
}

/// Run Π_PREP for both parties simultaneously (local simulation).
///
/// In the real protocol the two calls are executed by P₀ and P₁ over a
/// network; here we compute both outputs at once for testing purposes.
///
/// * `alpha_bits` — the *full* path α (MSB first, length n).
/// * `cot0`  — COT oracle with P₀ as sender  (identifier b=0 in the paper).
/// * `cot1`  — COT oracle with P₁ as sender  (identifier b=1 in the paper).
///
/// Returns `(prep0, prep1)`.
pub fn run_prep<C: CotOracle>(
    alpha_bits: &[bool],
    cot0: &mut C,
    cot1: &mut C,
) -> (PrepOutput, PrepOutput) {
    let n = alpha_bits.len();

    // ------------------------------------------------------------------
    // Initialise: obtain Δ'_b from each COT oracle.
    // ------------------------------------------------------------------
    let delta0_prime = cot0.delta(); // P₀'s raw Δ (returned to P₀ as sender)
    let delta1_prime = cot1.delta(); // P₁'s raw Δ

    // Exchange LSBs so that lsb(⟨Δ⟩₀ ⊕ ⟨Δ⟩₁) = 1 (paper §5.2, Fig. 11).
    // ⟨Δ⟩_b := Δ'_b ⊕ (0^{λ-1} ‖ (lsb(Δ'_{1-b}) ⊕ b))
    let lsb0 = (delta0_prime[15] & 1) != 0;
    let lsb1 = (delta1_prime[15] & 1) != 0;

    let mut delta_share0 = delta0_prime;
    let adjust0 = (lsb1 ^ false) as u8; // b=0: XOR with (lsb(Δ'₁) ⊕ 0)
    delta_share0[15] ^= adjust0;

    let mut delta_share1 = delta1_prime;
    let adjust1 = (lsb0 ^ true) as u8;  // b=1: XOR with (lsb(Δ'₀) ⊕ 1)
    delta_share1[15] ^= adjust1;

    // ------------------------------------------------------------------
    // Extend: get n COT tuples from each oracle.
    // ------------------------------------------------------------------
    // cot0 acts as sender for P₀; cot1 acts as sender for P₁.
    let batch0 = cot0.extend(n); // P₀ is sender   → batch0.sender_keys = K₀[·]
    let batch1 = cot1.extend(n); // P₁ is sender   → batch1.sender_keys = K₁[·]

    // Receiver bits for each oracle are random; we mask them with α shares.
    // r_b = random bit; g_b = ⟨α⟩_b ⊕ r_b is sent to P_{1-b}.
    // After exchange: g_{1-b} lets P_b recover K_b[⟨αᵢ⟩_{1-b}].

    let mut k_vals0 = Vec::with_capacity(n);
    let mut m_vals0 = Vec::with_capacity(n);
    let mut k_vals1 = Vec::with_capacity(n);
    let mut m_vals1 = Vec::with_capacity(n);

    for i in 0..n {
        let alpha_i = alpha_bits[i];

        // ---- P₀ side (uses cot0 as sender, cot1 as receiver) ----
        let r0 = batch0.receiver[i].r; // P₀'s random choice bit as receiver of cot1
        let m0 = batch0.receiver[i].m; // P₀'s MAC from cot1

        // g₀ = ⟨αᵢ⟩₀ ⊕ r₀  (P₀ sends this to P₁)
        // In the two-party setting P₁ uses g₀ to mask K₁[·].
        // K₀[⟨αᵢ⟩_{1-0}] = K₀[⟨αᵢ⟩₁] = k_{cot0}[i] ⊕ g₁·⟨Δ⟩₀
        //   where g₁ = ⟨αᵢ⟩₁ ⊕ r₁ (received from P₁).
        let r1 = batch1.receiver[i].r;
        let g1 = alpha_i ^ r1; // ⟨αᵢ⟩ = alpha_i (we treat alpha as shared trivially here)

        // P₀'s sender key for the opposite choice: K₀[g₁-adjusted]
        let k0 = if g1 {
            xor_block(&batch0.sender_keys[i], &delta_share0)
        } else {
            batch0.sender_keys[i]
        };

        // M₀[⟨αᵢ⟩₀] = m_{cot1,i} ⊕ r₀·(0^{λ-1}‖(lsb(Δ'₀) ⊕ (1-0)))
        // Simplified: adjust the MAC with the Δ-LSB correction.
        let mut m0_adj = m0;
        if r0 {
            m0_adj[15] ^= (lsb0 ^ true) as u8;
        }

        k_vals0.push(k0);
        m_vals0.push(m0_adj);

        // ---- P₁ side (uses cot1 as sender, cot0 as receiver) ----
        let g0 = alpha_i ^ r0; // ⟨αᵢ⟩₁ ⊕ r₀ ... symmetric

        let k1 = if g0 {
            xor_block(&batch1.sender_keys[i], &delta_share1)
        } else {
            batch1.sender_keys[i]
        };

        let m1 = batch1.receiver[i].m;
        let mut m1_adj = m1;
        if r1 {
            m1_adj[15] ^= (lsb1 ^ false) as u8;
        }

        k_vals1.push(k1);
        m_vals1.push(m1_adj);
    }

    (
        PrepOutput { delta_share: delta_share0, k_vals: k_vals0, m_vals: m_vals0 },
        PrepOutput { delta_share: delta_share1, k_vals: k_vals1, m_vals: m_vals1 },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid::cot::IdealCot;

    #[test]
    fn delta_lsb_xor_is_one() {
        let alpha = vec![true, false, true, true];
        let mut cot0 = IdealCot::new(1);
        let mut cot1 = IdealCot::new(2);
        let (p0, p1) = run_prep(&alpha, &mut cot0, &mut cot1);
        let xor_lsb = (p0.delta_share[15] ^ p1.delta_share[15]) & 1;
        assert_eq!(xor_lsb, 1, "lsb(⟨Δ⟩₀ ⊕ ⟨Δ⟩₁) must be 1");
    }

    #[test]
    fn prep_output_lengths_match_n() {
        let n = 6;
        let alpha = vec![false; n];
        let mut cot0 = IdealCot::new(10);
        let mut cot1 = IdealCot::new(20);
        let (p0, p1) = run_prep(&alpha, &mut cot0, &mut cot1);
        assert_eq!(p0.k_vals.len(), n);
        assert_eq!(p0.m_vals.len(), n);
        assert_eq!(p1.k_vals.len(), n);
        assert_eq!(p1.m_vals.len(), n);
    }
}
