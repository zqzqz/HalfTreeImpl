use crate::seed::Seed;

/// Correction word for levels 1 .. n-1.
/// A single λ-bit block XOR-ed into every node whose parent's tag is 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixCw(pub [u8; 16]);

/// Correction word for the final tree level (level n).
/// Structured as (HCW ‖ LCW₀ ‖ LCW₁) per the paper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastCw {
    /// λ-bit seed-correction for the on-path node.
    pub hcw: [u8; 16],
    /// Control-bit correction for σ = 0.
    pub lcw0: bool,
    /// Control-bit correction for σ = 1.
    pub lcw1: bool,
}

/// A full DPF key held by one party.
#[derive(Clone, Debug)]
pub struct DpfKey<R> {
    /// Root share ⟨s₀⁰ ‖ t₀⁰⟩_b  (λ bits, tag in LSB).
    pub root: Seed,
    /// CW₁ … CW_{n-1}  — one per intermediate level.
    pub prefix_cws: Vec<PrefixCw>,
    /// CW_n — structured correction for the last level.
    pub last_cw: LastCw,
    /// CW_{n+1} — output correction word (a range element).
    pub out_cw: R,
}
