//! Keyed hash / seed-expansion interface used by the GGM tree.
//!
//! The paper uses H_S(x) = H(S ⊕ x) where H is a CCR function (one AES call).
//! For v1 we provide an AES-based implementation and a simple XOR-based stub
//! that is cheap to use in unit tests.

use crate::bits::{lsb, high_bits, xor_block};

/// Output of expanding a non-last-level node into two children.
#[derive(Clone, Debug)]
pub struct ExpandedNode {
    /// Left child: the high 127 bits (seed) and tag (LSB).
    pub left: [u8; 16],
    /// Right child: the high 127 bits (seed) and tag (LSB).
    pub right: [u8; 16],
}

impl ExpandedNode {
    pub fn left_seed(&self)  -> [u8; 16] { high_bits(&self.left) }
    pub fn left_tag(&self)   -> bool      { lsb(&self.left) }
    pub fn right_seed(&self) -> [u8; 16] { high_bits(&self.right) }
    pub fn right_tag(&self)  -> bool      { lsb(&self.right) }
}

/// Output of expanding a last-level node (level n-1 → level n).
///
/// The paper splits the hash output into a "high" part (seed, λ-1 bits)
/// and a "low" part (control bit) for each σ ∈ {0,1}.
#[derive(Clone, Debug)]
pub struct LastExpandedNode {
    /// H_S(node ⊕ 0): high bits = seed, LSB = control bit.
    pub sigma0: [u8; 16],
    /// H_S(node ⊕ 1): high bits = seed, LSB = control bit.
    pub sigma1: [u8; 16],
}

impl LastExpandedNode {
    pub fn high0(&self) -> [u8; 16] { high_bits(&self.sigma0) }
    pub fn low0(&self)  -> bool      { lsb(&self.sigma0) }
    pub fn high1(&self) -> [u8; 16] { high_bits(&self.sigma1) }
    pub fn low1(&self)  -> bool      { lsb(&self.sigma1) }
}

/// Trait abstracting the keyed hash used for tree expansion.
pub trait SeedExpander: Send + Sync {
    /// Expand a non-leaf node into left and right children.
    /// Corresponds to one application of H_S producing two λ-bit outputs.
    fn expand(&self, node: &[u8; 16]) -> ExpandedNode;

    /// Expand a level-(n-1) node into the two last-level candidates
    /// (σ=0 and σ=1), as required by the final-level step in Fig. 10.
    fn expand_last(&self, node: &[u8; 16]) -> LastExpandedNode;

    /// Raw keyed hash: H_S(x) = H(S ⊕ x).  Used directly for correction
    /// word computation in Figs. 10 and 11.
    fn hash(&self, x: &[u8; 16]) -> [u8; 16];
}

// ---------------------------------------------------------------------------
// AES-based expander  (one fixed-key AES call per hash, as in the paper)
// ---------------------------------------------------------------------------

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

pub struct AesExpander {
    key: [u8; 16],
    cipher: Aes128,
}

impl AesExpander {
    pub fn new(key: [u8; 16]) -> Self {
        let cipher = Aes128::new_from_slice(&key).expect("AES-128 key");
        AesExpander { key, cipher }
    }

    fn aes_eval(&self, x: &[u8; 16]) -> [u8; 16] {
        use aes::cipher::generic_array::GenericArray;
        let mut block = GenericArray::clone_from_slice(x);
        self.cipher.encrypt_block(&mut block);
        // MMO (Matyas-Meyer-Oseas): output = E(x) ⊕ x
        let mut out = [0u8; 16];
        out.copy_from_slice(&block);
        xor_block(&out, x)
    }
}

impl SeedExpander for AesExpander {
    fn hash(&self, x: &[u8; 16]) -> [u8; 16] {
        // H_S(x) = AES_MMO(S ⊕ x)
        let sx = xor_block(&self.key, x);
        self.aes_eval(&sx)
    }

    /// Half-Tree intermediate-level expansion (one hash call per node):
    ///   left  = H_S(node)
    ///   right = H_S(node) ⊕ node
    ///
    /// `node` is the full λ-bit block (seed ‖ tag).
    fn expand(&self, node: &[u8; 16]) -> ExpandedNode {
        let left = self.hash(node);
        let right = xor_block(&left, node);
        ExpandedNode { left, right }
    }

    /// Last-level expansion (two hash calls, one per σ ∈ {0,1}):
    ///   sigma0 = H_S(node)
    ///   sigma1 = H_S(node ⊕ 1)   (flip LSB)
    ///
    /// `node` is the full λ-bit block (seed ‖ tag).
    fn expand_last(&self, node: &[u8; 16]) -> LastExpandedNode {
        let mut n1 = *node;
        n1[15] ^= 0x01;
        LastExpandedNode {
            sigma0: self.hash(node),
            sigma1: self.hash(&n1),
        }
    }
}

// ---------------------------------------------------------------------------
// XOR-stub expander  — deterministic, fast, NOT secure; for unit tests only
// ---------------------------------------------------------------------------

pub struct XorExpander {
    key: [u8; 16],
}

impl XorExpander {
    pub fn new(key: [u8; 16]) -> Self { XorExpander { key } }
}

impl SeedExpander for XorExpander {
    fn hash(&self, x: &[u8; 16]) -> [u8; 16] {
        // Trivial: rotate left by 3 bits then XOR with key ⊕ x
        let mut out = xor_block(&self.key, x);
        let carry = out[0] >> 5;
        for i in 0..15 { out[i] = (out[i] << 3) | (out[i + 1] >> 5); }
        out[15] = (out[15] << 3) | carry;
        out
    }

    fn expand(&self, node: &[u8; 16]) -> ExpandedNode {
        let left = self.hash(node);
        let right = xor_block(&left, node);
        ExpandedNode { left, right }
    }

    fn expand_last(&self, node: &[u8; 16]) -> LastExpandedNode {
        let mut n1 = *node;
        n1[15] ^= 0x01;
        LastExpandedNode { sigma0: self.hash(node), sigma1: self.hash(&n1) }
    }
}
