use zeroize::Zeroize;

/// A 128-bit seed (the λ-bit "s" part of a GGM tree node).
#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct Seed(pub [u8; 16]);

/// The single-bit control tag attached to each tree node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tag(pub bool);

/// A combined node: seed (high 127 bits) + control bit (LSB).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedTag {
    pub seed: Seed,
    pub tag: Tag,
}

impl SeedTag {
    /// Pack into a 16-byte block with the tag in the LSB.
    pub fn to_block(&self) -> [u8; 16] {
        let mut b = self.seed.0;
        crate::bits::set_lsb(&mut b, self.tag.0);
        b
    }

    /// Unpack from a 16-byte block (LSB = tag).
    pub fn from_block(b: [u8; 16]) -> Self {
        let tag = crate::bits::lsb(&b);
        let seed = Seed(crate::bits::high_bits(&b));
        SeedTag { seed, tag: Tag(tag) }
    }
}
