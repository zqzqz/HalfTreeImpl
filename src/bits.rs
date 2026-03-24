/// Decompose `x` into `n` bits, MSB first (bit 0 = most significant).
pub fn decompose_bits_msb(x: u128, n: usize) -> Vec<bool> {
    (0..n).map(|i| (x >> (n - 1 - i)) & 1 == 1).collect()
}

/// XOR two 16-byte blocks, returning the result.
pub fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// XOR `b` into `a` in place.
pub fn xor_block_inplace(a: &mut [u8; 16], b: &[u8; 16]) {
    for i in 0..16 {
        a[i] ^= b[i];
    }
}

/// Return the least significant bit of a block.
pub fn lsb(block: &[u8; 16]) -> bool {
    block[15] & 1 == 1
}

/// Return the high 127 bits (clear LSB) of a block.
pub fn high_bits(block: &[u8; 16]) -> [u8; 16] {
    let mut out = *block;
    out[15] &= 0xfe;
    out
}

/// Set the least significant bit of a block.
pub fn set_lsb(block: &mut [u8; 16], bit: bool) {
    if bit {
        block[15] |= 1;
    } else {
        block[15] &= 0xfe;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_round_trips() {
        let x = 0b1011u128;
        let bits = decompose_bits_msb(x, 4);
        assert_eq!(bits, vec![true, false, true, true]);
    }

    #[test]
    fn xor_block_self_is_zero() {
        let a = [0xabu8; 16];
        let r = xor_block(&a, &a);
        assert_eq!(r, [0u8; 16]);
    }

    #[test]
    fn lsb_correct() {
        let mut b = [0u8; 16];
        b[15] = 0b00000011;
        assert!(lsb(&b));
        b[15] = 0b00000010;
        assert!(!lsb(&b));
    }
}
