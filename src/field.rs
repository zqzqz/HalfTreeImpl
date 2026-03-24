use std::ops::{Add, AddAssign, Sub, Mul, Neg};

/// Algebraic range that DPF outputs live in.
pub trait DpfRange:
    Clone + std::fmt::Debug + PartialEq + Eq
    + Add<Output = Self> + AddAssign
    + Sub<Output = Self> + Neg<Output = Self>
    + Mul<bool, Output = Self>   // scalar-multiply by a control bit
{
    fn zero() -> Self;
    fn one() -> Self;

    /// Map a 16-byte seed block to a range element (ConvertR in the paper).
    fn convert(bytes: &[u8; 16]) -> Self;
}

// ---------------------------------------------------------------------------
// F₂  — the simplest possible range (single bit)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct F2(pub bool);

impl Add for F2 {
    type Output = F2;
    fn add(self, rhs: F2) -> F2 { F2(self.0 ^ rhs.0) }
}
impl AddAssign for F2 {
    fn add_assign(&mut self, rhs: F2) { self.0 ^= rhs.0; }
}
impl Sub for F2 {
    type Output = F2;
    fn sub(self, rhs: F2) -> F2 { F2(self.0 ^ rhs.0) }
}
impl Neg for F2 {
    type Output = F2;
    fn neg(self) -> F2 { self }
}
impl Mul<bool> for F2 {
    type Output = F2;
    fn mul(self, rhs: bool) -> F2 { F2(self.0 & rhs) }
}
impl DpfRange for F2 {
    fn zero() -> Self { F2(false) }
    fn one() -> Self { F2(true) }
    fn convert(bytes: &[u8; 16]) -> Self {
        // Use the LSB of the block as the F2 element.
        F2(crate::bits::lsb(bytes))
    }
}

// ---------------------------------------------------------------------------
// u64 — useful for testing with integer arithmetic
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U64(pub u64);

impl Add for U64 {
    type Output = U64;
    fn add(self, rhs: U64) -> U64 { U64(self.0.wrapping_add(rhs.0)) }
}
impl AddAssign for U64 {
    fn add_assign(&mut self, rhs: U64) { self.0 = self.0.wrapping_add(rhs.0); }
}
impl Sub for U64 {
    type Output = U64;
    fn sub(self, rhs: U64) -> U64 { U64(self.0.wrapping_sub(rhs.0)) }
}
impl Neg for U64 {
    type Output = U64;
    fn neg(self) -> U64 { U64(self.0.wrapping_neg()) }
}
impl Mul<bool> for U64 {
    type Output = U64;
    fn mul(self, rhs: bool) -> U64 { if rhs { self } else { U64(0) } }
}
impl DpfRange for U64 {
    fn zero() -> Self { U64(0) }
    fn one() -> Self { U64(1) }
    fn convert(bytes: &[u8; 16]) -> Self {
        // Take the first 8 bytes as a little-endian u64.
        let arr: [u8; 8] = bytes[..8].try_into().unwrap();
        U64(u64::from_le_bytes(arr))
    }
}
