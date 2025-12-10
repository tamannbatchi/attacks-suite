//! Kyber-512-like parameters and common reductions.

pub const K: usize = 2; // Kyber-512 dimension
pub const N: usize = 256; // Polynomial degree
pub const Q: u32 = 3329; // Modulus
pub const Q_HALF: u32 = Q / 2;
pub const MSG_BYTES: usize = 32;
pub const SS_BYTES: usize = 32;

// Montgomery constants for Kyber
pub const MONT_R: u32 = (1u64 << 16) as u32; // R = 2^16
pub const QINV: u32 = 62209; // -q^{-1} mod 2^16 (precomputed for q=3329)

// Barrett reduction constant
pub const BARRETT_MULT: u32 = ((1u64 << 26) / Q as u64) as u32;

// Reduce a 32-bit value modulo Q using Barrett reduction
#[inline]
pub fn barrett_reduce(a: u32) -> u32 {
    let t = ((a as u64 * BARRETT_MULT as u64) >> 26) as u32;
    let r = a - t * Q;
    if r >= Q {
        r - Q
    } else {
        r
    }
}

// Montgomery reduction: reduce a 32-bit value in Montgomery domain
#[inline]
pub fn montgomery_reduce(a: u32) -> u32 {
    // Computes a * R^{-1} mod q using QINV
    let u = (a.wrapping_mul(QINV)) & 0xFFFF;
    let t = (a as u64 + (u as u64) * (Q as u64)) >> 16;
    let r = t as u32;
    if r >= Q {
        r - Q
    } else {
        r
    }
}
