//! Simplified parameters roughly aligned with Dilithium2 (ML-DSA-44).
//! For learning/testing; not FIPS-accurate.

pub const N: usize = 256; // polynomial degree
pub const Q: u32 = 8380417; // modulus
pub const K: usize = 4; // rows of A
pub const L: usize = 4; // columns of A / s1 dimension

// Noise parameter for CBD
pub const ETA: u8 = 2;

// Bounds (educational placeholders)
pub const GAMMA1: u32 = 1 << 17; // used to bound z in verify
pub const GAMMA2: u32 = (Q - 1) / 88; // placeholder

// Byte sizes (not FIPS-accurate packing)
pub const SEED_BYTES: usize = 32;
pub const HASH_BYTES: usize = 32;
pub const CRH_BYTES: usize = 64;

// Simple modular helpers
#[inline]
pub fn add_mod(a: u32, b: u32) -> u32 {
    let x = a.wrapping_add(b);
    if x >= Q {
        x - Q
    } else {
        x
    }
}

#[inline]
pub fn sub_mod(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

#[inline]
pub fn mul_mod(a: u32, b: u32) -> u32 {
    // naive mul mod q (u64 reduce)
    ((a as u64 * b as u64) % (Q as u64)) as u32
}
