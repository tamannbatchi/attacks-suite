//! CBD eta=2 and uniform polynomial sampling using SHAKE128.
//! Educational version matching the structure (not FIPS-accurate rejection).

use super::params::{N, Q};
use super::poly::{Poly, PolyVec};
use rand::{rngs::OsRng, RngCore};
use sha3::digest::XofReader;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake128;

pub fn random32() -> [u8; 32] {
    let mut z = [0u8; 32];
    OsRng.fill_bytes(&mut z);
    z
}

pub fn shake128_stream(seed: &[u8], nonce: u8, out_len: usize) -> Vec<u8> {
    let mut xof = Shake128::default();
    xof.update(seed);
    xof.update(&[nonce]);
    let mut out = vec![0u8; out_len];
    xof.finalize_xof().read(&mut out);
    out
}

/// Uniform sampling mod q via 16-bit words mod q (educational simplification).
pub fn uniform_poly(seed: &[u8], nonce: u8) -> Poly {
    let bytes = shake128_stream(seed, nonce, N * 2);
    let mut p = Poly::zero();
    for i in 0..N {
        let w = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]) as u32;
        p.coeffs[i] = w % Q;
    }
    p
}

/// CBD eta=2: count ones in low/high nibble per byte, difference gives small coeff.
pub fn cbd_eta2(seed: &[u8], nonce: u8) -> Poly {
    let bytes = shake128_stream(seed, nonce, N);
    let mut p = Poly::zero();
    for i in 0..N {
        let lo = bytes[i] & 0x0F;
        let hi = (bytes[i] >> 4) & 0x0F;
        let a = (lo as u8).count_ones() as i32;
        let b = (hi as u8).count_ones() as i32;
        let val = (a - b).rem_euclid(Q as i32) as u32;
        p.coeffs[i] = val;
    }
    p
}

pub fn sample_s1_s2(seed: &[u8], l: usize, k: usize) -> (PolyVec, PolyVec) {
    let mut s1 = PolyVec::zero(l);
    let mut s2 = PolyVec::zero(k);
    for i in 0..l {
        s1.polys[i] = cbd_eta2(seed, i as u8);
    }
    for i in 0..k {
        s2.polys[i] = cbd_eta2(seed, (l + i) as u8);
    }
    (s1, s2)
}
