//! Exact centered binomial distribution (CBD) samplers for Kyber using SHAKE128.
//! This matches the reference approach: count ones in grouped bits.

use super::params::{K, N, Q};
use super::poly::{Poly, PolyVec};
use sha3::digest::XofReader;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake128;

pub fn sample_secret_vec(k: usize, seed: &[u8], nonce_base: u8, eta: u8) -> PolyVec {
    let mut v = PolyVec::zero(k);
    for i in 0..k {
        v.polys[i] = cbd_poly(seed, nonce_base + i as u8, eta);
    }
    v
}

pub fn sample_error_vec(k: usize, seed: &[u8], nonce_base: u8, eta: u8) -> PolyVec {
    let mut v = PolyVec::zero(k);
    for i in 0..k {
        v.polys[i] = cbd_poly(seed, nonce_base + k as u8 + i as u8, eta);
    }
    v
}

// CBD sampler: eta=2 or eta=3 for Kyber, using SHAKE128 stream per nonce.
fn cbd_poly(seed: &[u8], nonce: u8, eta: u8) -> Poly {
    let bytes_needed = match eta {
        2 => (N / 4) * 4, // Kyber ref groups 4 bits per coefficient for eta=2
        3 => (N / 4) * 6, // eta=3 needs 6 bytes per 4 coeffs
        _ => panic!("Unsupported eta"),
    };

    let mut xof = Shake128::default();
    xof.update(seed);
    xof.update(&[nonce]);
    let mut buf = vec![0u8; bytes_needed];
    xof.finalize_xof().read(&mut buf);

    let mut p = Poly::zero();
    let mut idx = 0usize;

    if eta == 2 {
        // Process 4 coefficients per 4 bytes
        for i in 0..(N / 4) {
            let t = (buf[4 * i] as u32)
                | ((buf[4 * i + 1] as u32) << 8)
                | ((buf[4 * i + 2] as u32) << 16)
                | ((buf[4 * i + 3] as u32) << 24);
            for j in 0..4 {
                let a = ((t >> (8 * j)) & 0x0F) as u32; // low nibble
                let b = ((t >> (8 * j + 4)) & 0x0F) as u32; // high nibble
                let val = (a.count_ones() as i32 - b.count_ones() as i32) as i32;
                p.coeffs[idx] = ((val.rem_euclid(Q as i32)) as u32) % Q;
                idx += 1;
            }
        }
    } else {
        // eta == 3
        // Process 4 coefficients per 6 bytes
        for i in 0..(N / 4) {
            let t0 = (buf[6 * i] as u32) | ((buf[6 * i + 1] as u32) << 8);
            let t1 = (buf[6 * i + 2] as u32) | ((buf[6 * i + 3] as u32) << 8);
            let t2 = (buf[6 * i + 4] as u32) | ((buf[6 * i + 5] as u32) << 8);
            let a0 = (t0 & 0x0FFF) as u32;
            let b0 = (t0 >> 12) as u32;
            let a1 = (t1 & 0x0FFF) as u32;
            let b1 = (t1 >> 12) as u32;
            let a2 = (t2 & 0x0FFF) as u32;
            let b2 = (t2 >> 12) as u32;
            let vals = [
                (a0.count_ones() as i32 - b0.count_ones() as i32),
                (a1.count_ones() as i32 - b1.count_ones() as i32),
                (a2.count_ones() as i32 - b2.count_ones() as i32),
                // last coeff uses mixed bits
                (((t0 >> 8) & 0x0FFF).count_ones() as i32
                    - ((t1 >> 8) & 0x0FFF).count_ones() as i32),
            ];
            for v in vals {
                p.coeffs[idx] = ((v.rem_euclid(Q as i32)) as u32) % Q;
                idx += 1;
            }
        }
    }
    p
}
