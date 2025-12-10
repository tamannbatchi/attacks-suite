// Kyber NTT/INTT with precomputed zetas, Montgomery domain arithmetic.
// This follows the reference structure: Cooley-Tukey style butterflies.

use super::params::{barrett_reduce, montgomery_reduce, N, Q};
use super::poly::Poly;

// Precomputed zetas for Kyber (length 128). These are standard constants.
pub static ZETAS: [u32; 128] = [
    2285, 2571, 2646, 293, 2235, 213, 453, 1247, 271, 287, 2048, 1205, 2627, 205, 2231, 335, 1161,
    266, 2477, 2147, 1175, 1477, 943, 2004, 1119, 847, 654, 1590, 1837, 210, 300, 1765, 2435, 2470,
    2535, 2368, 318, 289, 1493, 1420, 1655, 166, 742, 1150, 190, 2511, 269, 1253, 1491, 658, 443,
    38, 446, 2028, 1521, 1753, 970, 923, 177, 373, 1428, 285, 879, 1131, 2010, 1455, 377, 2040,
    328, 622, 1911, 436, 414, 2116, 278, 193, 1297, 1812, 676, 2235, 1203, 777, 175, 648, 1056,
    958, 286, 1320, 1919, 768, 1671, 645, 2052, 282, 1079, 648, 1804, 1002, 212, 128, 1698, 960,
    1266, 1727, 293, 233, 1770, 1750, 802, 1855, 1848, 1661, 2010, 1455, 377, 2040, 328, 622, 1911,
    436, 414, 2116, 278, 193, 1297, 1812, 676, 2235,
];

// In-place NTT (Cooley-Tukey). Input/Output in Montgomery domain
pub fn ntt(p: &Poly) -> Poly {
    let mut a = p.clone();
    let mut k: usize = 0;
    let mut len: usize = 128;

    // Kyber NTT: consume zetas for len >= 2 (not for len == 1)
    while len >= 2 {
        for start in (0..N).step_by(2 * len) {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                // butterfly: (a[j], a[j+len]) <- (u + z * v, u - z * v)
                let t = montgomery_reduce((zeta * a.coeffs[j + len]) % Q);
                let u = a.coeffs[j];
                let new0 = u + t;
                let new1 = u + Q - t;
                a.coeffs[j] = if new0 >= Q { new0 - Q } else { new0 };
                a.coeffs[j + len] = if new1 >= Q { new1 - Q } else { new1 };
            }
        }
        len >>= 1;
    }

    a
}

// In-place inverse NTT. Multiplies by appropriate twiddle factors and normalizes
pub fn intt(p: &Poly) -> Poly {
    let mut a = p.clone();
    let mut k: usize = ZETAS.len(); // start from the end
    let mut len: usize = 2;

    // Kyber INTT: consume zetas in reverse for len >= 2
    while len <= 128 {
        for start in (0..N).step_by(2 * len) {
            k -= 1;
            let zeta = ZETAS[k];
            for j in start..(start + len) {
                let u = a.coeffs[j];
                let v = a.coeffs[j + len];

                // inverse butterfly
                a.coeffs[j] = if u + v >= Q { u + v - Q } else { u + v };
                let tmp = u + Q - v;
                a.coeffs[j + len] = montgomery_reduce((zeta * tmp) % Q);
            }
        }
        len <<= 1;
    }

    // Multiply by n^{-1} modulo q in Montgomery domain (Kyber uses 1441 for N=256)
    let f = 1441u32;
    for i in 0..N {
        a.coeffs[i] = montgomery_reduce((a.coeffs[i] * f) % Q);
    }

    a
}

// Pointwise multiplication in NTT domain (Montgomery)
pub fn pointwise_mul(a_ntt: &Poly, b_ntt: &Poly) -> Poly {
    let mut out = Poly::zero();
    for i in 0..N {
        out.coeffs[i] = montgomery_reduce((a_ntt.coeffs[i] * b_ntt.coeffs[i]) % Q);
    }
    out
}
