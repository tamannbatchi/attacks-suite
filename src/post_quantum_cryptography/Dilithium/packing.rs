//! Simplified pack/unpack for keys and signatures (not FIPS-accurate).

use super::params::{CRH_BYTES, HASH_BYTES, K, L, N, SEED_BYTES};
use super::poly::{Poly, PolyVec};

pub fn pack_pk(t: &PolyVec, rho: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(rho);
    for p in &t.polys {
        for &c in &p.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out
}

pub fn unpack_pk(bytes: &[u8]) -> (PolyVec, Vec<u8>) {
    let rho = bytes[0..SEED_BYTES].to_vec();
    let mut t = PolyVec::zero(K);
    let mut offset = SEED_BYTES;
    for i in 0..K {
        for j in 0..N {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            t.polys[i].coeffs[j] = u32::from_le_bytes(b);
            offset += 4;
        }
    }
    (t, rho)
}

pub fn pack_sk(s1: &PolyVec, s2: &PolyVec, tr: &[u8], pk: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in &s1.polys {
        for &c in &p.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    for p in &s2.polys {
        for &c in &p.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out.extend_from_slice(tr);
    out.extend_from_slice(pk);
    out
}

pub fn unpack_sk(bytes: &[u8]) -> (PolyVec, PolyVec, Vec<u8>, Vec<u8>) {
    let mut offset = 0usize;
    let mut s1 = PolyVec::zero(L);
    for i in 0..L {
        for j in 0..N {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            s1.polys[i].coeffs[j] = u32::from_le_bytes(b);
            offset += 4;
        }
    }
    let mut s2 = PolyVec::zero(K);
    for i in 0..K {
        for j in 0..N {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            s2.polys[i].coeffs[j] = u32::from_le_bytes(b);
            offset += 4;
        }
    }
    let tr = bytes[offset..offset + CRH_BYTES].to_vec();
    offset += CRH_BYTES;
    let pk = bytes[offset..].to_vec();
    (s1, s2, tr, pk)
}

// Signature packing: c || z (L polys) || h (K polys) — demo format
pub fn pack_sig(c: &[u8], z: &PolyVec, h: &PolyVec) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(c);
    for p in &z.polys {
        for &coeff in &p.coeffs {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    for p in &h.polys {
        for &coeff in &p.coeffs {
            out.extend_from_slice(&coeff.to_le_bytes());
        }
    }
    out
}

pub fn unpack_sig(bytes: &[u8]) -> (Vec<u8>, PolyVec, PolyVec) {
    let c = bytes[0..HASH_BYTES].to_vec();
    let mut offset = HASH_BYTES;
    let mut z = PolyVec::zero(L);
    for i in 0..L {
        for j in 0..N {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            z.polys[i].coeffs[j] = u32::from_le_bytes(b);
            offset += 4;
        }
    }
    let mut h = PolyVec::zero(K);
    for i in 0..K {
        for j in 0..N {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            h.polys[i].coeffs[j] = u32::from_le_bytes(b);
            offset += 4;
        }
    }
    (c, z, h)
}
