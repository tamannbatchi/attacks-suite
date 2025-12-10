// ML-DSA (Dilithium2): keygen, sign, verify.
// Uses naive polynomial multiplication.

use super::matrix::expand_a;
use super::packing::{pack_pk, pack_sig, pack_sk, unpack_pk, unpack_sig, unpack_sk};
use super::params::{CRH_BYTES, GAMMA1, HASH_BYTES, K, L, SEED_BYTES};
use super::poly::{Poly, PolyVec};
use super::sampling::{cbd_eta2, random32, sample_s1_s2};
use sha3::digest::XofReader;
use sha3::digest::{ExtendableOutput, Update};
use sha3::{Shake128, Shake256};

pub struct PublicKey {
    pub bytes: Vec<u8>,
}
pub struct SecretKey {
    pub bytes: Vec<u8>,
}
pub struct Signature {
    pub bytes: Vec<u8>,
}

fn shake256(out_len: usize, input: &[u8]) -> Vec<u8> {
    let mut xof = Shake256::default();
    xof.update(input);
    let mut out = vec![0u8; out_len];
    xof.finalize_xof().read(&mut out);
    out
}

fn shake128(out_len: usize, input: &[u8]) -> Vec<u8> {
    let mut xof = Shake128::default();
    xof.update(input);
    let mut out = vec![0u8; out_len];
    xof.finalize_xof().read(&mut out);
    out
}

/// KeyGen:
/// - rho: seed for A
/// - s1,s2 via CBD
/// - t = A*s1 + s2
/// - pk = (rho, t), tr = H(pk), sk packs s1,s2,tr,pk
pub fn keygen() -> (PublicKey, SecretKey) {
    let rho = random32();
    let seed_s = random32();
    let (s1, s2) = sample_s1_s2(&seed_s, L, K);

    let a = expand_a(&rho);
    let t = mat_times_vec_plus(&a, &s1, &s2);

    let pk_bytes = pack_pk(&t, &rho);
    let tr = shake256(CRH_BYTES, &pk_bytes);
    let sk_bytes = pack_sk(&s1, &s2, &tr, &pk_bytes);

    (PublicKey { bytes: pk_bytes }, SecretKey { bytes: sk_bytes })
}

/// Sign:
/// - mu = H(tr || msg)
/// - y sampled (ephemeral)
/// - w = A*y
/// - c = H(mu || compress(w))
/// - z = y + c*s1
/// - h = hint(w - c*t)
pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    let (s1, _s2, tr, pk_bytes) = unpack_sk(&sk.bytes);
    let (t, rho) = unpack_pk(&pk_bytes);

    let mut mu_in = Vec::new();
    mu_in.extend_from_slice(&tr);
    mu_in.extend_from_slice(msg);
    let mu = shake256(HASH_BYTES, &mu_in);

    // Sample y (ephemeral): CBD eta2 using mu-derived seed (deterministic mimic)
    let mut y = PolyVec::zero(L);
    for i in 0..L {
        y.polys[i] = cbd_eta2(&mu, i as u8);
    }

    // w = A*y
    let a = expand_a(&rho);
    let w = mat_times_vec(&a, &y);

    // Compress w
    let w1 = compress_w_hi(&w);

    // Challenge c
    let mut ch_in = Vec::new();
    ch_in.extend_from_slice(&mu);
    ch_in.extend_from_slice(&w1);
    let c = shake256(HASH_BYTES, &ch_in);

    // z = y + c*s1 (scale s1 by small scalar derived from c for demo)
    let z = add_scaled(&y, &s1, &c);

    // h = hint(w - c*t)
    let ct = scale_vec(&t, &c);
    let w_minus_ct = w.sub(&ct);
    let h = hint(&w_minus_ct);

    let sig_bytes = pack_sig(&c, &z, &h);
    Signature { bytes: sig_bytes }
}

/// Verify:
/// - mu = H(tr || msg)
/// - w' = A*z - c*t
/// - c' = H(mu || compress(w'))
/// - bounds check on z, accept if c' == c
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    let (t, rho) = unpack_pk(&pk.bytes);
    let (c, z, h) = unpack_sig(&sig.bytes);

    // Basic bounds on z
    for p in &z.polys {
        for &coeff in &p.coeffs {
            if coeff >= GAMMA1 {
                return false;
            }
        }
    }

    let tr = shake256(CRH_BYTES, &pk.bytes);
    let mut mu_in = Vec::new();
    mu_in.extend_from_slice(&tr);
    mu_in.extend_from_slice(msg);
    let mu = shake256(HASH_BYTES, &mu_in);

    let a = expand_a(&rho);
    let az = mat_times_vec(&a, &z);
    let ct = scale_vec(&t, &c);
    let wprime = az.sub(&ct);

    // Apply hint
    let w1p = apply_hint(&wprime, &h);
    let w1c = compress_w_hi(&w1p);

    let mut ch_in = Vec::new();
    ch_in.extend_from_slice(&mu);
    ch_in.extend_from_slice(&w1c);
    let cprime = shake256(HASH_BYTES, &ch_in);

    cprime == c
}

// Linear algebra helpers (naive multiplication)

fn mat_times_vec(a: &Vec<Vec<Poly>>, v: &PolyVec) -> PolyVec {
    let mut out = PolyVec::zero(a.len());
    for i in 0..a.len() {
        let mut acc = Poly::zero();
        for j in 0..a[i].len() {
            let prod = a[i][j].mul_negacyclic(&v.polys[j]);
            acc = acc.add(&prod);
        }
        out.polys[i] = acc;
    }
    out
}

fn mat_times_vec_plus(a: &Vec<Vec<Poly>>, v: &PolyVec, add_vec: &PolyVec) -> PolyVec {
    mat_times_vec(a, v).add(add_vec)
}

// Challenge scaling and hint

fn scale_vec(v: &PolyVec, c: &[u8]) -> PolyVec {
    // Map challenge bytes to a small scalar for demo
    let s = (c[0] as u32 % 17) + 1;
    let mut out = PolyVec::zero(v.polys.len());
    for i in 0..v.polys.len() {
        let mut p = Poly::zero();
        for j in 0..super::params::N {
            p.coeffs[j] =
                ((v.polys[i].coeffs[j] as u64 * s as u64) % super::params::Q as u64) as u32;
        }
        out.polys[i] = p;
    }
    out
}

fn add_scaled(y: &PolyVec, s1: &PolyVec, c: &[u8]) -> PolyVec {
    let scaled = scale_vec(s1, c);
    y.add(&scaled)
}

/// Compress "high bits".
fn compress_w_hi(w: &PolyVec) -> Vec<u8> {
    let mut out = Vec::new();
    for p in &w.polys {
        for &c in &p.coeffs {
            let hi = (c >> 12) as u16; // coarse high bits
            out.extend_from_slice(&hi.to_le_bytes());
        }
    }
    out
}

/// Hint: store coarse buckets to aid reconstruction (educational).
fn hint(v: &PolyVec) -> PolyVec {
    let mut h = PolyVec::zero(v.polys.len());
    for i in 0..v.polys.len() {
        let mut p = Poly::zero();
        for j in 0..super::params::N {
            p.coeffs[j] = v.polys[i].coeffs[j] / 4096;
        }
        h.polys[i] = p;
    }
    h
}

fn apply_hint(v: &PolyVec, h: &PolyVec) -> PolyVec {
    v.add(h)
}
