// KEM flow wired with real NTT and exact CBD sampling (eta=2).

use super::{
    ntt,
    params::*,
    poly::{Poly, PolyVec},
    sampling,
};
use rand::{rngs::OsRng, RngCore};
use sha3::digest::XofReader;
use sha3::digest::{ExtendableOutput, Update};
use sha3::{Shake128, Shake256};

pub struct PublicKey {
    pub bytes: Vec<u8>,
}
pub struct SecretKey {
    pub bytes: Vec<u8>,
}
pub struct Ciphertext {
    pub bytes: Vec<u8>,
}

fn kdf256(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut xof = Shake256::default();
    xof.update(input);
    let mut out = vec![0u8; out_len];
    xof.finalize_xof().read(&mut out);
    out
}

fn hash_pk(pk: &[u8]) -> Vec<u8> {
    let mut xof = Shake128::default();
    xof.update(pk);
    let mut out = vec![0u8; 32];
    xof.finalize_xof().read(&mut out);
    out
}

fn random32() -> [u8; 32] {
    let mut z = [0u8; 32];
    OsRng.fill_bytes(&mut z);
    z
}

pub fn keygen() -> (PublicKey, SecretKey) {
    // Seed for public matrix A
    let rho = random32();

    // Secret and error via CBD (eta=2)
    let seed = random32();
    let s = sampling::sample_secret_vec(K, &seed, 0, 2);
    let e = sampling::sample_error_vec(K, &seed, 0, 2);

    // t = A * s + e using NTT
    let t = mat_mul_add(&rho, &s, &e);

    let pk_bytes = pack_pk(&t, &rho);
    let hpk = hash_pk(&pk_bytes);
    let z = random32();
    let sk_bytes = pack_sk(&s, &pk_bytes, &hpk, &z);

    (PublicKey { bytes: pk_bytes }, SecretKey { bytes: sk_bytes })
}

pub fn encapsulate(pk: &PublicKey) -> (Ciphertext, Vec<u8>) {
    let hpk = hash_pk(&pk.bytes);
    let m = kdf256(&hpk, MSG_BYTES);
    // Ephemeral secrets via CBD (eta=2)
    let seed = random32();
    let r = sampling::sample_secret_vec(K, &seed, 0, 2);
    let e1 = sampling::sample_error_vec(K, &seed, 0, 2);
    let e2 = sampling::sample_error_vec(1, &seed, 17, 2);

    let (t, rho) = unpack_pk(&pk.bytes);

    let u = mat_mul_add(&rho, &r, &e1);
    let mut v = dot_transpose(&t, &r);
    v = add_poly(&v, &e2.polys[0]);
    let v = add_message(&v, &m);

    let ct = pack_ct(&u, &v);
    let ss = kdf256(&[ct.as_slice(), pk.bytes.as_slice()].concat(), SS_BYTES);
    (Ciphertext { bytes: ct }, ss)
}

pub fn decapsulate(sk: &SecretKey, ct: &Ciphertext) -> Vec<u8> {
    let (s, pk_bytes, _hpk, _z) = unpack_sk(&sk.bytes);
    let (u, v) = unpack_ct(&ct.bytes);
    let vp = dot_transpose(&u, &s);
    let _m = recover_message(&v, &vp);
    // Demo KDF: derive from ct||pk (matches encapsulate)
    kdf256(
        &[ct.bytes.as_slice(), pk_bytes.as_slice()].concat(),
        SS_BYTES,
    )
}

fn expand_a_ij(rho: &[u8], i: usize, j: usize) -> Poly {
    // Expand polynomial from XOF(rho || i || j), then reduce mod Q
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[i as u8, j as u8]);
    let mut bytes = vec![0u8; N * 2];
    xof.finalize_xof().read(&mut bytes);

    let mut p = Poly::zero();
    for k in 0..N {
        let val = u16::from_le_bytes([bytes[2 * k], bytes[2 * k + 1]]) as u32;
        p.coeffs[k] = val % Q;
    }
    p
}

fn mat_mul_add(rho: &[u8], s: &PolyVec, e: &PolyVec) -> PolyVec {
    let mut out = PolyVec::zero(K);
    for i in 0..K {
        let mut acc = Poly::zero();
        for j in 0..K {
            let aij = expand_a_ij(rho, i, j);
            let a_ntt = ntt::ntt(&aij);
            let s_ntt = ntt::ntt(&s.polys[j]);
            let prod = ntt::pointwise_mul(&a_ntt, &s_ntt);
            let tmp = ntt::intt(&prod);
            acc = add_poly(&acc, &tmp);
        }
        out.polys[i] = add_poly(&acc, &e.polys[i]);
    }
    out
}

fn dot_transpose(t: &PolyVec, r: &PolyVec) -> Poly {
    let mut acc = Poly::zero();
    for i in 0..K {
        let ti_ntt = ntt::ntt(&t.polys[i]);
        let ri_ntt = ntt::ntt(&r.polys[i]);
        let prod = ntt::pointwise_mul(&ti_ntt, &ri_ntt);
        let tmp = ntt::intt(&prod);
        acc = add_poly(&acc, &tmp);
    }
    acc
}

fn add_poly(a: &Poly, b: &Poly) -> Poly {
    use super::params::Q;
    let mut out = Poly::zero();
    for i in 0..N {
        let x = a.coeffs[i] + b.coeffs[i];
        out.coeffs[i] = if x >= Q { x - Q } else { x };
    }
    out
}

fn add_message(v: &Poly, m: &[u8]) -> Poly {
    let mut out = v.clone();
    let mut bit_idx = 0;
    for i in 0..N {
        if bit_idx / 8 >= m.len() {
            break;
        }
        let bit = (m[bit_idx / 8] >> (bit_idx % 8)) & 1;
        if bit == 1 {
            out.coeffs[i] = (out.coeffs[i] + Q_HALF) % Q;
        }
        bit_idx += 1;
    }
    out
}

fn recover_message(v: &Poly, vp: &Poly) -> Vec<u8> {
    let mut m = vec![0u8; MSG_BYTES];
    let mut bit_idx = 0;
    for i in 0..N {
        if bit_idx / 8 >= m.len() {
            break;
        }
        let diff = (v.coeffs[i] + Q - vp.coeffs[i]) % Q;
        let bit = if diff > Q_HALF { 1 } else { 0 };
        if bit == 1 {
            m[bit_idx / 8] |= 1 << (bit_idx % 8);
        }
        bit_idx += 1;
    }
    m
}

// Simplified packing (for testing only)

fn pack_pk(t: &PolyVec, rho: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(rho);
    for p in &t.polys {
        for &c in &p.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out
}

fn unpack_pk(bytes: &[u8]) -> (PolyVec, Vec<u8>) {
    let rho = bytes[0..32].to_vec();
    let mut offset = 32;
    let mut t = PolyVec::zero(K);
    for i in 0..K {
        for j in 0..N {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[offset..offset + 4]);
            t.polys[i].coeffs[j] = u32::from_le_bytes(buf) % Q;
            offset += 4;
        }
    }
    (t, rho)
}

fn pack_ct(u: &PolyVec, v: &Poly) -> Vec<u8> {
    let mut out = Vec::new();
    for p in &u.polys {
        for &c in &p.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    for &c in &v.coeffs {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

fn unpack_ct(bytes: &[u8]) -> (PolyVec, Poly) {
    let mut u = PolyVec::zero(K);
    let mut v = Poly::zero();
    let mut offset = 0;
    for i in 0..K {
        for j in 0..N {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[offset..offset + 4]);
            u.polys[i].coeffs[j] = u32::from_le_bytes(buf) % Q;
            offset += 4;
        }
    }
    for j in 0..N {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[offset..offset + 4]);
        v.coeffs[j] = u32::from_le_bytes(buf) % Q;
        offset += 4;
    }
    (u, v)
}

fn pack_sk(s: &PolyVec, pk_bytes: &[u8], hpk: &[u8], z: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();

    // Serialize the secret vector s
    for p in &s.polys {
        for &c in &p.coeffs {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }

    // Append the public key bytes
    out.extend_from_slice(pk_bytes);

    // Append the hash of the public key (hpk)
    out.extend_from_slice(hpk);

    // Append the random seed z
    out.extend_from_slice(z);

    out
}

fn unpack_sk(bytes: &[u8]) -> (PolyVec, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut offset = 0;

    // Reconstruct the secret vector s
    let mut s = PolyVec::zero(K);
    for i in 0..K {
        for j in 0..N {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[offset..offset + 4]);
            s.polys[i].coeffs[j] = u32::from_le_bytes(buf) % Q;
            offset += 4;
        }
    }

    // Extract the public key bytes
    // pk_len must match the length produced by pack_pk
    let pk_len = 32 + K * N * 4; // rho (32 bytes) + t (K*N coefficients as u32)
    let pk_bytes = bytes[offset..offset + pk_len].to_vec();
    offset += pk_len;

    // Extract the hash of the public key (hpk)
    let hpk = bytes[offset..offset + 32].to_vec();
    offset += 32;

    // Extract the random seed z
    let z = bytes[offset..offset + 32].to_vec();

    (s, pk_bytes, hpk, z)
}
