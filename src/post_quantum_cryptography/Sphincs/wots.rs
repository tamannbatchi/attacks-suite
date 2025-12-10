//! Minimal WOTS+ over base-w with SHAKE256 chains. Educational, not optimized.

use super::hash::{h_n, shake256};
use super::params::{N, WOTS_LEN, WOTS_LEN1, WOTS_LEN2, WOTS_LOGW, WOTS_W};

fn base_w(msg: &[u8]) -> Vec<u32> {
    // Convert msg (N bytes) into base-w digits (len1 digits).
    let mut out = Vec::with_capacity(WOTS_LEN1);
    let mut acc = Vec::new();
    for &b in msg {
        acc.push(b);
    }
    let mut bits = acc.iter().map(|&x| x as u32).collect::<Vec<_>>();
    let mut val = 0u32;
    let mut bit_cnt = 0u32;
    for _ in 0..WOTS_LEN1 {
        if bit_cnt < WOTS_LOGW {
            if bits.is_empty() {
                bits.push(0);
            }
            val |= (bits.remove(0) as u32) << (8 - WOTS_LOGW - bit_cnt);
            bit_cnt += 8 - WOTS_LOGW;
        }
        out.push(val & (WOTS_W - 1));
        val >>= WOTS_LOGW;
    }
    out
}

fn checksum(base: &[u32]) -> Vec<u32> {
    let sum: u32 = base.iter().map(|&d| (WOTS_W - 1) - d).sum();
    // Expand sum in base-w into len2 digits
    let mut cs = Vec::with_capacity(WOTS_LEN2);
    let mut s = sum;
    for _ in 0..WOTS_LEN2 {
        cs.push(s & (WOTS_W - 1));
        s >>= WOTS_LOGW;
    }
    cs
}

fn chain_step(x: &[u8], step: u32) -> [u8; N] {
    // Apply 'step' hash iterations to derive the chain output.
    let mut y = [0u8; N];
    y.copy_from_slice(x);
    for i in 0..step {
        let h = h_n(&[&y, &[(i & 0xFF) as u8]], N);
        y.copy_from_slice(&h);
    }
    y
}

pub fn wots_pk(sk_seed: &[u8], pk_seed: &[u8], addr: &[u8]) -> Vec<[u8; N]> {
    // Derive WOTS secret element i from sk_seed||addr||i, then full chain to pk.
    let mut pk = vec![[0u8; N]; WOTS_LEN];
    for i in 0..WOTS_LEN {
        let se = shake256(N, &[sk_seed, addr, &[i as u8]]);
        let yi = chain_step(&se, WOTS_W - 1);
        pk[i] = yi;
    }
    pk
}

pub fn wots_sign(sk_seed: &[u8], pk_seed: &[u8], addr: &[u8], msg_digest: &[u8]) -> Vec<[u8; N]> {
    let mut sig = vec![[0u8; N]; WOTS_LEN];
    let bw = base_w(msg_digest);
    let cs = checksum(&bw);
    let digits = bw.into_iter().chain(cs.into_iter()).collect::<Vec<_>>();
    for i in 0..WOTS_LEN {
        let se = shake256(N, &[sk_seed, addr, &[i as u8]]);
        let yi = chain_step(&se, digits[i]);
        sig[i] = yi;
    }
    sig
}

pub fn wots_verify(
    pk_seed: &[u8],
    addr: &[u8],
    msg_digest: &[u8],
    sig: &[[u8; N]],
) -> Vec<[u8; N]> {
    // Recompute WOTS public key from signature chains complement.
    let bw = base_w(msg_digest);
    let cs = checksum(&bw);
    let digits = bw.into_iter().chain(cs.into_iter()).collect::<Vec<_>>();
    let mut pk = vec![[0u8; N]; WOTS_LEN];
    for i in 0..WOTS_LEN {
        let rem = (WOTS_W - 1) - digits[i];
        let yi = chain_step(&sig[i], rem);
        pk[i] = yi;
    }
    pk
}

pub fn wots_pk_hash(pk: &[[u8; N]]) -> [u8; N] {
    // Hash all pk elements to a compact digest.
    let mut cat = Vec::with_capacity(WOTS_LEN * N);
    for e in pk {
        cat.extend_from_slice(e);
    }
    h_n(&[&cat], N)
}
