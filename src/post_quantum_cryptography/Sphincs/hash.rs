//! Hash primitives for the pedagogical SPHINCS-like scheme.
//! Uses SHAKE256 as a versatile XOF for hashing and PRF.

use sha3::digest::XofReader;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake256;

pub fn shake256(out_len: usize, inputs: &[&[u8]]) -> Vec<u8> {
    let mut xof = Shake256::default();
    for inp in inputs {
        xof.update(inp);
    }
    let mut out = vec![0u8; out_len];
    xof.finalize_xof().read(&mut out);
    out
}

/// PRF: derive pseudo-random bytes from a secret and context.
pub fn prf(secret: &[u8], ctx: &[u8], out_len: usize) -> Vec<u8> {
    shake256(out_len, &[secret, ctx])
}

/// H: simple hash to N bytes.
pub fn h_n(inputs: &[&[u8]], n: usize) -> [u8; 32] {
    let v = shake256(n, inputs);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..n]);
    out
}

/// Concatenate helper.
pub fn cat3(a: &[u8], b: &[u8], c: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(a.len() + b.len() + c.len());
    v.extend_from_slice(a);
    v.extend_from_slice(b);
    v.extend_from_slice(c);
    v
}
