//! XOF-based stream generator for deriving many bytes deterministically.

use super::hash::shake256;

pub fn stream(seed: &[u8], nonce: &[u8], out_len: usize) -> Vec<u8> {
    shake256(out_len, &[seed, nonce])
}
