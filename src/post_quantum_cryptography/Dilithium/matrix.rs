//! Expand public matrix A from rho: K x L polynomials.
//! Educational uniform expansion per (i,j) with nonce.

use super::params::{K, L};
use super::poly::Poly;
use super::sampling::uniform_poly;

pub fn expand_a(rho: &[u8]) -> Vec<Vec<Poly>> {
    let mut a = vec![vec![Poly::zero(); L]; K];
    for i in 0..K {
        for j in 0..L {
            let nonce = ((i * L + j) % 256) as u8;
            a[i][j] = uniform_poly(rho, nonce);
        }
    }
    a
}
