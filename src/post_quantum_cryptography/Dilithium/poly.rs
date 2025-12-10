//! Polynomial type and operations modulo q, with naive negacyclic convolution.
//! We use X^N + 1 reduction for Dilithium's ring structure.

use super::params::{add_mod, mul_mod, sub_mod, N, Q};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [u32; N],
}

impl Poly {
    pub fn zero() -> Self {
        Poly { coeffs: [0u32; N] }
    }
    pub fn add(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = add_mod(self.coeffs[i], other.coeffs[i]);
        }
        out
    }
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = sub_mod(self.coeffs[i], other.coeffs[i]);
        }
        out
    }
    /// Naive negacyclic convolution: (a * b) mod (X^N + 1, q)
    pub fn mul_negacyclic(&self, other: &Poly) -> Poly {
        let mut tmp = vec![0u32; 2 * N - 1];
        // schoolbook convolution
        for i in 0..N {
            for j in 0..N {
                let idx = i + j;
                let prod = mul_mod(self.coeffs[i], other.coeffs[j]);
                tmp[idx] = add_mod(tmp[idx], prod);
            }
        }
        // reduce modulo X^N + 1: for k >= N, fold with sign
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = tmp[i];
        }
        for k in N..(2 * N - 1) {
            let folded = tmp[k];
            let target = k - N;
            // X^N ≡ -1, so add q - folded (i.e., subtract)
            out.coeffs[target] = sub_mod(out.coeffs[target], folded);
        }
        out
    }
}

#[derive(Clone, Debug)]
pub struct PolyVec {
    pub polys: Vec<Poly>,
}

impl PolyVec {
    pub fn zero(k: usize) -> Self {
        PolyVec {
            polys: (0..k).map(|_| Poly::zero()).collect(),
        }
    }
    pub fn add(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.polys.len(), other.polys.len());
        let mut out = PolyVec::zero(self.polys.len());
        for i in 0..self.polys.len() {
            out.polys[i] = self.polys[i].add(&other.polys[i]);
        }
        out
    }
    pub fn sub(&self, other: &PolyVec) -> PolyVec {
        assert_eq!(self.polys.len(), other.polys.len());
        let mut out = PolyVec::zero(self.polys.len());
        for i in 0..self.polys.len() {
            out.polys[i] = self.polys[i].sub(&other.polys[i]);
        }
        out
    }
}
