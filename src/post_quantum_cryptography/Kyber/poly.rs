// Polynomial type and basic ops modulo Q.

use super::params::{N, Q};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [u32; N],
}

impl Poly {
    pub fn zero() -> Self {
        Poly { coeffs: [0u32; N] }
    }
    pub fn from_slice(xs: &[u32]) -> Self {
        assert_eq!(xs.len(), N);
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = xs[i] % Q;
        }
        p
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
}

pub fn add(a: &Poly, b: &Poly) -> Poly {
    let mut out = Poly::zero();
    for i in 0..N {
        let x = a.coeffs[i] + b.coeffs[i];
        out.coeffs[i] = if x >= Q { x - Q } else { x };
    }
    out
}
