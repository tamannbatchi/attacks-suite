// Implementation of ECDSA signature on secp256k1 curve
// by injecting an external nonce

use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::Secp256k1;
use k256::{ecdsa::SigningKey, elliptic_curve::FieldBytes};
use k256::{AffinePoint, ProjectivePoint, Scalar};
use rand::thread_rng;
use rand::Rng;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Signature {
    pub r: FieldBytes<Secp256k1>,
    pub s: FieldBytes<Secp256k1>,
}

pub fn sign_with_nonce(sk: &SigningKey, msg: &[u8], k: FieldBytes<Secp256k1>) -> Signature {
    // Hash of msg message and convertion to scalar modulo the curve order
    let z = Sha256::digest(msg);
    let z_int = Scalar::from_repr(z.into()).unwrap();

    // Calculation of abscissa r of R = k*G
    let k_scalar = Scalar::from_repr(k).unwrap();
    let r_point = (k256::ProjectivePoint::generator() * &k_scalar).to_affine();
    let encoded = r_point.to_encoded_point(false);
    let x_bytes = encoded.x().expect("missing x coordinate");
    let r_scalar = Scalar::from_repr(*x_bytes).expect("invalid scalar");

    // Convertion of private key to bytes and transformation to scalar modulo the order
    let priv_scalar = sk.to_bytes();
    let priv_int = Scalar::from_repr(priv_scalar).unwrap();

    // Calculation of s = k⁻¹ · (z + r·priv)
    let s = k_scalar.invert().unwrap() * (z_int + r_scalar * priv_int);

    Signature {
        r: r_scalar.to_bytes(),
        s: s.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_signature_structure_is_valid() {
        // Fix private key
        let sk = SigningKey::random(&mut thread_rng());

        let msg = b"hello world";
        let nonce = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let sig = sign_with_nonce(&sk, msg, nonce.into());

        // Verifie that r and s have 32 bytes
        assert_eq!(sig.r.len(), 32, "r doit avoir 32 octets");
        assert_eq!(sig.s.len(), 32, "s doit avoir 32 octets");
    }

    #[test]
    fn test_signature_is_deterministic_with_fixed_nonce() {
        let sk = SigningKey::random(&mut thread_rng());

        let msg = b"hello world";
        let nonce = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        let sig1 = sign_with_nonce(&sk, msg, nonce.into());
        let sig2 = sign_with_nonce(&sk, msg, nonce.into());

        // Verifie that the signature is reproductible with the same nonce
        assert_eq!(sig1.r, sig2.r);
        assert_eq!(sig1.s, sig2.s);
    }

    #[test]
    fn test_signature_changes_with_nonce() {
        let sk = SigningKey::random(&mut thread_rng());

        let msg = b"hello world";
        let nonce1 = hex!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let nonce2 = hex!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let sig1 = sign_with_nonce(&sk, msg, nonce1.into());
        let sig2 = sign_with_nonce(&sk, msg, nonce2.into());

        // Verifie that the signature changes if the nonce changes
        assert_ne!(sig1.r, sig2.r);
        assert_ne!(sig1.s, sig2.s);
    }
}
