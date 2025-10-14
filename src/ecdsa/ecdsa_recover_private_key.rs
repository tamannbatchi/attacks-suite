// Implementation of a classic attack on ECDSA:
// Recovering the private key from two signatures using the same nonce k

use crate::ecdsa::ecdsa::{sign_with_nonce, Signature};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::FieldBytes;
use k256::elliptic_curve::ScalarPrimitive;
use k256::Scalar;
use rand::thread_rng;
use sha2::{Digest, Sha256};

pub fn recover_private_key(sig1: &Signature, sig2: &Signature, z1: Scalar, z2: Scalar) -> Scalar {
    // Convertion of r, s1 and s2 to scalar modulo the curve order
    let r = Scalar::from_repr(sig1.r).unwrap();
    let s1 = Scalar::from_repr(sig1.s).unwrap();
    let s2 = Scalar::from_repr(sig2.s).unwrap();

    let order = Scalar::MODULUS;

    // Calculation of nonce k
    let k = (z1 - z2) * (s1 - s2).invert().unwrap();

    // Calculation of private key
    let priv_key = (s1 * k - z1) * r.invert().unwrap();

    priv_key
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_to_scalar(msg: &[u8]) -> Scalar {
        let hash = Sha256::digest(msg);
        Scalar::from_repr(hash.into()).unwrap()
    }

    #[test]
    fn test_recover_private_key_from_repeated_nonce() {
        // Generate a random private key
        let sk = SigningKey::random(&mut thread_rng());
        let priv_scalar = Scalar::from_repr(sk.to_bytes()).unwrap();

        // Message 1 and 2
        let msg1 = b"message one";
        let msg2 = b"message two";
        let z1 = hash_to_scalar(msg1);
        let z2 = hash_to_scalar(msg2);

        // Fix Nonce
        let k = Scalar::from(123456789u64);

        // Signature 1
        let sig1 = super::sign_with_nonce(&sk, msg1, k.to_bytes());

        // Signature 2
        let sig2 = super::sign_with_nonce(&sk, msg2, k.to_bytes());

        // Recuperation of the private key
        let recovered = recover_private_key(&sig1, &sig2, z1, z2);

        assert_eq!(
            recovered, priv_scalar,
            "The private key must be properly retrieved"
        );
    }

    #[test]
    fn test_recover_fails_if_r_differs() {
        // Random private key
        let sk = SigningKey::random(&mut thread_rng());

        // Messages
        let msg1 = b"msg1";
        let msg2 = b"msg2";
        let z1 = hash_to_scalar(msg1);
        let z2 = hash_to_scalar(msg2);

        // Different Nonces
        let k1 = Scalar::from(111u64);
        let k2 = Scalar::from(222u64);

        let sig1 = super::sign_with_nonce(&sk, msg1, k1.to_bytes());
        let sig2 = super::sign_with_nonce(&sk, msg2, k2.to_bytes());

        // r will be différent → the attack fails
        assert_ne!(sig1.r, sig2.r, "The r must be differents");
    }
}
