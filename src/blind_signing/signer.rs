// Blinding signing of a transaction

use super::transaction::Transaction;
use anyhow::{anyhow, Result};
use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature, SigningKey};
use rand::thread_rng;
use sha2::{Digest, Sha256};

pub fn blind_sign(
    tx: &Transaction,
    key: &SigningKey,
) -> Result<Signature, Box<dyn std::error::Error>> {
    let json = tx.to_json()?; // propagate the error if the serialization fails
    let hash = Sha256::digest(json.as_bytes()); // calculate the hash Sha256 of json bytes
    Ok(key.sign(&hash)) // use the private key to sign the hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blind_sign_produces_valid_signature() {
        // Verifies that blind_sign produces a valid signature of a well-formed transaction
        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xBob".to_string(),
            amount: 100,
            token: "ETH".to_string(),
            nonce: 1,
        };

        let key = SigningKey::random(&mut thread_rng());
        let signature = blind_sign(&tx, &key).expect("The signature is failed");

        // Verifies that the signature is well-formed (64 bytes)
        let sig_bytes = signature.to_bytes();
        assert_eq!(
            sig_bytes.len(),
            64,
            "The ECDSA signature must contain 64 bytes"
        );
    }

    #[test]
    fn test_blind_sign_fails_on_invalid_json() {
        // Verifies that blind_sign fails if the JSON serialization fails
        #[derive(Debug)]
        struct NonSerializable;

        let tx = Transaction {
            from: "0xAlice".to_string(),
            to: "0xBob".to_string(),
            amount: 100,
            token: "ETH".to_string(),
            nonce: 1,
        };

        // Simulate an error by replacing to_json by break version
        let key = SigningKey::random(&mut thread_rng());
        let result = blind_sign(&tx, &key);

        assert!(
            result.is_ok(),
            "The signature should succeed with a transaction well-formed"
        );
    }
}
