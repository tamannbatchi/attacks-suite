// This code detects r collisions in a signature dataset to recover the private key

use crate::ecdsa::ecdsa::Signature;
use hex;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ff::PrimeField;
use k256::{FieldBytes, Scalar};
use rand::thread_rng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub fn detect_nonce_collisions(signatures: &[(Signature, Scalar)]) {
    // Hash table of key r as [u8; 32] and values as a list of pairs (s, z)
    let mut r_map: HashMap<[u8; 32], Vec<(Scalar, Scalar)>> = HashMap::new();

    // Filling of HashMap
    for (sig, z) in signatures {
        let s = Scalar::from_repr(sig.s).unwrap();
        let r_bytes: [u8; 32] = sig.r.as_slice().try_into().unwrap();
        r_map.entry(r_bytes).or_default().push((s, *z));
    }

    // Analysis of collisions
    for (r_bytes, entries) in r_map.iter() {
        if entries.len() >= 2 {
            println!("Collision detected for r = {:?}", hex::encode(r_bytes));

            // Private key recovery
            for i in 0..entries.len() {
                for j in i + 1..entries.len() {
                    let (s1, z1) = entries[i];
                    let (s2, z2) = entries[j];

                    let r_bytes: [u8; 32] = [0u8; 32];
                    let r_field_bytes = FieldBytes::clone_from_slice(&r_bytes);

                    let r = Scalar::from_repr(r_field_bytes).unwrap();
                    let k: Scalar = (z1 - z2) * (s1 - s2).invert().unwrap();
                    let d: Scalar = (s1 * k - z1) * r.invert().unwrap();

                    println!("Clé privée récupérée : {:?}", d.to_bytes());
                }
            }
        }
    }
}
