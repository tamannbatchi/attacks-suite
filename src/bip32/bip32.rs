// BIP32 Key Derivation

use hmac::{Hmac, Mac};
use num_bigint::{BigUint, ToBigUint};
use num_traits::Zero;
use sha2::Sha512;

const HARDENED_OFFSET: u32 = 0x80000000; // offset from which the indices are considered hardened

const CURVE_ORDER: [u8; 32] =
    hex_literal::hex!("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

pub struct Key {
    pub private_key: [u8; 32],
    pub chain_code: [u8; 32],
}

// Function that takes a master key and derives child keys
pub fn derive_hardened_child(parent: &Key, index: u32) -> Option<Key> {
    if index < HARDENED_OFFSET {
        eprintln!("Rejected non-hardened index: {:08x}", index);
        return None;
    }

    let mut mac = Hmac::<Sha512>::new_from_slice(&parent.chain_code).unwrap();
    let mut data = Vec::new();

    // We concatenate the 0x00 padding (hardened), the parent private key (32 bytes),
    // and the index in big-endian (4 bytes)

    data.push(0x00);
    data.extend_from_slice(&parent.private_key);
    data.extend_from_slice(&index.to_be_bytes());

    // Hash calculation and retrieval of the 64 bytes
    mac.update(&data);
    let result = mac.finalize().into_bytes();

    let il = &result[..32]; // used to derive the new private key
    let ir = &result[32..]; // becomes the new chain code

    // Convert to BigUint for modular addition
    let il_bn = BigUint::from_bytes_be(il);
    let parent_bn = BigUint::from_bytes_be(&parent.private_key);
    let curve_order_bn = BigUint::from_bytes_be(&CURVE_ORDER);

    let child_bn = il_bn + parent_bn;

    // Verification modulo n
    if child_bn >= curve_order_bn || child_bn.is_zero() {
        return None; // invalid key
    }

    let mut child_priv = [0u8; 32];
    let child_bytes = child_bn.to_bytes_be();
    let offset = 32 - child_bytes.len();
    child_priv[offset..].copy_from_slice(&child_bytes);

    // represent the derived child key
    Some(Key {
        private_key: child_priv,
        chain_code: ir.try_into().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_derive_hardened_child_valid() {
        // Master Key (32 bytes) + chain_code (32 bytes)
        let parent = Key {
            private_key: hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            chain_code: hex!("f1f2f3f4f5f6f7f8f9fafbfcfdfeff00112233445566778899aabbccddeeff00"),
        };

        let index = HARDENED_OFFSET + 1; // Index hardened

        let child = derive_hardened_child(&parent, index);

        assert!(child.is_some(), "The derivation should succeed");
        let child_key = child.unwrap();

        // Verifies that the derived private key is not empty
        assert!(child_key.private_key.iter().any(|&b| b != 0));

        // Verifies that the derived chain_code has 32 bytes
        assert_eq!(child_key.chain_code.len(), 32);
    }

    #[test]
    fn test_derive_hardened_child_reject_non_hardened() {
        let parent = Key {
            private_key: [1u8; 32],
            chain_code: [2u8; 32],
        };

        let index = 42; // Non-hardened

        let child = derive_hardened_child(&parent, index);
        assert!(child.is_none(), "L'index non-hardened doit être rejeté");
    }
}
