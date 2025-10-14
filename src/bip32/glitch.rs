//These codes simulate a deliberate derivation error
//on certain data used in BIP32 (BIP32 index, HMAC input)

use hmac::{Hmac, Mac};
use k256::SecretKey;
use rand::Rng;
use sha2::Sha512;

// Function that takes a BIP32 derivation index
// and returns a new index potentially altered by a glitch
pub fn glitch_index(index: u32) -> u32 {
    let glitch_type = rand::thread_rng().gen_range(0..3);
    match glitch_type {
        0 => 0,                  //zero glitch (root key exposed)
        1 => index ^ 0x0000FFFF, //bit flip (alters the low bits of the index)
        2 => index & 0x0000FFFF, //truncate (loss of the hardened bit)
        _ => index,
    }
}

// Function that takes a HMAC input and returns an altered version of this input
pub fn glitch_hmac_input(data: &[u8]) -> Vec<u8> {
    let mut glitched = data.to_vec();
    let flip_index = rand::thread_rng().gen_range(0..data.len());
    glitched[flip_index] ^= 0xFF; // invert all the bits
    glitched
}

// glitch_type is randomly selected in the glitch_index function,
// which makes the tests non-deterministic, and therefore unreliable
// Definition of an internal function to make tests reliable
fn glitch_index_with_type(index: u32, glitch_type: u32) -> u32 {
    match glitch_type {
        0 => 0,                  // Zero glitch
        1 => index ^ 0x0000FFFF, // Bit flip
        2 => index & 0x0000FFFF, // Truncate
        _ => index,
    }
}

// Testable version of the glitch_hmac_input function
fn glitch_hmac_input_at(data: &[u8], flip_index: usize) -> Vec<u8> {
    let mut glitched = data.to_vec();
    glitched[flip_index] ^= 0xFF;
    glitched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_glitch_exposes_root() {
        // Check that the type 0 glitch returns 0 (root key exposed)
        let index = 0x8000002C;
        let glitched = glitch_index_with_type(index, 0);
        assert_eq!(glitched, 0);
    }

    #[test]
    fn test_bit_flip_glitch_alters_index() {
        // Check that the type 1 glitch alters the low bits of the index
        let index = 0x8000002C;
        let expected = index ^ 0x0000FFFF;
        let glitched = glitch_index_with_type(index, 1);
        assert_eq!(glitched, expected);
    }

    #[test]
    fn test_truncate_glitch_removes_hardened_bit() {
        // Check that the type 2 glitch truncates the index (loss of the hardened bit)
        let index = 0x8000002C;
        let expected = index & 0x0000FFFF;
        let glitched = glitch_index_with_type(index, 2);
        assert_eq!(glitched, expected);
    }

    #[test]
    fn test_default_case_returns_original() {
        // Check that any unknown type returns the original index
        let index = 0x8000002C;
        let glitched = glitch_index_with_type(index, 99);
        assert_eq!(glitched, index);
    }

    #[test]
    fn test_bit_flip_at_known_index() {
        // Simulated HMAC Data
        let data = [0xAA, 0xBB, 0xCC, 0xDD];
        let index = 2;

        let glitched = glitch_hmac_input_at(&data, index);

        // Check that only the byte at index 2 is modified
        assert_eq!(glitched.len(), data.len());
        for i in 0..data.len() {
            if i == index {
                assert_eq!(glitched[i], data[i] ^ 0xFF);
            } else {
                assert_eq!(glitched[i], data[i]);
            }
        }
    }

    #[test]
    fn test_flip_on_first_byte() {
        let data = [0x00, 0x11, 0x22];
        let glitched = glitch_hmac_input_at(&data, 0);
        assert_eq!(glitched[0], 0xFF);
        assert_eq!(glitched[1], 0x11);
        assert_eq!(glitched[2], 0x22);
    }

    #[test]
    fn test_flip_on_last_byte() {
        let data = [0x10, 0x20, 0x30];
        let glitched = glitch_hmac_input_at(&data, 2);
        assert_eq!(glitched[0], 0x10);
        assert_eq!(glitched[1], 0x20);
        assert_eq!(glitched[2], 0xCF); // 0x30 ^ 0xFF = 0xCF
    }
}
