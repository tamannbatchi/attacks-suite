use crate::bip32::bip32::{derive_hardened_child, Key};
use crate::bip32::timing::measure;

// This code simulates a side-channel attack (timing attack here)
// on the derivation of a hardened BIP32 key
// to detect if certain indices or keys cause significant timing variations

pub fn run_timing_attack(master: &Key, index: u32, trials: usize) -> (Vec<u128>, f64) {
    // Vector of execution times of the function derive_hardened_child ( for BIP32) for trial indices
    let mut samples = Vec::new();
    for _ in 0..trials {
        let duration = measure(|| {
            derive_hardened_child(master, index);
        });
        samples.push(duration);
    }

    // Mean of execution time
    let avg = samples.iter().sum::<u128>() as f64 / trials as f64;

    //println!("Average derivation time for index 0x{:08x}: {:.2} ns", index, avg);
    (samples, avg)
}
