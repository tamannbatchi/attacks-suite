mod bip32;
mod blind_signing;
mod ecdsa;
mod fault_attacks_ml;
mod sca_attacks_dl;

use bip32::{
    bip32::{derive_hardened_child, Key},
    glitch::{glitch_hmac_input, glitch_index},
    stats, timing_attack,
};

use ecdsa::{
    ecdsa::{sign_with_nonce, Signature},
    ecdsa_recover_private_key::recover_private_key,
};

use sca_attacks_dl::{ml_attack, trace_generator};

use blind_signing::{
    attack_blind_signing::inject_malicious,
    classic_contermeasures::{display_transaction, is_safe},
    signer::blind_sign,
    transaction::Transaction,
    zkp_contermeasures::TxCircuit,
};

use fault_attacks_ml::{
    ml_classifier::train_classifier, ml_secret_recovery::recover_secret, trace::gen_traces,
};

use hmac::{Hmac, Mac};
use k256::elliptic_curve::ff::PrimeField;
use k256::{ecdsa::SigningKey, FieldBytes, Scalar};
use rand::thread_rng;
use rand::Rng;
use sha2::{Digest, Sha512};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::process::Command;

use ark_bn254::{Bn254, Fr};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};

use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generation of a random seed
    let seed: [u8; 32] = rand::thread_rng().gen();
    let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
    mac.update(&seed);
    let result = mac.finalize().into_bytes();

    // Master private key and Master chain_code
    let master_priv = result[..32].try_into().unwrap();
    let master_chain = result[32..].try_into().unwrap();
    let master_key = Key {
        private_key: master_priv,
        chain_code: master_chain,
    };

    println!("Master private key: {:02x?}", master_key.private_key);
    println!("Master chain code:  {:02x?}", master_key.chain_code);

    // Test1: Normal child derivation
    println!("Test 1: Normal derivation with BIP32");
    let index = 0x80000002;
    let child_normal = derive_hardened_child(&master_key, index);
    match child_normal {
        Some(child) => println!("Normal child key: {:02x?}", child.private_key),
        None => println!("Normal child key: <invalid>"),
    }

    // Test2: Glitch on index
    println!("Test 2: Glitch on index in BIP32");
    let glitched_index = glitch_index(index);
    println!("Glitched index:   {:08x}", glitched_index);
    let child_glitched = derive_hardened_child(&master_key, glitched_index);
    match child_glitched {
        Some(child) => println!("Glitched child key: {:02x?}", child.private_key),
        None => println!("Glitched child key: <invalid>"),
    }

    // Test 3: Glitch on HMAC input
    println!("Test 3: Glitch sur entrée HMAC dans BIP32");
    let mut hmac_input = Vec::new();
    hmac_input.extend_from_slice(&[0x00]);
    hmac_input.extend_from_slice(&master_key.private_key);
    hmac_input.extend_from_slice(&index.to_be_bytes());
    let glitched_hmac = glitch_hmac_input(&hmac_input);
    println!("Original HMAC input: {:02x?}", hmac_input);
    println!("Glitched HMAC input: {:02x?}", glitched_hmac);

    // Test 4: Timing Attack on BIP32 hardened
    println!("Test 4: Timing Attack on BIP32 hardened");
    let (timings, moyenne) = timing_attack::run_timing_attack(&master_key, index, 100);

    println!(
        " Collected Timings (5 first elements) : {:?}",
        &timings[..5]
    );

    // Save
    let mut file = File::create("output/bip32_timings.csv").unwrap();
    for t in &timings {
        writeln!(file, "{}", t).unwrap();
    }

    // Statistical analysis via stats.rs
    let var = stats::variance(&timings);
    println!(" Mean of execution time of BIP32 : {:.2} ns ", moyenne);
    println!(" Variance of execution time of BIP32 : {:.2} ns ", var);

    // Test 5: Recover private key attack on ECDSA
    println!("Test 5 :Recover private key attack on ECDSA");
    let sk = SigningKey::random(&mut thread_rng());
    let msg1 = b"Transaction A";
    let msg2 = b"Transaction B";

    let k = Scalar::from(123456789u64);
    let reused_k = k.to_bytes();
    println!("Private key for signature: {:02x?}", sk.to_bytes());

    let sig1 = sign_with_nonce(&sk, msg1, reused_k);
    let sig2 = sign_with_nonce(&sk, msg2, reused_k);

    let z1 = Scalar::from_repr(sha2::Sha256::digest(msg1).into()).unwrap();
    let z2 = Scalar::from_repr(sha2::Sha256::digest(msg2).into()).unwrap();

    println!("With the function recover_private_key");
    let recovered = recover_private_key(&sig1, &sig2, z1, z2);
    println!("Recovered private key: {:02x?}", recovered.to_bytes());

    // Test 6: SCA attack by Deep Learning
    println!("Test 6: SCA attack by deep learning to predict bits of secret");

    let dataset: Vec<(u8, Vec<f64>)> = (0..=1)
        .flat_map(|bit| {
            (0..1000).map(move |_| {
                let trace_f32 = trace_generator::generate_trace(bit);
                let trace_f64 = trace_f32.iter().map(|&x| x as f64).collect();
                (bit, trace_f64)
            })
        })
        .collect();

    trace_generator::save_traces("output/dataset.csv", &dataset).unwrap();

    let secret_bit = 1;

    println!(
        "Launching the ML attack to predict the secret bit : {}",
        secret_bit
    );
    ml_attack::run_deep_learning_attack(secret_bit);

    // Test 7: Machine learning and fault injection attacks
    println!("Test 7: Glitch and Machine learning to predict bits positions of the secret");

    // Étape 1 : Generation of faulted traces

    let (traces, labels) = gen_traces(100, 0.3, 64); // 100 traces, 30% faulted, 64 points by trace
    println!("Trace[0] = {:?}", traces[0]);
    println!("Label[0] = {:?}", labels[0]);

    // Étape 2 : Training of the modèle ML
    let model = train_classifier(traces.clone(), labels);

    // Étape 3 : Recuperation of faulted bits positions of the secret
    let recovered_bits = recover_secret(&model, traces, 0.8);

    // Étape 4 : Results display
    println!(
        "Bits Positions that the model ML has identified as faulted : {:?}",
        recovered_bits
    );

    // Test 8: Blindind signing
    println!("Test 8: Blinding signing attack and contermeasures");
    // Generation of a random private key to sign the transaction
    let key = SigningKey::random(&mut thread_rng());

    // Legitimate Transaction
    let legit_tx = Transaction {
        from: "0xUserWallet".to_string(),
        to: "0xSwapPool".to_string(),
        amount: 950,
        token: "USDC".to_string(),
        nonce: 42,
    };

    // Injection of a malicious transaction
    let malicious_tx = inject_malicious(&legit_tx);

    // Clear display
    display_transaction(&malicious_tx);

    // Verification that the transaction respects the conditions: amount <= 1000,
    // recipient is in whitelist, and token is in  the authorized list
    if !is_safe(&malicious_tx) {
        println!(" Transaction blocked : conditions non satisfied.");
        return Ok(());
    }

    // Secure blindind signing
    match blind_sign(&malicious_tx, &key) {
        Ok(sig) => println!(" Transaction signed : {:?}", sig),
        Err(e) => eprintln!(" Error during signing : {}", e),
    }

    // Construction of the ZKP circuit with data extracted from the transaction
    let circuit = TxCircuit {
        amount: malicious_tx.amount,
        to_hash: 12345,  // simulated hash of "0xSwapPool"
        token_hash: 111, // simulated hash of "USDC"
    };

    let rng = &mut thread_rng();

    // Groth16 Setup (generation proof key and verification key)
    let (pk, vk): (ProvingKey<Bn254>, VerifyingKey<Bn254>) =
        match Groth16::<Bn254>::setup(circuit.clone(), rng) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!(" Error during the setup ZKP : {}", e);
                return Ok(());
            }
        };

    // Generation of proof that the transaction respects the circuit constraints
    let proof: Proof<Bn254> = match Groth16::<Bn254>::prove(&pk, circuit.clone(), rng) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(" Error during the proof generation : {}", e);
            return Ok(());
        }
    };

    // Verification of the proof with the public key
    // We give in input an empty vector &[] because no public inputs here
    let pvk = prepare_verifying_key(&vk);
    //let verified = Groth16::<Bn254>::verify_proof(&pvk, &proof, &[])?;
    let verified = match Groth16::<Bn254>::verify_proof(&pvk, &proof, &[]) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(" Error during the verification of proof : {}", e);
            return Ok(());
        }
    };

    if !verified {
        println!(" Invalid ZKP : transaction blocked.");
        return Ok(());
    }
    // Secure Blinding Signing
    match blind_sign(&malicious_tx, &key) {
        Ok(sig) => println!(" Transaction signed with valid ZKP : {:?}", sig),
        Err(e) => eprintln!(" Error during the signature : {}", e),
    }

    Ok(())
}
