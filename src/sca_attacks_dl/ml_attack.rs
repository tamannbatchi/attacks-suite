// Attack based on Deep Learning to predict secret_bit
// from its trace by using Python prediction model (predict.py)

use crate::trace_generator;
use std::process::Command;
use std::str;

pub fn run_deep_learning_attack(secret_bit: u8) {
    // Generate a synthetic trace for the given bit
    let trace = trace_generator::generate_trace(secret_bit);

    let trace_f64: Vec<f64> = trace.iter().map(|&x| x as f64).collect();
    if let Err(e) = trace_generator::save_traces("output/Traces.csv", &[(secret_bit, trace_f64)]) {
        eprintln!("Error while saving : {}", e);
    }

    // Call the Python model with the CSV file
    let output = Command::new("python3")
        .arg("ml/predict.py")
        .arg("output/Traces.csv")
        .output()
        .expect("Échec de l'exécution du modèle Python");

    // Display the prediction returned by the model
    if output.status.success() {
        let prediction = String::from_utf8_lossy(&output.stdout);
        println!(
            "Trace for bit {} → Predicted: {}",
            secret_bit,
            prediction.trim()
        );
    } else {
        eprintln!(
            "Erreur du modèle : {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
