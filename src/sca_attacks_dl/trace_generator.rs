// These codes simulate a trace of consumption or emission,
// generate n simulated traces and save traces in a file

use rand::Rng;
use std::fs::File;
use std::io::Write;

// Generate a trace
pub fn generate_trace(secret_bit: u8) -> Vec<f32> {
    let mut trace = Vec::new();
    for i in 0..100 {
        let noise: f32 = rand::thread_rng().gen_range(-0.05..0.05);
        let signal = if secret_bit == 1 {
            0.8 + noise
        } else {
            0.2 + noise
        };
        trace.push(signal);
    }
    trace
}

// Generate n simulated traces
pub fn generate_traces(n: usize) -> Vec<Vec<f32>> {
    (0..n).map(|i| generate_trace((i % 2) as u8)).collect()
}

// Save traces and associated bits in a file
pub fn save_traces(path: &str, dataset: &[(u8, Vec<f64>)]) -> std::io::Result<()> {
    let mut file = File::create(path)?; // Create a new file and propagate the error if the creation fails
    for (label, trace) in dataset {
        let line = std::iter::once(label.to_string())
            .chain(trace.iter().map(|v| format!("{:.4}", v)))
            .collect::<Vec<_>>()
            .join(",");
        writeln!(file, "{}", line)?; // Write the formatted line to the file
                                     // and propagates the error if the write fails
    }
    Ok(())
}
