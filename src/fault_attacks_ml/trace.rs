// This code generates the simulated traces of consumption with and without fault

use rand::seq::SliceRandom;
use rand::Rng;

// Generate faulty and non-faulty traces, with mixed labels
pub fn gen_traces(n: usize, fault_ratio: f32, trace_len: usize) -> (Vec<Vec<f32>>, Vec<u8>) {
    let fault_count = (n as f32 * fault_ratio).round() as usize; // Number of faulty traces
    let normal_count = n - fault_count; // Number of non-faulty traces

    let mut rng = rand::thread_rng();
    let mut traces = Vec::with_capacity(n);
    let mut labels = Vec::with_capacity(n);

    // Non-faulty traces
    for _ in 0..normal_count {
        let trace: Vec<f32> = (0..trace_len)
            .map(|_| rng.gen_range(0.0..1.0)) // normal noise
            .collect();
        traces.push(trace);
        labels.push(0);
    }

    // Faulty traces
    for _ in 0..fault_count {
        let trace: Vec<f32> = (0..trace_len)
            .map(|_| rng.gen_range(0.5..1.5)) // faulty noise
            .collect();
        traces.push(trace);
        labels.push(1);
    }

    // Random mix of traces
    let mut combined: Vec<(Vec<f32>, u8)> = traces.into_iter().zip(labels.into_iter()).collect();
    combined.shuffle(&mut rng);

    let (traces_shuffled, labels_shuffled): (Vec<_>, Vec<_>) = combined.into_iter().unzip();
    (traces_shuffled, labels_shuffled)
}
