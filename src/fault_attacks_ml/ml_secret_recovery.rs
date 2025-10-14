use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::tree::decision_tree_classifier::DecisionTreeClassifier;

// This function returns the bit positions of the secret
// based on traces classified as faulty
pub fn recover_secret(
    model: &DecisionTreeClassifier<f32, u8, DenseMatrix<f32>, Vec<u8>>,
    traces: Vec<Vec<f32>>,
    threshold: f32,
) -> Vec<u32> {
    let data = DenseMatrix::from_2d_vec(&traces);
    let predictions = model.predict(&data).unwrap();
    let mut bits = vec![];

    for (i, &p) in predictions.iter().enumerate() {
        if p as f32 > threshold {
            bits.push((i % 32) as u32); // hypothesis : affected bit
        }
    }

    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use smartcore::linalg::basic::matrix::DenseMatrix;
    use smartcore::tree::decision_tree_classifier::DecisionTreeClassifier;
    use smartcore::tree::decision_tree_classifier::DecisionTreeClassifierParameters;

    #[test]
    fn test_recover_secret_detects_faulted_bits() {
        // Verifies that recover_secret identifies correctly the faulted bits
        let traces = vec![
            vec![0.9, 0.8, 0.7],   // ranked as 1
            vec![0.2, 0.1, 0.3],   // ranked as 0
            vec![0.85, 0.9, 0.95], // ranked as 1
        ];
        let labels = vec![1, 0, 1];

        let model = DecisionTreeClassifier::fit(
            &DenseMatrix::from_2d_vec(&traces),
            &labels,
            DecisionTreeClassifierParameters::default(),
        )
        .unwrap();

        let recovered = recover_secret(&model, traces.clone(), 0.5);
        assert_eq!(
            recovered,
            vec![0, 2],
            "Les indices 0 et 2 doivent être considérés comme fautés"
        );
    }
}
