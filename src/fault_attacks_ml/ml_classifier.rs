/// This code trains a classifier on the traces
use smartcore::linalg::basic::matrix::DenseMatrix;
use smartcore::metrics::accuracy;
use smartcore::model_selection::train_test_split;
use smartcore::tree::decision_tree_classifier::DecisionTreeClassifier;
use smartcore::tree::decision_tree_classifier::DecisionTreeClassifierParameters;

pub fn train_classifier(
    traces: Vec<Vec<f32>>,
    labels: Vec<u8>,
) -> DecisionTreeClassifier<f32, u8, DenseMatrix<f32>, Vec<u8>> {
    // Convert data to DenseMatrix
    let x = DenseMatrix::from_2d_vec(&traces);
    let y = labels;

    // Create the classifier
    let classifier =
        DecisionTreeClassifier::fit(&x, &y, DecisionTreeClassifierParameters::default())
            .expect("Training error");

    classifier
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::train_classifier;

    #[test]
    fn test_classifier_trains_and_predicts_correctly() {
        // This test verifies that the classifier can learn a simple separation
        let traces = vec![
            vec![0.1, 0.2, 0.3],
            vec![0.2, 0.1, 0.4],
            vec![0.9, 0.8, 0.7],
            vec![0.8, 0.9, 0.6],
        ];
        let labels = vec![0, 0, 1, 1];

        let classifier = train_classifier(traces.clone(), labels.clone());

        let x_test = DenseMatrix::from_2d_vec(&traces);
        let predictions = classifier.predict(&x_test).unwrap();

        let acc = accuracy(&labels, &predictions);
        assert!(
            acc >= 0.99,
            "The classifier should achieve high accuracy on the training data"
        );
    }

    #[test]
    fn test_classifier_fails_on_mismatched_lengths() {
        // This test verifies that the training fails if the lengths don't correspond
        let traces = vec![vec![0.1, 0.2, 0.3], vec![0.2, 0.1, 0.4]];
        let labels = vec![0];

        let result = std::panic::catch_unwind(|| {
            train_classifier(traces.clone(), labels.clone());
        });

        assert!(
            result.is_err(),
            "The classifier must panic if the lengths don't correspond"
        );
    }
}
