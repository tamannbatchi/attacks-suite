// Function that calculates the variance of a set of time-series data
// to detect anomalies or leaks in timing attacks
pub fn variance(data: &[u128]) -> f64 {
    // Arithmetic mean of the elements of data
    let mean = data.iter().sum::<u128>() as f64 / data.len() as f64;

    // sum of the squared deviations divided by the number of elements (variance)
    data.iter()
        .map(|&x| {
            let diff = x as f64 - mean;
            diff * diff
        })
        .sum::<f64>()
        / data.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_variance_constant_values() {
        // All the items are identical → variance = 0
        let data = vec![100u128; 5];
        let result = variance(&data);
        assert_eq!(result, 0.0, "The variance of a constant series must be 0");
    }

    #[test]
    fn test_variance_known_values() {
        // simple series : [1, 2, 3, 4, 5]
        // Mean = 3, variance = 2.0
        let data = vec![1, 2, 3, 4, 5];
        let result = variance(&data);
        assert!(
            (result - 2.0).abs() < 1e-6,
            "The variance must be close to 2.0"
        );
    }

    #[test]
    fn test_variance_single_element() {
        // One value → variance = 0
        let data = vec![42];
        let result = variance(&data);
        assert_eq!(result, 0.0, "The variance of a single element must be 0");
    }

    #[test]
    fn test_variance_empty_slice() {
        // limit case : empty slice → division by zero avoided ?
        let data: Vec<u128> = vec![];
        let result = variance(&data);
        assert!(
            result.is_nan(),
            "The variance of an empty vector must be NaN"
        );
    }

    #[test]
    fn test_variance_large_values() {
        // Check that the function handles large integers without overflow
        let data = vec![1_000_000_000_000u128, 1_000_000_000_001, 999_999_999_999];
        let result = variance(&data);
        assert!(
            result > 0.0,
            "The variance must be positive for dispersed values"
        );
    }
}
