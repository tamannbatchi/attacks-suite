use std::time::Instant;

// Function that measures the execution time of a function f
pub fn measure<F: FnOnce()>(f: F) -> u128 {
    let start = Instant::now();
    f();
    start.elapsed().as_nanos()
}
