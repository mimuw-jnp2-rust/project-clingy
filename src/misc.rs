pub fn align(num: u64, bound: u64) -> u64 {
    ((num + (bound - 1)) / bound) * bound
}
