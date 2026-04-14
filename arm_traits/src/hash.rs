pub trait RMHash {
    type Output: AsRef<[u8]> + Copy + Eq + core::fmt::Debug;

    fn hash(input: &[u8]) -> Self::Output;
}
