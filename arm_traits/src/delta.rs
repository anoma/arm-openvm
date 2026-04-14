pub trait Delta {
    fn add(&self, other: &Self) -> Self;
}
