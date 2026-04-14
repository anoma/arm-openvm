pub trait RMNullifierKey {
    type NKCommitment;

    fn commit(&self) -> Self::NKCommitment;
}
