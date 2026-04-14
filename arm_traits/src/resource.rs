use crate::nullifier_key::RMNullifierKey;
pub trait Resource<K: RMNullifierKey>
where
    K::NKCommitment: PartialEq,
{
    type RLogicRef;
    type RLabelRef;
    type RValueRef;
    type RQuantity;
    type RNonce;
    type RKind;
    type RRandSeed;
    type RCommitment;
    type RNullifier;
    type RDelta;

    // getters
    fn get_logic_ref(&self) -> &Self::RLogicRef;
    fn get_label_ref(&self) -> &Self::RLabelRef;
    fn get_value_ref(&self) -> &Self::RValueRef;
    fn get_quantity(&self) -> &Self::RQuantity;
    fn get_nonce(&self) -> &Self::RNonce;
    fn get_nk_commitment(&self) -> &K::NKCommitment;
    fn get_random_seed(&self) -> &Self::RRandSeed;
    fn is_ephemeral(&self) -> bool;

    // defaults
    fn kind(&self) -> Self::RKind {
        Self::compute_kind(self.get_logic_ref(), self.get_label_ref())
    }
    fn nullify(&self, nk: &K) -> Result<Self::RNullifier, NullifierError> {
        if &nk.commit() != self.get_nk_commitment() {
            return Err(NullifierError::KeyMismatch);
        }

        Ok(self.compute_nullifier(nk))
    }

    // computational interfaces
    fn commit(&self) -> Self::RCommitment;
    fn compute_kind(logic_ref: &Self::RLogicRef, label_ref: &Self::RLabelRef) -> Self::RKind;
    fn compute_nullifier(&self, nk: &K) -> Self::RNullifier;
}

#[derive(Debug)]
pub enum NullifierError {
    KeyMismatch,
}
