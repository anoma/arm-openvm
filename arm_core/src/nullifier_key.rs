//! # nullifier_key
//!
//! An implemetation of a nullifier key interface.

use crate::hash::keccak256;
use arm_traits::nullifier_key::RMNullifierKey;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NullifierKey {
    bytes: [u8; 32],
}

impl NullifierKey {
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl RMNullifierKey for NullifierKey {
    type NKCommitment = [u8; 32];

    fn commit(&self) -> [u8; 32] {
        keccak256(&self.bytes)
    }
}
