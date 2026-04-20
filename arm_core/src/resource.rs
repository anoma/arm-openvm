//! # resource
//!
//! A trivial implementation of the resource interface
//! Posesses trivial randomness

use crate::{
    hash::keccak256,
    hash_to_curve::{DST, hash_from_bytes},
    nullifier_key::NullifierKey,
};
use alloc::vec::Vec;
use arm_traits::{nullifier_key::RMNullifierKey, resource::Resource as ResourceTrait};
use openvm_k256::Secp256k1Point;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Resource {
    pub logic_ref: [u8; 32],
    pub label_ref: [u8; 32],
    pub value_ref: [u8; 32],
    pub quantity: u128,
    pub nonce: [u8; 32],
    pub nk_commitment: [u8; 32],
    pub is_ephemeral: bool,
}

impl Resource {
    fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 * 5 + 16 + 1);
        bytes.extend_from_slice(&self.logic_ref);
        bytes.extend_from_slice(&self.label_ref);
        bytes.extend_from_slice(&self.value_ref);
        // use big endian encoding for evm
        bytes.extend_from_slice(&self.quantity.to_be_bytes());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.nk_commitment);
        bytes.push(self.is_ephemeral as u8);
        return bytes;
    }

    fn to_bytes(&self) -> [u8; 177] {
        let mut bytes = [0u8; 32 * 5 + 16 + 1];
        bytes[0..32].copy_from_slice(&self.logic_ref);
        bytes[32..64].copy_from_slice(&self.label_ref);
        bytes[64..96].copy_from_slice(&self.value_ref);
        // use big endian encoding for evm
        bytes[96..112].copy_from_slice(&self.quantity.to_be_bytes());
        bytes[112..144].copy_from_slice(&self.nonce);
        bytes[144..176].copy_from_slice(&self.nk_commitment);
        bytes[176] = self.is_ephemeral as u8;
        return bytes;
    }
}

impl ResourceTrait<NullifierKey> for Resource {
    type RLogicRef = [u8; 32];
    type RLabelRef = [u8; 32];
    type RValueRef = [u8; 32];
    type RQuantity = u128;
    type RNonce = [u8; 32];
    type RKind = Secp256k1Point;
    type RRandSeed = ();
    type RCommitment = [u8; 32];
    type RNullifier = [u8; 32];
    type RDelta = [u8; 32];

    fn get_logic_ref(&self) -> &Self::RLogicRef {
        &self.logic_ref
    }

    fn get_label_ref(&self) -> &Self::RLabelRef {
        &self.label_ref
    }

    fn get_value_ref(&self) -> &Self::RValueRef {
        &self.value_ref
    }

    fn get_quantity(&self) -> &Self::RQuantity {
        &self.quantity
    }

    fn get_nonce(&self) -> &Self::RNonce {
        &self.nonce
    }

    fn get_nk_commitment(&self) -> &<NullifierKey as RMNullifierKey>::NKCommitment {
        &self.nk_commitment
    }

    fn get_random_seed(&self) -> &Self::RRandSeed {
        &()
    }
    fn is_ephemeral(&self) -> bool {
        self.is_ephemeral
    }

    fn commit(&self) -> Self::RCommitment {
        keccak256(&self.to_bytes())
    }

    fn compute_kind(logic_ref: &Self::RLogicRef, label_ref: &Self::RLabelRef) -> Self::RKind {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(logic_ref);
        bytes[32..].copy_from_slice(label_ref);
        hash_from_bytes(&bytes, DST)
    }

    fn compute_nullifier(&self, nk: &NullifierKey) -> Self::RNullifier {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.commit());
        bytes[32..].copy_from_slice(nk.to_bytes());
        keccak256(&bytes)
    }
}
