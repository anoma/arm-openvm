//! # compliance
//!
//! A trivial implementation of the complaince interface

use crate::{
    error::ArmError, hash::keccak256, nullifier_key::NullifierKey, resource::Resource, tree::Proof,
};
use alloc::vec::Vec;
use arm_traits::resource::Resource as ResourceTrait;
use openvm_algebra_guest::Reduce;
use openvm_ecc_guest::{CyclicGroup, weierstrass::WeierstrassPoint};
use openvm_k256::{Secp256k1Point as CurvePoint, Secp256k1Scalar as Scalar};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct ConsumedWitness {
    resource: Resource,
    nullifier_key: NullifierKey,
    path: Proof,
    delta_extra_input: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct CreatedWitness {
    resource: Resource,
    delta_extra_input: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComplianceWitness {
    consumed: Vec<ConsumedWitness>,
    created: Vec<CreatedWitness>,
}

pub struct ConsumedInstance {
    pub nullifier: [u8; 32],
    pub root: [u8; 32],
    pub logic_ref: [u8; 32],
}

pub struct CreatedInstance {
    pub commitment: [u8; 32],
    pub logic_ref: [u8; 32],
}

pub struct ComplianceInstance {
    pub consumed: Vec<ConsumedInstance>,
    pub created: Vec<CreatedInstance>,
    pub delta_x: [u8; 32],
    pub delta_y: [u8; 32],
}

impl ConsumedWitness {
    pub fn constrain(&self) -> ConsumedInstance {
        let commitment = self.resource.commit();

        ConsumedInstance {
            nullifier: self.resource.nullify(&self.nullifier_key).unwrap(),
            root: self.path.compute_root(commitment),
            logic_ref: self.resource.logic_ref,
        }
    }
}

impl CreatedWitness {
    pub fn constrain(&self) -> CreatedInstance {
        CreatedInstance {
            commitment: self.resource.commit(),
            logic_ref: self.resource.logic_ref,
        }
    }
}

impl ComplianceWitness {
    /// Function providing the core logic for the guest program
    pub fn constrain(&self) -> Result<ComplianceInstance, ArmError> {
        let mut delta = CurvePoint::IDENTITY;
        let consumed_instances: Vec<ConsumedInstance> = self
            .consumed
            .iter()
            .map(|x| {
                delta -= to_delta(&x.resource, x.delta_extra_input);
                x.constrain()
            })
            .collect();
        let mut nullifiers: Vec<[u8; 32]> =
            consumed_instances.iter().map(|x| x.nullifier).collect();
        let length = nullifiers.len();

        // if the nullifier array is empty we cannot guarantee
        // commitment uniqueness
        if length == 0 {
            return Err(ArmError::ComplianceProofEmptyNullifierArray);
        }
        nullifiers.push([0u8; 32]);
        let mut index_bytes = [0u8; 32];
        let mut created_instances = Vec::new();
        for (index, witness) in self.created.iter().enumerate() {
            delta += to_delta(&witness.resource, witness.delta_extra_input);
            index_bytes[..4].copy_from_slice(&(index as u32).to_be_bytes());
            nullifiers[length] = index_bytes;
            // hash the array [index] ++ nullifier array
            // given the array uniqueness is guaranteed by global checks
            // the hash is going to be globally unuque for each commitment
            let hash = keccak256(&nullifiers.concat());
            if witness.resource.nonce != hash {
                return Err(ArmError::ComplianceProofCreatedResourceNonceMismatch);
            }

            created_instances.push(CreatedInstance {
                commitment: witness.resource.commit(),
                logic_ref: witness.resource.logic_ref,
            })
        }

        Ok(ComplianceInstance {
            created: created_instances,
            consumed: consumed_instances,
            delta_x: delta.x_be_bytes(),
            delta_y: delta.y_be_bytes(),
        })
    }
}

fn quantity_to_scalar(quantity: u128) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&quantity.to_le_bytes());
    Scalar::reduce_le_bytes(&bytes)
}

fn extra_value_to_scalar(rcv: [u8; 32]) -> Scalar {
    Scalar::reduce_le_bytes(&rcv)
}

fn to_delta(resource: &Resource, rcv: [u8; 32]) -> CurvePoint {
    resource.kind() * quantity_to_scalar(resource.quantity)
        + CurvePoint::GENERATOR * extra_value_to_scalar(rcv)
}
