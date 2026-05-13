//! # witness
//!
//! A module implementing all general witness data in the sense of guest reads

use crate::{
    error::ArmError,
    hash::keccak256,
    instance::AppData,
    instance::{ActionInstance, ConsumedInstance, CreatedInstance, ResourceLogicInstance},
    nullifier_key::NullifierKey,
    resource::Resource,
    tree::Proof as MerkleProof,
};
use alloc::vec::Vec;
use arm_traits::resource::Resource as ResourceTrait;
use openvm_algebra_guest::Reduce;
use openvm_ecc_guest::{CyclicGroup, weierstrass::WeierstrassPoint};
use openvm_k256::{Secp256k1Point as CurvePoint, Secp256k1Scalar as Scalar};

/// The commitment to the proof used via deferrals
type LogicProofCommitment = [u8; 32];

pub struct ConsumedWitness {
    pub resource: Resource,
    pub nullifier_key: NullifierKey,
    pub path: MerkleProof,
    pub delta_extra_input: [u8; 32],
    // these fields are added for wrapping
    pub logic_hiding_input: [u8; 32],
    pub app_data: AppData,
    pub logic_proof: LogicProofCommitment,
}

pub struct CreatedWitness {
    pub resource: Resource,
    pub delta_extra_input: [u8; 32],
    // these fields are added for wrapping
    pub logic_hiding_input: [u8; 32],
    pub app_data: AppData,
    pub logic_proof: LogicProofCommitment,
}

pub struct ComplianceWitness {
    pub consumed: Vec<ConsumedWitness>,
    pub created: Vec<CreatedWitness>,
    // these fields are added for wrapping
    pub action_root: [u8; 32],
}

impl ConsumedWitness {
    pub fn constrain(&self, action_root: [u8; 32]) -> Result<ConsumedInstance, ArmError> {
        let commitment = self.resource.commit();

        let root = if self.resource.is_ephemeral {
            [0u8; 32]
        } else {
            self.path.compute_root(commitment)
        };

        let nullifier = self.resource.nullify(&self.nullifier_key).unwrap();

        // make sure logic instance and compliance witness data corresponds
        // and return the encoded logic reference
        let outer_logic_ref = process_logic_instance(
            nullifier,
            true,
            self.resource.logic_ref,
            &self.app_data,
            self.logic_proof,
            action_root,
            self.logic_hiding_input,
        )?;

        // return the logic instance, binding to it, as well as the root
        // against which we are consuming and the outer hash of the
        // guestID
        Ok(ConsumedInstance {
            nullifier,
            root,
            outer_logic_ref,
            app_data: self.app_data.clone(),
        })
    }
}

impl CreatedWitness {
    pub fn constrain(&self, action_root: [u8; 32]) -> Result<CreatedInstance, ArmError> {
        let commitment = self.resource.commit();

        // make sure logic instance and compliance witness data corresponds
        // and return the encoded logic reference
        let outer_logic_ref = process_logic_instance(
            commitment,
            false,
            self.resource.logic_ref,
            &self.app_data,
            self.logic_proof,
            action_root,
            self.logic_hiding_input,
        )?;

        // return the logic instance, binding it, as well as the outer
        // hash of the guestID
        Ok(CreatedInstance {
            commitment,
            outer_logic_ref,
            app_data: self.app_data.clone(),
        })
    }
}

fn process_logic_instance(
    tag: [u8; 32],
    is_consumed: bool,
    logic_ref: [u8; 32],
    app_data: &AppData,
    proof: LogicProofCommitment,
    action_root: [u8; 32],
    randomness: [u8; 32],
) -> Result<[u8; 32], ArmError> {
    // verify the logic proof
    let logic_instance = ResourceLogicInstance {
        tag,
        action_root,
        is_consumed,
        app_data: app_data.clone(),
    };

    logic_instance.verify(logic_ref, proof);

    // concatenate the logic reference and randomness bytes
    // as the plaintext to the outer hash
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&logic_ref);
    bytes[32..].copy_from_slice(&randomness);

    Ok(keccak256(&bytes))
}

impl ComplianceWitness {
    /// Function providing the core logic for the compliance guest program
    pub fn constrain(&self) -> Result<ActionInstance, ArmError> {
        let mut delta = CurvePoint::IDENTITY;
        let consumed_instances: Vec<ConsumedInstance> = self
            .consumed
            .iter()
            .map(|x| {
                delta -= to_delta(&x.resource, x.delta_extra_input);
                x.constrain(self.action_root)
            })
            .collect::<Result<Vec<_>, _>>()?;
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

            created_instances.push(witness.constrain(self.action_root)?)
        }

        Ok(ActionInstance {
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
