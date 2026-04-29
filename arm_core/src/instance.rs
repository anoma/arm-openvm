//! # instance
//!
//! A module implementing all instance data in the sense of public inputs
//! that an Anoma verifier receives, including the transaction datatype.
//!
//! Implemented for efficiency in size and computation.

use crate::{
    error::ArmError,
    proving::{DEF_IDX, LOGIC_VM_COMMIT},
};
use alloc::vec::Vec;
use openvm_verify_stark_guest::verify_stark_unchecked;

pub type Proof = Vec<u8>;

/// A payload struct encoding a blob and indexing information.
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct Payload {
    pub data: Vec<u8>,
    pub deletion_criterion: bool,
}

/// Appdata struct encoding different kinds of payloads.
#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct AppData {
    pub resource_payload: Vec<Payload>,
    pub encryption_payload: Vec<Payload>,
    pub external_payload: Vec<Payload>,
    pub discovery_payload: Vec<Payload>,
}

/// Instance returned by the compliance program for each consumed resource
pub struct ConsumedInstance {
    pub nullifier: [u8; 32],
    pub root: [u8; 32],
    pub outer_logic_ref: [u8; 32],
    // these fields are added for wrapping
    pub app_data: AppData,
}

/// Instance returned by the compliance program for each created resource
pub struct CreatedInstance {
    pub commitment: [u8; 32],
    pub outer_logic_ref: [u8; 32],
    // these fields are added for wrapping
    pub app_data: AppData,
}

/// Resource Logic Insance returned by any custom guest program
#[derive(Default, serde::Serialize, serde::Deserialize)]
pub struct ResourceLogicInstance {
    pub tag: [u8; 32],
    pub action_root: [u8; 32],
    pub is_consumed: bool,
    pub app_data: AppData,
}

impl ResourceLogicInstance {
    pub fn verify(&self, logic_ref: [u8; 32], proof_commit: [u8; 32]) -> Result<(), ArmError> {
        let journal = verify_stark_unchecked::<DEF_IDX>(&proof_commit);

        if journal.app_exe_commit != logic_ref || journal.app_vm_commit != LOGIC_VM_COMMIT {
            return Err(ArmError::GeneralError);
        }

        todo!("check instance bytes against the user_public_values")
    }
}

/// A type implementing both compliance unit and action interfaces
pub struct ActionInstance {
    pub consumed: Vec<ConsumedInstance>,
    pub created: Vec<CreatedInstance>,
    pub delta_x: [u8; 32],
    pub delta_y: [u8; 32],
}

/// A type implementing both compliance unit and action interfaces
pub struct ActionVerifierInput {
    pub action_instance: ActionInstance,
    pub compliance_proof: Proof,
}

/// An RM transaction datatype
/// Assumes one compliance unit per action
pub struct Transaction {
    // Since we have variable-sized proofs, we can assume that
    // each each action corresponds to exactly one compliance unit
    // in this implementation
    units: Vec<(ActionInstance, Proof)>,
    delta_proof: [u8; 65],
    aggregation_proof: Vec<u8>,
}
