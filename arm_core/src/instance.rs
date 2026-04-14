//! # instance
//!
//! A module implementing all instance data in the sense of public inputs
//! that an Anoma verifier receives, including the transaction datatype.
//!
//! Implemented for efficiency in size and computation.

use crate::compliance::{ComplianceInstance, ConsumedInstance, CreatedInstance};
use alloc::vec::Vec;
//use k256::ecdsa::{RecoveryId, Signature};
// Enable later to support inidivdual proofs
// use openvm_circuit::arch::ContinuationVmProof;
// use openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2Config;

/// A payload struct encoding a blob and indexing information.
pub struct Payload {
    pub data: Vec<u8>,
    pub deletion_criterion: bool,
}

/// Appdata struct encoding different kinds of payloads.
pub struct AppData {
    pub resource_payload: Vec<Payload>,
    pub encryption_payload: Vec<Payload>,
    pub external_payload: Vec<Payload>,
    pub discovery_payload: Vec<Payload>,
}

/// Instance data associated with a specific resource tag
/// Currently can be used for both consumed and created resources
pub struct ResourceInstanceData {
    pub tag: [u8; 32],
    pub logic_ref: [u8; 32],
    pub appdata: AppData,
    pub logic_proof: Vec<u8>,
    pub root: Option<[u8; 32]>,
}

/// A type implementing both compliance unit and action interfaces
pub struct InstanceDataUnit {
    created: Vec<ResourceInstanceData>,
    consumed: Vec<ResourceInstanceData>,
    delta_x: [u32; 8],
    delta_y: [u32; 8],
    compliance_proof: Vec<u8>,
}

/// An RM transaction datatype
/// Assumes one compliance unit per action
pub struct Transaction {
    // Since we have variable-sized proofs, we can assume that
    // each each action corresponds to exactly one compliance unit
    // in this implementation
    units: Vec<InstanceDataUnit>,
    delta_proof: [u8; 65],
    aggregation_proof: Vec<u8>,
}

pub fn to_compliance_instance(
    created: Vec<ResourceInstanceData>,
    consumed: Vec<ResourceInstanceData>,
    delta_x: [u32; 8],
    delta_y: [u32; 8],
) -> ComplianceInstance {
    ComplianceInstance {
        created: created
            .into_iter()
            .map(|x| CreatedInstance {
                commitment: x.tag,
                logic_ref: x.logic_ref,
            })
            .collect(),
        consumed: consumed
            .into_iter()
            .map(|x| ConsumedInstance {
                nullifier: x.tag,
                root: x.root.expect("No root provided"),
                logic_ref: x.logic_ref,
            })
            .collect(),
        delta_x,
        delta_y,
    }
}
