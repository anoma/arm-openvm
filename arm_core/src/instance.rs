//! # instance
//!
//! A module implementing all instance data in the sense of public inputs
//! that an Anoma verifier receives, including the transaction datatype.
//!
//! Implemented for efficiency in size and computation.

use crate::{
    hash::keccak256,
    proving::{DEF_IDX, LOGIC_VM_COMMIT},
};
use alloc::vec::Vec;
use alloy_sol_types::{SolValue, sol};
use openvm_verify_stark_guest::{ProofOutput, verify_stark};

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

/// A type implementing both compliance instance and action interfaces
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
    pub units: Vec<ActionVerifierInput>,
    pub delta_proof: [u8; 65],
}

// ABI representations of the instance data for EVM chains
sol! {
    struct SolPayload {
        bytes data;
        bool deletionCriterion;
    }

    struct SolAppData {
        SolPayload[] resourcePayload;
        SolPayload[] encryptionPayload;
        SolPayload[] externalPayload;
        SolPayload[] discoveryPayload;
    }

    struct SolLogicInstance {
        bytes32 tag;
        bytes32 actionRoot;
        bool isConsumed;
        SolAppData appData;
    }

    struct SolConsumedInstance {
        bytes32 nullifier;
        bytes32 root;
        bytes32 outerLogicRef;
        SolAppData appData;
    }

    struct SolCreatedInstance {
        bytes32 commitment;
        bytes32 outerLogicRef;
        SolAppData appData;
    }

    struct SolActionInstance {
        SolConsumedInstance[] consumed;
        SolCreatedInstance[] created;
        bytes32 deltaX;
        bytes32 deltaY;
    }
}

impl Payload {
    pub fn to_sol(&self) -> SolPayload {
        SolPayload {
            data: self.data.clone().into(),
            deletionCriterion: self.deletion_criterion,
        }
    }
}

impl AppData {
    pub fn to_sol(&self) -> SolAppData {
        SolAppData {
            resourcePayload: self
                .resource_payload
                .iter()
                .map(|payload| payload.to_sol())
                .collect(),
            encryptionPayload: self
                .encryption_payload
                .iter()
                .map(|payload| payload.to_sol())
                .collect(),
            externalPayload: self
                .external_payload
                .iter()
                .map(|payload| payload.to_sol())
                .collect(),
            discoveryPayload: self
                .discovery_payload
                .iter()
                .map(|payload| payload.to_sol())
                .collect(),
        }
    }
}

impl ConsumedInstance {
    pub fn to_sol(&self) -> SolConsumedInstance {
        SolConsumedInstance {
            nullifier: self.nullifier.into(),
            root: self.root.into(),
            outerLogicRef: self.outer_logic_ref.into(),
            appData: self.app_data.to_sol(),
        }
    }
}

impl CreatedInstance {
    pub fn to_sol(&self) -> SolCreatedInstance {
        SolCreatedInstance {
            commitment: self.commitment.into(),
            outerLogicRef: self.outer_logic_ref.into(),
            appData: self.app_data.to_sol(),
        }
    }
}

impl ActionInstance {
    pub fn to_sol(&self) -> SolActionInstance {
        SolActionInstance {
            consumed: self.consumed.iter().map(ConsumedInstance::to_sol).collect(),
            created: self.created.iter().map(CreatedInstance::to_sol).collect(),
            deltaX: self.delta_x.into(),
            deltaY: self.delta_y.into(),
        }
    }
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
    pub fn to_sol(&self) -> SolLogicInstance {
        SolLogicInstance {
            tag: self.tag.into(),
            actionRoot: self.action_root.into(),
            isConsumed: self.is_consumed,
            appData: self.app_data.to_sol(),
        }
    }

    pub fn verify(&self, logic_ref: [u8; 32], proof_commit: [u8; 32]) -> () {
        // we assume each proof output is a keccak of the abi encoding of the specified instance
        let guest_output = keccak256(&self.to_sol().abi_encode());
        // TODO! Double check that each byte is cast into a word
        let revealed_bytes: Vec<u8> = guest_output.iter().flat_map(|&b| [b, 0, 0, 0]).collect();
        let expected_output = ProofOutput {
            app_exe_commit: logic_ref,
            app_vm_commit: LOGIC_VM_COMMIT,
            user_public_values: revealed_bytes,
        };
        // WARNING: this panics pm failure
        verify_stark::<DEF_IDX>(&proof_commit, &expected_output);
    }
}
