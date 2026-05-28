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
use alloc::collections::BTreeSet;
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
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConsumedInstance {
    pub nullifier: [u8; 32],
    pub root: [u8; 32],
    pub outer_logic_ref: [u8; 32],
    // these fields are added for wrapping
    pub app_data: AppData,
}

/// Instance returned by the compliance program for each created resource
#[derive(serde::Serialize, serde::Deserialize)]
pub struct CreatedInstance {
    pub commitment: [u8; 32],
    pub outer_logic_ref: [u8; 32],
    // these fields are added for wrapping
    pub app_data: AppData,
}

/// A type implementing both compliance instance and action interfaces
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ActionInstance {
    pub consumed: Vec<ConsumedInstance>,
    pub created: Vec<CreatedInstance>,
    pub delta_x: [u8; 32],
    pub delta_y: [u8; 32],
    pub action_root: [u8; 32],
}

/// A type implementing both compliance unit and action interfaces
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ActionVerifierInput {
    pub action_instance: ActionInstance,
    pub compliance_proof: Proof,
}

/// An RM transaction datatype
/// Assumes one compliance unit per action
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub units: Vec<ActionVerifierInput>,
    #[serde(with = "serde_big_array::BigArray")]
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
        bytes32 actionRoot;
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
            actionRoot: self.action_root.into(),
        }
    }

    pub fn delta_msg(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(32 * (self.consumed.len() + self.created.len()));
        for c in &self.consumed {
            msg.extend_from_slice(&c.nullifier);
        }
        for c in &self.created {
            msg.extend_from_slice(&c.commitment);
        }
        msg
    }

    /// The action's tags in canonical order: consumed nullifiers, then created
    /// commitments. The action tree is built over exactly this sequence.
    pub fn tags(&self) -> Vec<[u8; 32]> {
        self.consumed
            .iter()
            .map(|c| c.nullifier)
            .chain(self.created.iter().map(|c| c.commitment))
            .collect()
    }
}

#[cfg(feature = "host")]
pub static COMPLIANCE_VK: std::sync::LazyLock<openvm_verify_stark_host::vk::VmStarkVerifyingKey> =
    std::sync::LazyLock::new(|| {
        bincode::serde::decode_from_slice(
            include_bytes!("../compliance.vk"),
            bincode::config::standard(),
        )
        .expect("embedded compliance.vk must deserialize")
        .0
    });

#[cfg(feature = "host")]
impl ActionVerifierInput {
    pub fn verify(&self) -> Result<(), crate::error::ArmError> {
        use crate::error::ArmError;
        use crate::proving::verify_stark;
        use crate::tree::SparseTree;
        use alloy_sol_types::SolValue;
        use openvm_stark_backend::codec::Decode;
        use openvm_verify_stark_host::VmStarkProof;

        // bind the committed action root to the action's actual tags
        let tags = self.action_instance.tags();
        let computed_root = SparseTree::compute_tree(&tags)
            .ok()
            .and_then(|tree| tree.root().copied())
            .ok_or(ArmError::ActionRootMismatch)?;
        if computed_root != self.action_instance.action_root {
            return Err(ArmError::ActionRootMismatch);
        }

        let proof = VmStarkProof::decode_from_bytes(&self.compliance_proof)
            .map_err(|_| ArmError::InvalidProof)?;
        let instance = crate::hash::keccak256(&self.action_instance.to_sol().abi_encode());

        verify_stark(&COMPLIANCE_VK, &instance, &proof)
    }
}

#[cfg(feature = "host")]
impl ActionInstance {
    pub fn delta_point(&self) -> Result<k256::ProjectivePoint, crate::error::ArmError> {
        use k256::elliptic_curve::sec1::FromEncodedPoint;
        let encoded_point = k256::EncodedPoint::from_affine_coordinates(
            (&self.delta_x).into(),
            (&self.delta_y).into(),
            false,
        );
        k256::ProjectivePoint::from_encoded_point(&encoded_point)
            .into_option()
            .ok_or(crate::error::ArmError::InvalidDelta)
    }
}

impl Transaction {
    /// Function fetching all nullifiers in a transaction
    /// as ordered by the actions
    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.units
            .iter()
            .flat_map(|u| u.action_instance.consumed.iter().map(|c| c.nullifier))
            .collect()
    }

    /// Function fetching all commitments in a transaction
    /// as ordered by the actions
    pub fn commitments(&self) -> Vec<[u8; 32]> {
        self.units
            .iter()
            .flat_map(|u| u.action_instance.created.iter().map(|c| c.commitment))
            .collect()
    }

    /// Function fetching the set of roots in a transaction
    pub fn roots(&self) -> BTreeSet<[u8; 32]> {
        self.units
            .iter()
            .flat_map(|u| u.action_instance.consumed.iter().map(|c| c.root))
            .collect()
    }
}

#[cfg(feature = "host")]
impl Transaction {
    pub fn verify(&self) -> Result<(), crate::error::ArmError> {
        use crate::delta::{DeltaInstance, DeltaProof};
        use crate::error::ArmError;

        for unit in &self.units {
            unit.verify()?;
        }

        let mut seen_nullifiers = BTreeSet::new();
        let mut seen_commitments = BTreeSet::new();
        for unit in &self.units {
            for c in &unit.action_instance.consumed {
                if !seen_nullifiers.insert(c.nullifier) {
                    return Err(ArmError::NullifierDuplication);
                }
            }
            for c in &unit.action_instance.created {
                if !seen_commitments.insert(c.commitment) {
                    return Err(ArmError::CommitmentDuplication);
                }
            }
        }

        let deltas: Vec<k256::ProjectivePoint> = self
            .units
            .iter()
            .map(|u| u.action_instance.delta_point())
            .collect::<Result<Vec<_>, _>>()?;
        let instance = DeltaInstance::from_deltas(&deltas)?;
        let msg: Vec<u8> = self
            .units
            .iter()
            .flat_map(|u| u.action_instance.delta_msg())
            .collect();
        let proof = DeltaProof::from_bytes(&self.delta_proof)?;
        DeltaProof::verify(&msg, &proof, instance)?;

        Ok(())
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
