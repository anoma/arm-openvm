//! voting
//!
//! A PROTOTYPE implementation of the voting guest program
//! Hardcoded consts have to be treated per-application currently
//! and placed as mocks currently

use crate::{
    error::ArmError,
    hash::keccak256,
    instance::{AppData, Payload, ResourceLogicInstance},
    nullifier_key::NullifierKey,
    resource::Resource,
    tree::Proof,
};
use alloc::vec::Vec;
use arm_traits::resource::Resource as ResourceTrait;
use openvm_algebra_guest::Reduce;
use openvm_ecc_guest::{CyclicGroup, weierstrass::WeierstrassPoint};
use openvm_k256::{Secp256k1Point as CurvePoint, Secp256k1Scalar as Scalar};

// All the consts can also be stored in the resource labelRef

/// the hardcoded forwarder contract
pub const FORWARDER: [u8; 20] = [0u8; 20];
/// the label of the election cast as a labelRef
pub const ELECTION_LABEL: [u8; 32] = [0u8; 32];
/// a public key of the decoder able to decode the votes
pub const DECODER_PK: CurvePoint = CurvePoint::GENERATOR;
/// a merkle root of a tree whose leaves are (pk, weight)
/// assumed each pk is unique per tree
pub const MERKLE_ROOT: [u8; 32] = [0u8; 32];

#[derive(Debug)]
pub struct VoteWitness {
    pub resource: Resource,
    pub is_consumed: bool,
    pub action_tree_root: [u8; 32],
    // Currently a stand-in for both the nullifier key and
    // the voter secret key
    pub sk: Option<[u8; 32]>,
    // path for the voter merkle tree
    pub path: Option<Proof>,
    // randomness for vote casting
    pub randomness: Option<[u8; 32]>,
    // whether a person voted "yes"
    pub vote: Option<bool>,
}

impl VoteWitness {
    pub fn constrain(&self) -> Result<ResourceLogicInstance, ArmError> {
        let (tag, app_data): ([u8; 32], AppData) =
            match (self.resource.is_ephemeral, self.is_consumed) {
                (true, true) => {
                    let sk = self.sk.ok_or(ArmError::GeneralError)?;
                    let path: &Proof = self.path.as_ref().ok_or(ArmError::GeneralError)?;
                    // make sure the prover owns an existing vote
                    let _ = prove_voting_power(sk, path, self.resource.quantity)?;
                    // make sure that if an sk claims, they can only do so via
                    // a unique resource preventing double-mints
                    let _ = bind_nullifier(&self.resource, sk);
                    let nf_key = NullifierKey { bytes: sk };
                    (self.resource.nullify(&nf_key)?, AppData::default())
                }
                (true, false) => {
                    let vote = self.vote.ok_or(ArmError::GeneralError)?;
                    let randomness = self.randomness.ok_or(ArmError::GeneralError)?;
                    (
                        self.resource.commit(),
                        // put the curve points representing votes to the external payloads
                        compute_app_data(vote, self.resource.quantity, randomness),
                    )
                }
                (false, true) => {
                    // currently uses nk as the only authorization
                    let sk = self.sk.ok_or(ArmError::GeneralError)?;
                    let nf_key = NullifierKey { bytes: sk };
                    (self.resource.nullify(&nf_key)?, AppData::default())
                }
                (false, false) => (self.resource.commit(), AppData::default()),
            };

        Ok(ResourceLogicInstance {
            tag,
            action_root: self.action_tree_root,
            is_consumed: self.is_consumed,
            app_data,
        })
    }
}

fn prove_voting_power(sk: [u8; 32], path: &Proof, quantity: u128) -> Result<(), ArmError> {
    let pk = CurvePoint::GENERATOR * Scalar::reduce_le_bytes(&sk);
    // leaves are (pk || quantity)
    let mut leaf_plaintext = [0u8; 32 + 32 + 16];
    leaf_plaintext[..32].copy_from_slice(&pk.x_be_bytes());
    leaf_plaintext[32..64].copy_from_slice(&pk.y_be_bytes());
    leaf_plaintext[64..].copy_from_slice(&quantity.to_be_bytes());
    // leaves are assumed to be keccak
    if path.verify(keccak256(&leaf_plaintext), MERKLE_ROOT) {
        Ok(())
    } else {
        Err(ArmError::GeneralError)
    }
}

fn bind_nullifier(resource: &Resource, sk: [u8; 32]) -> Result<(), ArmError> {
    // make sure all fields of the resource are bound to deterministic constants
    // many ways of doing this
    if resource.label_ref == ELECTION_LABEL
        && resource.value_ref == [0u8; 32]
        && resource.nonce == [0u8; 32]
        && resource.nk_commitment == keccak256(&sk)
    {
        Ok(())
    } else {
        Err(ArmError::GeneralError)
    }
}

fn compute_app_data(voted_yes: bool, weight: u128, randomness: [u8; 32]) -> AppData {
    // generate randomness and hidden voting points
    let (point1, point2) = compute_vote_commitment(voted_yes, weight, randomness);

    // mock of external payload encoding
    let mut forwarder_bytes = [0u8; 32 + 32 + 32 + 32 + 20];
    forwarder_bytes[..32].copy_from_slice(&point1.x_be_bytes());
    forwarder_bytes[32..64].copy_from_slice(&point1.y_be_bytes());
    forwarder_bytes[64..96].copy_from_slice(&point2.x_be_bytes());
    forwarder_bytes[96..128].copy_from_slice(&point2.y_be_bytes());
    forwarder_bytes[128..].copy_from_slice(&FORWARDER);

    AppData {
        external_payload: Vec::from([Payload {
            data: forwarder_bytes.to_vec(),
            deletion_criterion: true,
        }]),
        ..Default::default()
    }
}

fn compute_vote_commitment(
    voted_yes: bool,
    weight: u128,
    randomness: [u8; 32],
) -> (CurvePoint, CurvePoint) {
    let randomness_scalar = Scalar::reduce_le_bytes(&randomness);
    let randomness_commitment = CurvePoint::GENERATOR * randomness_scalar;
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&weight.to_le_bytes());

    // the voting weight only gets shifted by "yes" votes in this impl
    let vote = if voted_yes {
        CurvePoint::GENERATOR * Scalar::reduce_le_bytes(&bytes)
    } else {
        CurvePoint::IDENTITY
    };
    (randomness_commitment, vote + DECODER_PK * randomness_scalar)
}
