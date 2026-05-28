//! ARM-OpenVM error types.
#![allow(missing_docs)]
use thiserror::Error;

use arm_traits::resource::NullifierError;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArmError {
    #[error("Empty nullifier array for compliance proof")]
    ComplianceProofEmptyNullifierArray,
    #[error("Nonce mismatch for a created resource in compliance proof")]
    ComplianceProofCreatedResourceNonceMismatch,
    #[error("Invalid delta point (x, y do not lie on the curve)")]
    InvalidDelta,
    #[error("STARK proof verification failed")]
    ProofVerificationFailed,
    #[error("Instance mismatch for proof verification")]
    InstanceMismatch,
    #[error("Invalid proof supplied")]
    InvalidProof,
    #[error("Nullifier appears in more than one action in the transaction")]
    NullifierDuplication,
    #[error("Commitment appears in more than one action in the transaction")]
    CommitmentDuplication,
    #[error("Action root does not match the action's tags")]
    ActionRootMismatch,
    #[error("Delta proof verification failed")]
    DeltaProofVerificationFailed,
    #[error("RM Error")]
    GeneralError,
}

impl From<NullifierError> for ArmError {
    fn from(_: NullifierError) -> Self {
        ArmError::GeneralError
    }
}

#[cfg(feature = "host")]
impl From<crate::delta::DeltaError> for ArmError {
    fn from(_: crate::delta::DeltaError) -> Self {
        ArmError::DeltaProofVerificationFailed
    }
}
