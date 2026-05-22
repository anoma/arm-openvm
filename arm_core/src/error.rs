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
    #[error("Compliance STARK proof verification failed")]
    ComplianceProofVerificationFailed,
    #[error("Compliance proof reveals an action instance digest that doesn't match the claimed instance")]
    ActionInstanceMismatch,
    #[error("Compliance proof's app_vm_commit doesn't match expected COMPLIANCE_VM_COMMIT")]
    InvalidComplianceVmCommit,
    #[error("Nullifier appears in more than one action in the transaction")]
    NullifierDuplication,
    #[error("Commitment appears in more than one action in the transaction")]
    CommitmentDuplication,
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
