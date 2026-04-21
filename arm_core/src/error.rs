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
    #[error("RM Error")]
    GeneralError,
}

impl From<NullifierError> for ArmError {
    fn from(_: NullifierError) -> Self {
        ArmError::GeneralError
    }
}
