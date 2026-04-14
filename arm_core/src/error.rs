//! ARM-OpenVM error types.
#![allow(missing_docs)]
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ArmError {
    #[error("Empty nullifier array for compliance proof")]
    ComplianceProofEmptyNullifierArray,
    #[error("Nonce mismatch for a created resource in compliance proof")]
    ComplianceProofCreatedResourceNonceMismatch,
}
