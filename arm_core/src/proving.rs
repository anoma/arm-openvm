//! proving
//!
//! Module with proving-system relevant functionality

/// The deferral index
/// Zero corresponds to having only one vm commit
/// (i.e. everyone uses the same extensions for now)
pub const DEF_IDX: u16 = 0;

/// Commit bytes of the standardized extension set used by resource logics
pub const LOGIC_VM_COMMIT: [u8; 32] = [
    0xb2, 0x3a, 0x5b, 0x0d, 0xec, 0x92, 0x57, 0x59, 0x3d, 0x35, 0xa1, 0x45, 0x50, 0xdf, 0x63, 0x1d,
    0xf1, 0x54, 0x8d, 0x5b, 0x96, 0xcc, 0x03, 0x06, 0x19, 0x30, 0x40, 0x24, 0xec, 0x7f, 0x10, 0x45,
];

/// Commit bytes of the extention set used by the compliance guest program
pub const COMPLIANCE_VM_COMMIT: [u8; 32] = [
    0x1d, 0x7c, 0x2a, 0x6e, 0x25, 0xa6, 0xc4, 0x53, 0xbc, 0x49, 0xc0, 0x09, 0x08, 0xc7, 0xfe, 0x4d,
    0x5c, 0x0b, 0xe1, 0x66, 0x8a, 0xdc, 0xbb, 0x00, 0x87, 0x52, 0xb3, 0x1f, 0xf4, 0xc8, 0xed, 0x2d,
];

/// Verify a decoded VM STARK proof against `vk` and assert it reveals `instance`
/// (the 32-byte keccak digest of the action instance). Borrows the vk — callers
/// pass `&COMPLIANCE_VK` (the embedded compliance key) or a deserialized one.
#[cfg(feature = "host")]
pub fn verify_stark(
    vk: &openvm_verify_stark_host::vk::VmStarkVerifyingKey,
    instance: &[u8],
    proof: &openvm_verify_stark_host::VmStarkProof,
) -> Result<(), crate::error::ArmError> {
    use crate::error::ArmError;
    use alloc::vec::Vec;
    use openvm_verify_stark_host::verify_vm_stark_proof_decoded;
    use p3_field::PrimeField32;

    verify_vm_stark_proof_decoded(vk, proof).map_err(|_| ArmError::ProofVerificationFailed)?;
    let revealed: Vec<u8> = proof
        .user_pvs_proof
        .public_values
        .iter()
        .map(|f| f.as_canonical_u32() as u8)
        .collect();
    if revealed.as_slice() != instance {
        return Err(ArmError::InstanceMismatch);
    }
    Ok(())
}
