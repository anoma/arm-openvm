//! proving
//!
//! Module with proving-system relevant functionality

/// The deferral index
/// Zero corresponds to having only one vm commit
/// (i.e. everyone uses the same extensions for now)
pub const DEF_IDX: u16 = 0;

/// Commit bytes of the standardized extension set used by resource logics
pub const LOGIC_VM_COMMIT: [u8; 32] = [
    0x53, 0xa3, 0x57, 0x54, 0xb2, 0xf5, 0x51, 0x36, 0xfd, 0xa5, 0x07, 0x16, 0xce, 0xcd, 0x57, 0x6e,
    0xd6, 0x74, 0xb5, 0x18, 0xf9, 0xe2, 0x4a, 0x68, 0x8e, 0x4a, 0x43, 0x61, 0x61, 0x6d, 0x42, 0x37,
];

/// Commit bytes of the extention set used by the compliance guest program
pub const COMPLIANCE_VM_COMMIT: [u8; 32] = [
    0x01, 0xc2, 0x1e, 0x44, 0xc0, 0x08, 0x81, 0x41, 0x5b, 0x56, 0x26, 0x15, 0x9a, 0x31, 0xc0, 0x2d,
    0x05, 0xea, 0xef, 0x61, 0x0e, 0xd3, 0xe2, 0x1b, 0x8d, 0x24, 0x45, 0x11, 0x86, 0x7d, 0x8c, 0x64,
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
