//! # hash
//!
//! Implementation of a hash interface for OpenVM RM

/// A general keccak function implementation on slices
/// feature-gated to be used in guest programs
/// In the future, this should be abstacted away for different hashes
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    return openvm_keccak256::keccak256(input);
}

pub fn hash_two_heap(left: &[u8], right: &[u8]) -> [u8; 32] {
    keccak256(&[left, right].concat())
}

pub fn hash_two_stack(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(left);
    bytes[32..].copy_from_slice(right);
    keccak256(&bytes)
}
