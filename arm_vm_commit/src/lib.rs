//! Host-side computation of the protocol-wide LOGIC `app_vm_commit`.
//!
//! This is the value compliance guest checks against `proof_output.app_vm_commit`
//! when verifying inner logic STARK proofs via the deferral mechanism.

use core::mem::size_of_val;
use eyre::Result;
use openvm_recursion_circuit::utils::poseidon2_hash_slice;
use openvm_sdk::{
    Sdk,
    config::{AggregationSystemParams, AppConfig},
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security, baby_bear_poseidon2::F,
    internal_params_with_100_bits_security, leaf_params_with_100_bits_security,
};
use p3_field::PrimeField32;

// Copied from openvm `verify-stark/circuit/src/extension.rs` (private upstream)
// this is specifically for deferral in-guest verification
// on-chain has its own standard CommitBytes::from
pub fn f_slice_to_bytes(slice: &[F]) -> Vec<u8> {
    let mut output = Vec::with_capacity(size_of_val(slice));
    for value in slice {
        let bytes = value.as_canonical_u32().to_le_bytes();
        output.extend_from_slice(&bytes);
    }
    output
}

pub fn logic_sdk_vm_config() -> Result<SdkVmConfig> {
    Ok(SdkVmConfig::from_toml(include_str!("../logic.toml"))?)
}

pub fn compute_logic_vm_commit() -> Result<[u8; 32]> {
    let app_config = AppConfig::new(
        logic_sdk_vm_config()?,
        // assuming 2^21 trace size
        // TODO: Check what would be most proper
        app_params_with_100_bits_security(21),
    );
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };
    let sdk = Sdk::new(app_config, agg_params)?;
    let agg = sdk.agg_prover();

    // false stands for is_self_recursive value
    let app_vk = agg.leaf_prover.get_vk_commit(false);
    let leaf_vk = agg.internal_for_leaf_prover.get_vk_commit(false);
    let i4l_vk = agg.internal_recursive_prover.get_vk_commit(false);

    let components: Vec<F> = [
        app_vk.cached_commit,
        app_vk.vk_pre_hash,
        leaf_vk.cached_commit,
        leaf_vk.vk_pre_hash,
        i4l_vk.cached_commit,
        i4l_vk.vk_pre_hash,
    ]
    .concat();

    let digest = poseidon2_hash_slice(&components).0;
    Ok(f_slice_to_bytes(&digest)
        .try_into()
        .expect("f_slice_to_bytes of [F; 8] always yields 32 bytes"))
}
