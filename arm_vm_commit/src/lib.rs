//! Host-side computation of the protocol-wide LOGIC `app_vm_commit`.
//!
//! This is the value compliance guest checks against `proof_output.app_vm_commit`
//! when verifying inner logic STARK proofs via the deferral mechanism.

use core::mem::size_of_val;
use std::sync::Arc;

use eyre::Result;
use openvm_circuit::arch::instructions::DEFERRAL_AS;
use openvm_deferral_circuit::DeferralFn;
use openvm_recursion_circuit::utils::poseidon2_hash_slice;
use openvm_sdk::{
    Sdk,
    config::{AggregationConfig, AggregationSystemParams, AppConfig},
    prover::DeferralProver,
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security,
    baby_bear_poseidon2::{BabyBearPoseidon2CpuEngine, F},
    internal_params_with_100_bits_security, leaf_params_with_100_bits_security,
    root_params_with_100_bits_security,
};
use openvm_verify_stark_circuit::{
    extension::verify_stark_deferral_fn,
    prover::{DeferredVerifyCpuCircuitProver, DeferredVerifyCpuProver},
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

pub fn compliance_sdk_vm_config() -> Result<SdkVmConfig> {
    Ok(SdkVmConfig::from_toml(include_str!("../compliance.toml"))?)
}

/// `app_vm_commit` for a plain logic VM (no deferral): hash the app/leaf/internal
/// vk commits. Shared by every logic-side config.
fn vm_commit_from_config(vm_config: SdkVmConfig) -> Result<[u8; 32]> {
    // assuming 2^21 trace size
    // TODO: Check what would be most proper
    let app_config = AppConfig::new(vm_config, app_params_with_100_bits_security(21));
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

pub fn compute_logic_vm_commit() -> Result<[u8; 32]> {
    vm_commit_from_config(logic_sdk_vm_config()?)
}

pub fn construct_compliance_vk(
    vmexe_bytes: &[u8],
) -> Result<openvm_verify_stark_host::vk::VmStarkVerifyingKey> {
    let app_params = app_params_with_100_bits_security(21);
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };

    let logic_app_config = AppConfig::new(logic_sdk_vm_config()?, app_params.clone());
    let logic_sdk = Sdk::new(logic_app_config, agg_params.clone())?;

    let agg = logic_sdk.agg_prover();
    let ir_vk = agg.internal_recursive_prover.get_vk();
    let ir_pcs = agg
        .internal_recursive_prover
        .get_self_vk_pcs_data()
        .unwrap();
    let logic_sys = logic_sdk.app_config().app_vm_config.as_ref().clone();
    let verify_prover = DeferredVerifyCpuProver::new::<BabyBearPoseidon2CpuEngine>(
        ir_vk,
        ir_pcs.commitment.into(),
        internal_params_with_100_bits_security(),
        logic_sys.memory_config.memory_dimensions(),
        logic_sys.num_public_values,
        None,
        0,
    );
    let verify_circuit_prover = DeferredVerifyCpuCircuitProver::new(verify_prover);
    let deferral_prover = DeferralProver::new(
        verify_circuit_prover,
        AggregationConfig {
            params: agg_params.clone(),
        },
        root_params_with_100_bits_security(),
    );
    let deferral_ext =
        deferral_prover.make_extension(vec![Arc::new(DeferralFn::new(verify_stark_deferral_fn))]);

    let mut compliance_vm_config = compliance_sdk_vm_config()?;
    compliance_vm_config.deferral = Some(deferral_ext);
    compliance_vm_config.system.config.memory_config.addr_spaces[DEFERRAL_AS as usize].num_cells =
        1 << 25;

    let compliance_app_config = AppConfig::new(compliance_vm_config, app_params);
    let compliance_sdk = Sdk::builder()
        .app_config(compliance_app_config)
        .agg_params(agg_params)
        .deferral_prover(deferral_prover)
        .build()?;

    // .vmexe is bitcode-serialized by `cargo openvm build`; deserialize to build the StarkProver
    // and get the (vmexe-dependent) baseline.
    let vmexe: openvm_circuit::arch::instructions::exe::VmExe<F> =
        bitcode::deserialize(vmexe_bytes)?;
    let prover = compliance_sdk.prover(vmexe)?;
    let baseline = prover.generate_baseline();
    let mvk = compliance_sdk.agg_vk().as_ref().clone();

    Ok(openvm_verify_stark_host::vk::VmStarkVerifyingKey { mvk, baseline })
}

pub fn compute_compliance_vm_commit() -> Result<[u8; 32]> {
    let app_params = app_params_with_100_bits_security(21);
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };

    // Build the logic SDK to extract the deferral verifier's ir_vk + PCS commitment.
    let logic_app_config = AppConfig::new(logic_sdk_vm_config()?, app_params.clone());
    let logic_sdk = Sdk::new(logic_app_config, agg_params.clone())?;

    let agg = logic_sdk.agg_prover();
    let ir_vk = agg.internal_recursive_prover.get_vk();
    let ir_pcs = agg
        .internal_recursive_prover
        .get_self_vk_pcs_data()
        .unwrap();
    let logic_sys = logic_sdk.app_config().app_vm_config.as_ref().clone();
    let verify_prover = DeferredVerifyCpuProver::new::<BabyBearPoseidon2CpuEngine>(
        ir_vk,
        ir_pcs.commitment.into(),
        internal_params_with_100_bits_security(),
        logic_sys.memory_config.memory_dimensions(),
        logic_sys.num_public_values,
        None,
        0,
    );
    let verify_circuit_prover = DeferredVerifyCpuCircuitProver::new(verify_prover);
    let deferral_prover = DeferralProver::new(
        verify_circuit_prover,
        AggregationConfig {
            params: agg_params.clone(),
        },
        root_params_with_100_bits_security(),
    );
    let deferral_ext =
        deferral_prover.make_extension(vec![Arc::new(DeferralFn::new(verify_stark_deferral_fn))]);

    // Splice deferral_ext into the compliance VM config (overrides toml placeholder).
    let mut compliance_vm_config = compliance_sdk_vm_config()?;
    compliance_vm_config.deferral = Some(deferral_ext);
    compliance_vm_config.system.config.memory_config.addr_spaces[DEFERRAL_AS as usize].num_cells =
        1 << 25;

    let compliance_app_config = AppConfig::new(compliance_vm_config, app_params);
    let compliance_sdk = Sdk::builder()
        .app_config(compliance_app_config)
        .agg_params(agg_params)
        .deferral_prover(deferral_prover)
        .build()?;

    let agg = compliance_sdk.agg_prover();
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
