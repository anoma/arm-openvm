//! Compliance proof bench

use arm_core::instance::{AppData, ResourceLogicInstance};
use arm_core::nullifier_key::NullifierKey;
use arm_core::resource::Resource;
use arm_core::tree::Proof;
use arm_core::witness::{ComplianceWitness, ConsumedWitness, CreatedWitness};
use arm_traits::resource::Resource as ResourceTrait;
use arm_vm_commit::{f_slice_to_bytes, logic_sdk_vm_config};

use openvm_circuit::arch::instructions::{DEFERRAL_AS, exe::VmExe};
use openvm_deferral_circuit::DeferralFn;
use openvm_sdk::{
    DeferralInput, F, Sdk, StdIn,
    config::{AggregationConfig, AggregationSystemParams, AppConfig},
    fs::read_object_from_file,
    prover::DeferralProver,
};
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security, internal_params_with_100_bits_security,
    leaf_params_with_100_bits_security, root_params_with_100_bits_security,
};
use openvm_verify_stark_circuit::extension::{
    get_deferral_state, get_raw_deferral_results, verify_stark_deferral_fn,
};
use openvm_verify_stark_host::vk::VmStarkVerifyingKey;

#[cfg(not(feature = "cuda"))]
use openvm_verify_stark_circuit::prover::{
    DeferredVerifyCpuCircuitProver as VerifyCircuitProver, DeferredVerifyCpuProver as VerifyProver,
};
#[cfg(not(feature = "cuda"))]
type E = openvm_stark_sdk::config::baby_bear_poseidon2::BabyBearPoseidon2CpuEngine;

#[cfg(feature = "cuda")]
use openvm_verify_stark_circuit::prover::{
    DeferredVerifyGpuCircuitProver as VerifyCircuitProver, DeferredVerifyGpuProver as VerifyProver,
};
#[cfg(feature = "cuda")]
type E = openvm_cuda_backend::BabyBearPoseidon2GpuEngine;

use std::sync::Arc;
use std::time::Instant;

const TRIVIAL_LOGIC_VMEXE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/trivial_logic/openvm/release/trivial-logic-guest.vmexe"
);
const COMPLIANCE_VMEXE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/compliance/openvm/release/compliance-guest.vmexe"
);

fn main() -> eyre::Result<()> {
    // ---- 1. Build sdk_logic, load exe, compute logic_exe_commit ----
    // NOTE: SHOULD MATCH THE ARM_COMMIT TRACE DEPTH
    let app_params = app_params_with_100_bits_security(21);
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };
    let logic_app_config = AppConfig::new(logic_sdk_vm_config()?, app_params.clone());
    let logic_sdk = Sdk::new(logic_app_config, agg_params.clone())?;

    let logic_exe: VmExe<F> = read_object_from_file(TRIVIAL_LOGIC_VMEXE)?;
    let logic_exe_commit: [u8; 32] =
        f_slice_to_bytes(&logic_sdk.app_prover(logic_exe.clone())?.app_exe_commit())
            .try_into()
            .expect("32-byte commit");

    // ---- 2. Fixture: 1 consumed + 1 created resource ----
    let nullifier_key = NullifierKey { bytes: [6u8; 32] };
    let nk_commitment = arm_core::hash::keccak256(&nullifier_key.bytes);
    let action_root = [13u8; 32];
    let app_data = AppData::default();

    let consumed_resource = Resource {
        logic_ref: logic_exe_commit,
        label_ref: [2u8; 32],
        value_ref: [3u8; 32],
        quantity: 42u128,
        nonce: [4u8; 32],
        nk_commitment,
        is_ephemeral: true,
    };

    let nullifier_0 = consumed_resource.compute_nullifier(&nullifier_key);
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&nullifier_0);
    buf.extend_from_slice(&[0u8; 32]);
    let created_nonce = arm_core::hash::keccak256(&buf);

    let created_resource = Resource {
        logic_ref: logic_exe_commit,
        label_ref: [20u8; 32],
        value_ref: [30u8; 32],
        quantity: 42u128,
        nonce: created_nonce,
        nk_commitment: [0u8; 32],
        is_ephemeral: false,
    };

    // ---- 3. Prove logic for each resource ----
    let consumed_tag = consumed_resource.nullify(&nullifier_key).unwrap();
    let created_tag = created_resource.commit();

    let logic_witness_consumed = ResourceLogicInstance {
        tag: consumed_tag,
        action_root,
        is_consumed: true,
        app_data: app_data.clone(),
    };
    let logic_witness_created = ResourceLogicInstance {
        tag: created_tag,
        action_root,
        is_consumed: false,
        app_data: app_data.clone(),
    };

    let t = Instant::now();
    let mut stdin = StdIn::default();
    stdin.write(&logic_witness_consumed);
    let (logic_proof_consumed, baseline) = logic_sdk.prove(logic_exe.clone(), stdin, &[])?;
    eprintln!("logic proof (consumed): {:?}", t.elapsed());

    let t = Instant::now();
    let mut stdin = StdIn::default();
    stdin.write(&logic_witness_created);
    let (logic_proof_created, _) = logic_sdk.prove(logic_exe, stdin, &[])?;
    eprintln!("logic proof (created):  {:?}", t.elapsed());

    // ---- 4. Build deferral plumbing on top of sdk_logic's IR ----
    let agg = logic_sdk.agg_prover();
    let ir_vk = agg.internal_recursive_prover.get_vk();
    let ir_pcs = agg
        .internal_recursive_prover
        .get_self_vk_pcs_data()
        .unwrap();
    let logic_sys = logic_sdk.app_config().app_vm_config.as_ref().clone();
    let memory_dimensions = logic_sys.memory_config.memory_dimensions();
    let num_user_pvs = logic_sys.num_public_values;

    let verify_prover = VerifyProver::new::<E>(
        ir_vk,
        ir_pcs.commitment.into(),
        internal_params_with_100_bits_security(),
        memory_dimensions,
        num_user_pvs,
        None,
        0,
    );
    let verify_circuit_prover = VerifyCircuitProver::new(verify_prover);

    let hook_params = root_params_with_100_bits_security();
    let agg_config = AggregationConfig {
        params: agg_params.clone(),
    };
    let deferral_prover = DeferralProver::new(verify_circuit_prover, agg_config, hook_params);
    let deferral_ext =
        deferral_prover.make_extension(vec![Arc::new(DeferralFn::new(verify_stark_deferral_fn))]);

    // ---- 5. Build sdk_compliance: LOGIC config + deferral_ext ----
    let mut compliance_vm_config = logic_sdk_vm_config()?;
    compliance_vm_config.deferral = Some(deferral_ext);
    compliance_vm_config.system.config.memory_config.addr_spaces[DEFERRAL_AS as usize].num_cells =
        1 << 25;

    let compliance_app_config = AppConfig::new(compliance_vm_config, app_params);
    let compliance_sdk = Sdk::builder()
        .app_config(compliance_app_config)
        .agg_params(agg_params)
        .deferral_prover(deferral_prover)
        .build()?;

    // ---- 6. Derive input_commit per logic proof (host-side) ----
    let logic_vk = VmStarkVerifyingKey {
        mvk: logic_sdk.agg_vk().as_ref().clone(),
        baseline,
    };
    let raw = get_raw_deferral_results(
        &logic_vk,
        &[logic_proof_consumed.clone(), logic_proof_created.clone()],
    )?;
    let input_commit_consumed: [u8; 32] = raw[0].input.clone().try_into().unwrap();
    let input_commit_created: [u8; 32] = raw[1].input.clone().try_into().unwrap();
    let deferral_state = get_deferral_state(
        &logic_vk,
        &[logic_proof_consumed.clone(), logic_proof_created.clone()],
        arm_core::proving::DEF_IDX as u32,
    )?;

    // ---- 7. Build ComplianceWitness with real input_commits ----
    let consumed = ConsumedWitness {
        resource: consumed_resource,
        nullifier_key,
        path: Proof { path: vec![] },
        delta_extra_input: [7u8; 32],
        logic_hiding_input: [9u8; 32],
        app_data: app_data.clone(),
        logic_proof: input_commit_consumed,
    };
    let created = CreatedWitness {
        resource: created_resource,
        delta_extra_input: [8u8; 32],
        logic_hiding_input: [10u8; 32],
        app_data,
        logic_proof: input_commit_created,
    };
    let witness = ComplianceWitness {
        consumed: vec![consumed],
        created: vec![created],
        action_root,
    };

    // ---- 8. Prove compliance with DeferralInput carrying logic proofs ----
    let compliance_exe: VmExe<F> = read_object_from_file(COMPLIANCE_VMEXE)?;
    let mut compliance_stdin = StdIn::default();
    compliance_stdin.write(&witness);
    compliance_stdin.deferrals = vec![deferral_state];
    let def_input = DeferralInput::from_inputs(&[logic_proof_consumed, logic_proof_created]);

    let t = Instant::now();
    #[cfg(not(feature = "evm"))]
    {
        let (_compliance_proof, _baseline) =
            compliance_sdk.prove(compliance_exe, compliance_stdin, &[def_input])?;
    }

    #[cfg(feature = "evm")]
    {
        compliance_sdk.prove_evm(compliance_exe, compliance_stdin, &[def_input])?;
    }
    eprintln!("compliance proof:        {:?}", t.elapsed());

    eprintln!("end-to-end OK");
    Ok(())
}
