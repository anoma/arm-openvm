use arm_core::compliance::{ComplianceWitness, ConsumedWitness, CreatedWitness};
use arm_core::nullifier_key::NullifierKey;
use arm_core::resource::Resource;
use arm_core::tree::Proof;
use arm_traits::resource::Resource as ResourceTrait;
use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::{
    F, Sdk, StdIn,
    config::{AggregationSystemParams, AppConfig},
    fs::read_object_from_file,
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_sdk::config::{
    app_params_with_100_bits_security, internal_params_with_100_bits_security,
    leaf_params_with_100_bits_security,
};
use std::time::Instant;

fn make_witness() -> ComplianceWitness {
    let nullifier_key = NullifierKey { bytes: [6u8; 32] };
    let nk_commitment = arm_core::hash::keccak256(&nullifier_key.bytes);

    let consumed_resource = Resource {
        logic_ref: [1u8; 32],
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
    buf.extend_from_slice(&[0u8; 32]); // 0 represented as 32 bytes
    let created_nonce = arm_core::hash::keccak256(&buf);

    let created_resource = Resource {
        logic_ref: [10u8; 32],
        label_ref: [20u8; 32],
        value_ref: [30u8; 32],
        quantity: 42u128,
        nonce: created_nonce,
        nk_commitment: [0u8; 32], // not checked for created
        is_ephemeral: false,
    };

    let consumed = ConsumedWitness {
        resource: consumed_resource,
        nullifier_key,
        path: Proof { path: vec![] },
        delta_extra_input: [7u8; 32],
    };

    let created = CreatedWitness {
        resource: created_resource,
        delta_extra_input: [8u8; 32],
    };

    ComplianceWitness {
        consumed: vec![consumed],
        created: vec![created],
    }
}

fn main() -> eyre::Result<()> {
    let vm_config = SdkVmConfig::from_toml(include_str!("../../compliance/openvm.toml"))?;
    let exe: VmExe<F> = read_object_from_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/compliance/openvm/release/compliance-guest.vmexe"
    ))?;

    let mut stdin = StdIn::default();
    stdin.write(&make_witness());

    let app_config = AppConfig::new(vm_config, app_params_with_100_bits_security(21));
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };

    let t0 = Instant::now();
    let sdk = Sdk::new(app_config, agg_params)?;
    let (_proof, _baseline) = sdk.prove(exe, stdin, &[])?;
    eprintln!("stark-prove wall-clock: {:?}", t0.elapsed());

    Ok(())
}
