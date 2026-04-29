use arm_core::instance::ResourceLogicInstance;
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

fn main() -> eyre::Result<()> {
    let vm_config = SdkVmConfig::from_toml(include_str!("../../trivial_logic/openvm.toml"))?;
    let exe: VmExe<F> = read_object_from_file(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/trivial_logic/openvm/release/trivial-logic-guest.vmexe"
    ))?;

    let mut stdin = StdIn::default();
    stdin.write(&ResourceLogicInstance::default());

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
