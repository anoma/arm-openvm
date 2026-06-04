//! Single-VM transfer-auth compliance bench (`FLOW=wrap|unwrap|send`, default `wrap`).
//!
//! Proves a transfer_auth logic on the one rich VM (`logic.toml`) and verifies it
//! through the single deferral slot — the same VM + slot trivial logic uses, so
//! `logic_ref` is just the 32-byte app_commit. unwrap/send hit `persistent_consume`,
//! which needs a real secp256k1 signature, and aren't wired yet.

use arm_core::evm::CallType;
use arm_core::hash::keccak256;
use arm_core::nullifier_key::NullifierKey;
use arm_core::proving::DEF_IDX;
use arm_core::resource::Resource;
use arm_core::transfer_auth::{
    ForwarderInfo, LabelInfo, PermitInfo, TransferAuthWitness, calculate_label_ref,
    persistent_value_ref, value_ref_from_eth_addr,
};
use arm_core::tree::{Proof, SparseTree};
use arm_core::witness::{ComplianceWitness, ConsumedWitness, CreatedWitness};
use arm_traits::resource::Resource as ResourceTrait;
use arm_vm_commit::{f_slice_to_bytes, logic_sdk_vm_config};
use k256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use openvm_sdk_config::SdkVmConfig;

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

const TRANSFER_AUTH_VMEXE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/transfer_auth/openvm/release/transfer-auth-guest.vmexe"
);
const COMPLIANCE_VMEXE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/compliance/openvm/release/compliance-guest.vmexe"
);

/// Wrap: consume an ephemeral wrap resource (Permit2 forwarded, unverified in-circuit),
/// create the persistent wrapped-token resource (value_ref binds `keccak(pk‖payload)`,
/// no signature). `action_root` + the created `nonce` are placeholders filled by `main`.
fn wrap_witnesses(
    logic_ref: [u8; 32],
    nk_commitment: [u8; 32],
    nk: &NullifierKey,
) -> Vec<TransferAuthWitness> {
    let forwarder_addr = vec![0x11u8; 20];
    let erc20_token_addr = vec![0x22u8; 20];
    let eth_addr = vec![0x33u8; 20];
    let label_ref = calculate_label_ref(&forwarder_addr, &erc20_token_addr);

    let consumed = TransferAuthWitness {
        resource: Resource {
            logic_ref,
            label_ref,
            value_ref: [0u8; 32], // unchecked for wrap
            quantity: 42,
            nonce: [4u8; 32],
            nk_commitment,
            is_ephemeral: true,
        },
        is_consumed: true,
        action_root: [0u8; 32],
        nullifier_key: Some(nk.clone()),
        auth_pk: None,
        auth_sig: None,
        encryption_payload: None,
        discovery_payload: None,
        label_info: Some(LabelInfo {
            forwarder_addr: forwarder_addr.clone(),
            erc20_token_addr: erc20_token_addr.clone(),
        }),
        forwarder_info: Some(ForwarderInfo {
            call_type: CallType::Wrap,
            hiding_logic_bytes: [9u8; 32],
            ethereum_account_addr: eth_addr,
            permit: Some(PermitInfo {
                permit_nonce: vec![0u8; 32],
                permit_deadline: vec![0u8; 32],
                permit_sig: vec![1u8; 65],
            }),
        }),
    };

    let auth_pk = vec![2u8; 33];
    let payload = vec![7u8; 16];
    let created = TransferAuthWitness {
        resource: Resource {
            logic_ref,
            label_ref,
            value_ref: persistent_value_ref(&auth_pk, &payload),
            quantity: 42,
            nonce: [0u8; 32], // filled by main
            nk_commitment: [0u8; 32],
            is_ephemeral: false,
        },
        is_consumed: false,
        action_root: [0u8; 32],
        nullifier_key: None,
        auth_pk: Some(auth_pk),
        auth_sig: None,
        encryption_payload: Some(payload),
        discovery_payload: None,
        label_info: Some(LabelInfo { forwarder_addr, erc20_token_addr }),
        forwarder_info: None,
    };

    vec![consumed, created]
}

/// Unwrap: consume a persistent resource (`persistent_consume` — `auth_sig` over the
/// action_root is filled by `main`), create the ephemeral unwrap resource (value_ref =
/// the eth address; Unwrap forwarder calldata).
fn unwrap_witnesses(
    logic_ref: [u8; 32],
    nk_commitment: [u8; 32],
    nk: &NullifierKey,
    auth_pk: &[u8],
) -> Vec<TransferAuthWitness> {
    let forwarder_addr = vec![0x11u8; 20];
    let erc20_token_addr = vec![0x22u8; 20];
    let eth_addr = vec![0x33u8; 20];
    let payload = vec![7u8; 16];
    let pk_value_ref = persistent_value_ref(auth_pk, &payload);
    let label_ref = calculate_label_ref(&forwarder_addr, &erc20_token_addr);
    let eth_value_ref = value_ref_from_eth_addr(&eth_addr);

    let consumed = TransferAuthWitness {
        resource: Resource {
            logic_ref,
            label_ref: [0u8; 32], // persistent_consume doesn't check the label
            value_ref: pk_value_ref,
            quantity: 42,
            nonce: [4u8; 32],
            nk_commitment,
            is_ephemeral: false,
        },
        is_consumed: true,
        action_root: [0u8; 32],
        nullifier_key: Some(nk.clone()),
        auth_pk: Some(auth_pk.to_vec()),
        auth_sig: None, // filled by main
        encryption_payload: Some(payload),
        discovery_payload: None,
        label_info: None,
        forwarder_info: None,
    };

    let created = TransferAuthWitness {
        resource: Resource {
            logic_ref,
            label_ref,
            value_ref: eth_value_ref,
            quantity: 42,
            nonce: [0u8; 32],
            nk_commitment: [0u8; 32],
            is_ephemeral: true,
        },
        is_consumed: false,
        action_root: [0u8; 32],
        nullifier_key: None,
        auth_pk: None,
        auth_sig: None,
        encryption_payload: None,
        discovery_payload: None,
        label_info: Some(LabelInfo { forwarder_addr, erc20_token_addr }),
        forwarder_info: Some(ForwarderInfo {
            call_type: CallType::Unwrap,
            hiding_logic_bytes: [9u8; 32],
            ethereum_account_addr: eth_addr,
            permit: None,
        }),
    };

    vec![consumed, created]
}

/// Direct send: consume a persistent resource (`persistent_consume`, signed) → create a
/// persistent resource (`persistent_create` — binds value_ref + label, no signature).
fn send_witnesses(
    logic_ref: [u8; 32],
    nk_commitment: [u8; 32],
    nk: &NullifierKey,
    auth_pk: &[u8],
) -> Vec<TransferAuthWitness> {
    let forwarder_addr = vec![0x11u8; 20];
    let erc20_token_addr = vec![0x22u8; 20];
    let payload = vec![7u8; 16];
    let value_ref = persistent_value_ref(auth_pk, &payload);
    let label_ref = calculate_label_ref(&forwarder_addr, &erc20_token_addr);

    let consumed = TransferAuthWitness {
        resource: Resource {
            logic_ref,
            label_ref: [0u8; 32], // persistent_consume doesn't check the label
            value_ref,
            quantity: 42,
            nonce: [4u8; 32],
            nk_commitment,
            is_ephemeral: false,
        },
        is_consumed: true,
        action_root: [0u8; 32],
        nullifier_key: Some(nk.clone()),
        auth_pk: Some(auth_pk.to_vec()),
        auth_sig: None, // filled by main
        encryption_payload: Some(payload.clone()),
        discovery_payload: None,
        label_info: None,
        forwarder_info: None,
    };

    let created = TransferAuthWitness {
        resource: Resource {
            logic_ref,
            label_ref,
            value_ref,
            quantity: 42,
            nonce: [0u8; 32],
            nk_commitment: [0u8; 32],
            is_ephemeral: false,
        },
        is_consumed: false,
        action_root: [0u8; 32],
        nullifier_key: None,
        auth_pk: Some(auth_pk.to_vec()),
        auth_sig: None,
        encryption_payload: Some(payload),
        discovery_payload: None,
        label_info: Some(LabelInfo { forwarder_addr, erc20_token_addr }),
        forwarder_info: None,
    };

    vec![consumed, created]
}

fn main() -> eyre::Result<()> {
    let flow = std::env::var("FLOW").unwrap_or_else(|_| "wrap".to_string());

    let app_params = app_params_with_100_bits_security(21);
    let agg_params = AggregationSystemParams {
        leaf: leaf_params_with_100_bits_security(),
        internal: internal_params_with_100_bits_security(),
    };
    // The one rich VM (logic.toml) runs trivial logic AND transfer_auth.
    let logic_sdk = Sdk::new(
        AppConfig::new(logic_sdk_vm_config()?, app_params.clone()),
        agg_params.clone(),
    )?;

    let transfer_exe: VmExe<F> = read_object_from_file(TRANSFER_AUTH_VMEXE)?;
    let logic_ref: [u8; 32] =
        f_slice_to_bytes(&logic_sdk.app_prover(transfer_exe.clone())?.app_exe_commit())
            .try_into()
            .expect("32-byte commit");

    let nullifier_key = NullifierKey { bytes: [6u8; 32] };
    let nk_commitment = keccak256(&nullifier_key.bytes);

    // Authority key for persistent_consume (unwrap/send): host-signs the action_root.
    // openvm-k256 signing is stubbed, so sign with the plain k256 crate — its sigs verify
    // under openvm-k256's verify_prehash in-guest.
    let signing_key = SigningKey::from_slice(&[0x55u8; 32]).expect("valid scalar");
    let auth_pk = signing_key
        .verifying_key()
        .as_affine()
        .to_encoded_point(true)
        .as_bytes()
        .to_vec();

    let mut witnesses = match flow.as_str() {
        "wrap" => wrap_witnesses(logic_ref, nk_commitment, &nullifier_key),
        "unwrap" => unwrap_witnesses(logic_ref, nk_commitment, &nullifier_key, &auth_pk),
        "send" => send_witnesses(logic_ref, nk_commitment, &nullifier_key, &auth_pk),
        other => eyre::bail!("FLOW must be wrap|unwrap|send, got `{other}`"),
    };

    // Derive nullifiers, created nonces, and action_root (mirrors the compliance guest).
    let consumed_idx: Vec<usize> =
        witnesses.iter().enumerate().filter(|(_, w)| w.is_consumed).map(|(i, _)| i).collect();
    let created_idx: Vec<usize> =
        witnesses.iter().enumerate().filter(|(_, w)| !w.is_consumed).map(|(i, _)| i).collect();

    let mut nullifiers: Vec<[u8; 32]> = consumed_idx
        .iter()
        .map(|&i| {
            let w = &witnesses[i];
            w.resource.nullify(w.nullifier_key.as_ref().expect("consumed needs nk")).unwrap()
        })
        .collect();
    let n = nullifiers.len();
    nullifiers.push([0u8; 32]);
    let mut index_bytes = [0u8; 32];
    let mut created_tags = Vec::new();
    for (index, &wi) in created_idx.iter().enumerate() {
        index_bytes[..4].copy_from_slice(&(index as u32).to_be_bytes());
        nullifiers[n] = index_bytes;
        witnesses[wi].resource.nonce = keccak256(&nullifiers.concat());
        created_tags.push(witnesses[wi].resource.commit());
    }
    nullifiers.truncate(n);

    let all_tags: Vec<[u8; 32]> = nullifiers.iter().chain(created_tags.iter()).copied().collect();
    let action_root = *SparseTree::compute_tree(&all_tags).unwrap().root().unwrap();
    for w in witnesses.iter_mut() {
        w.action_root = action_root;
    }

    // persistent_consume (unwrap/send consumed side) verifies a signature over the
    // action_root — sign it now that it's known.
    for w in witnesses.iter_mut() {
        if w.is_consumed && !w.resource.is_ephemeral {
            let sig: Signature =
                signing_key.sign_prehash(&action_root).expect("sign action_root");
            w.auth_sig = Some(sig.to_bytes().to_vec());
        }
    }

    // Prove the transfer logic guest per resource — all on the one VM.
    let order: Vec<usize> = consumed_idx.iter().chain(created_idx.iter()).copied().collect();
    let mut proofs = Vec::new();
    let mut app_datas = Vec::new();
    let mut baseline = None;
    for &i in &order {
        let app_data = witnesses[i].constrain().unwrap().app_data;
        let mut stdin = StdIn::default();
        stdin.write(&witnesses[i]);
        let t = Instant::now();
        let (proof, bl) = logic_sdk.prove(transfer_exe.clone(), stdin, &[])?;
        eprintln!("transfer logic proof [{i}]: {:?}", t.elapsed());
        baseline.get_or_insert(bl);
        proofs.push(proof);
        app_datas.push(app_data);
    }
    let baseline = baseline.expect("at least one resource");

    // Single deferral slot built on the one VM's IR (same as bench_compliance).
    let agg = logic_sdk.agg_prover();
    let ir_vk = agg.internal_recursive_prover.get_vk();
    let ir_pcs = agg
        .internal_recursive_prover
        .get_self_vk_pcs_data()
        .unwrap();
    let logic_sys = logic_sdk.app_config().app_vm_config.as_ref().clone();
    let verify_prover = VerifyProver::new::<E>(
        ir_vk,
        ir_pcs.commitment.into(),
        internal_params_with_100_bits_security(),
        logic_sys.memory_config.memory_dimensions(),
        logic_sys.num_public_values,
        None,
        0,
    );
    let deferral_prover = DeferralProver::new(
        VerifyCircuitProver::new(verify_prover),
        AggregationConfig { params: agg_params.clone() },
        root_params_with_100_bits_security(),
    );
    let deferral_ext =
        deferral_prover.make_extension(vec![Arc::new(DeferralFn::new(verify_stark_deferral_fn))]);

    let mut compliance_vm_config =
        SdkVmConfig::from_toml(include_str!("../../compliance/openvm.toml"))?;
    compliance_vm_config.deferral = Some(deferral_ext);
    compliance_vm_config.system.config.memory_config.addr_spaces[DEFERRAL_AS as usize].num_cells =
        1 << 25;
    let compliance_sdk = Sdk::builder()
        .app_config(AppConfig::new(compliance_vm_config, app_params))
        .agg_params(agg_params)
        .deferral_prover(deferral_prover)
        .build()?;

    let logic_vk = VmStarkVerifyingKey {
        mvk: logic_sdk.agg_vk().as_ref().clone(),
        baseline,
    };
    let raw = get_raw_deferral_results(&logic_vk, &proofs)?;
    let input_commits: Vec<[u8; 32]> =
        raw.iter().map(|r| r.input.clone().try_into().unwrap()).collect();
    let deferral_state = get_deferral_state(&logic_vk, &proofs, DEF_IDX as u32)?;

    // ComplianceWitness — consumed/created follow `order`.
    let mut consumed = Vec::new();
    let mut created = Vec::new();
    for (pos, &i) in order.iter().enumerate() {
        let w = &witnesses[i];
        if w.is_consumed {
            consumed.push(ConsumedWitness {
                resource: w.resource.clone(),
                nullifier_key: w.nullifier_key.clone().unwrap(),
                path: Proof { path: vec![] },
                delta_extra_input: [7u8; 32],
                logic_hiding_input: [9u8; 32],
                app_data: app_datas[pos].clone(),
                logic_proof: input_commits[pos],
            });
        } else {
            created.push(CreatedWitness {
                resource: w.resource.clone(),
                delta_extra_input: [8u8; 32],
                logic_hiding_input: [10u8; 32],
                app_data: app_datas[pos].clone(),
                logic_proof: input_commits[pos],
            });
        }
    }
    let witness = ComplianceWitness { consumed, created, action_root, kind_table: vec![] };

    let compliance_exe: VmExe<F> = read_object_from_file(COMPLIANCE_VMEXE)?;
    let mut stdin = StdIn::default();
    stdin.write(&witness);
    stdin.deferrals = vec![deferral_state];
    let def_input = DeferralInput::from_inputs(&proofs);

    let t = Instant::now();
    compliance_sdk.prove(compliance_exe, stdin, &[def_input])?;
    eprintln!("compliance proof ({flow}): {:?}", t.elapsed());
    eprintln!("end-to-end OK");
    Ok(())
}
