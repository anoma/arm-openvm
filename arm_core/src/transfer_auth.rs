//! # transfer_auth
//!
//! The core guest logic for erc20 token wrapper
//! Core differences from arm-risc0 app include:
//! - forwarder calldata needs logic_hiding_input due to FP
//! - to skip AES generation the encryption payload is added to value

use alloc::vec::Vec;

use arm_traits::resource::Resource as _;
use openvm_k256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};

use crate::{
    error::ArmError,
    evm::{
        CallType, encode_forwarder_calldata, encode_unwrap_forwarder_input,
        encode_wrap_forwarder_input,
    },
    hash::keccak256,
    instance::{AppData, Payload, ResourceLogicInstance},
    nullifier_key::NullifierKey,
    resource::Resource,
};

/// Label plaintext: `label_ref = keccak256(forwarder_addr ‖ erc20_token_addr)`.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct LabelInfo {
    pub forwarder_addr: Vec<u8>,
    pub erc20_token_addr: Vec<u8>,
}

/// Permit2 inputs for a wrap, forwarded (unverified in-circuit) to the EVM forwarder.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PermitInfo {
    pub permit_nonce: Vec<u8>,
    pub permit_deadline: Vec<u8>,
    pub permit_sig: Vec<u8>,
}

/// Forwarder inputs for the ephemeral wrap/unwrap branch.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ForwarderInfo {
    pub call_type: CallType,
    pub hiding_logic_bytes: [u8; 32],
    pub ethereum_account_addr: Vec<u8>,
    /// Required for a wrap (consumed ephemeral); absent for an unwrap.
    pub permit: Option<PermitInfo>,
}

/// Witness for the erc20 wrapper logic
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TransferAuthWitness {
    pub resource: Resource,
    pub is_consumed: bool,
    pub action_root: [u8; 32],
    pub nullifier_key: Option<NullifierKey>,
    pub auth_pk: Option<Vec<u8>>,
    pub auth_sig: Option<Vec<u8>>,
    /// Host-encrypted resource ciphertext, bound into `value_ref` (non-ephemeral).
    pub encryption_payload: Option<Vec<u8>>,
    pub discovery_payload: Option<Vec<u8>>,
    pub label_info: Option<LabelInfo>,
    pub forwarder_info: Option<ForwarderInfo>,
}

/// `label_ref = keccak256(forwarder_addr ‖ erc20_token_addr)`.
pub fn calculate_label_ref(forwarder_addr: &[u8], erc20_token_addr: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(forwarder_addr.len() + erc20_token_addr.len());
    bytes.extend_from_slice(forwarder_addr);
    bytes.extend_from_slice(erc20_token_addr);
    keccak256(&bytes)
}

/// `value_ref = keccak256(auth_pk ‖ encryption_payload)`
pub fn persistent_value_ref(auth_pk: &[u8], encryption_payload: &[u8]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(auth_pk.len() + encryption_payload.len());
    bytes.extend_from_slice(auth_pk);
    bytes.extend_from_slice(encryption_payload);
    keccak256(&bytes)
}

/// Ephemeral-unwrap `value_ref`: the 20-byte ethereum account address left-aligned
/// in 32 bytes.
pub fn value_ref_from_eth_addr(ethereum_account_addr: &[u8]) -> [u8; 32] {
    let mut value_ref = [0u8; 32];
    value_ref[..20].copy_from_slice(ethereum_account_addr);
    value_ref
}

impl TransferAuthWitness {
    /// The resource tag: nullifier when consumed, commitment when created.
    fn tag(&self) -> Result<[u8; 32], ArmError> {
        if self.is_consumed {
            let nk = self
                .nullifier_key
                .as_ref()
                .ok_or(ArmError::MissingField("nullifier_key"))?;
            Ok(self.resource.nullify(nk)?)
        } else {
            Ok(self.resource.commit())
        }
    }

    /// Verify the resource logic and emit its instance.
    pub fn constrain(&self) -> Result<ResourceLogicInstance, ArmError> {
        let tag = self.tag()?;
        let app_data = if self.resource.is_ephemeral {
            self.ephemeral_resource_check()?
        } else if self.is_consumed {
            self.persistent_consume()?
        } else {
            self.persistent_create()?
        };
        Ok(ResourceLogicInstance {
            tag,
            action_root: self.action_root,
            is_consumed: self.is_consumed,
            app_data,
        })
    }

    /// Ephemeral wrap/unwrap: check the label and build the EVM forwarder calldata.
    fn ephemeral_resource_check(&self) -> Result<AppData, ArmError> {
        let forwarder = self
            .forwarder_info
            .as_ref()
            .ok_or(ArmError::MissingField("forwarder_info"))?;
        let label = self
            .label_info
            .as_ref()
            .ok_or(ArmError::MissingField("label_info"))?;

        if self.resource.label_ref
            != calculate_label_ref(&label.forwarder_addr, &label.erc20_token_addr)
        {
            return Err(ArmError::LabelRefMismatch);
        }

        let input = if self.is_consumed {
            if forwarder.call_type != CallType::Wrap {
                return Err(ArmError::InvalidCalldata("expected Wrap call type"));
            }
            let permit = forwarder
                .permit
                .as_ref()
                .ok_or(ArmError::MissingField("permit"))?;
            encode_wrap_forwarder_input(
                &label.erc20_token_addr,
                self.resource.quantity,
                &permit.permit_nonce,
                &permit.permit_deadline,
                &forwarder.ethereum_account_addr,
                &self.action_root,
                &permit.permit_sig,
            )?
        } else {
            if forwarder.call_type != CallType::Unwrap {
                return Err(ArmError::InvalidCalldata("expected Unwrap call type"));
            }
            if self.resource.value_ref != value_ref_from_eth_addr(&forwarder.ethereum_account_addr)
            {
                return Err(ArmError::ValueRefMismatch);
            }
            encode_unwrap_forwarder_input(
                &label.erc20_token_addr,
                &forwarder.ethereum_account_addr,
                self.resource.quantity,
            )?
        };

        let data = encode_forwarder_calldata(
            &label.forwarder_addr,
            forwarder.hiding_logic_bytes,
            input,
            Vec::new(),
        )?;
        Ok(AppData {
            external_payload: Vec::from([Payload {
                data,
                deletion_criterion: false,
            }]),
            ..AppData::default()
        })
    }

    /// Non-ephemeral consume: bind `value_ref` to `(auth_pk, payload)` and verify the
    /// authority signature over the action root.
    fn persistent_consume(&self) -> Result<AppData, ArmError> {
        let pk = self
            .auth_pk
            .as_ref()
            .ok_or(ArmError::MissingField("auth_pk"))?;
        let sig = self
            .auth_sig
            .as_ref()
            .ok_or(ArmError::MissingField("auth_sig"))?;
        let payload = self
            .encryption_payload
            .as_ref()
            .ok_or(ArmError::MissingField("encryption_payload"))?;

        if self.resource.value_ref != persistent_value_ref(pk, payload) {
            return Err(ArmError::ValueRefMismatch);
        }
        let vk = VerifyingKey::from_sec1_bytes(pk).map_err(|_| ArmError::InvalidSignature)?;
        let signature = Signature::from_slice(sig).map_err(|_| ArmError::InvalidSignature)?;
        vk.verify_prehash(&self.action_root, &signature)
            .map_err(|_| ArmError::InvalidSignature)?;

        Ok(AppData::default())
    }

    /// Non-ephemeral create: bind `value_ref` to `(auth_pk, payload)`, check the label,
    /// and emit the resource + discovery payloads.
    fn persistent_create(&self) -> Result<AppData, ArmError> {
        let pk = self
            .auth_pk
            .as_ref()
            .ok_or(ArmError::MissingField("auth_pk"))?;
        let payload = self
            .encryption_payload
            .as_ref()
            .ok_or(ArmError::MissingField("encryption_payload"))?;
        let label = self
            .label_info
            .as_ref()
            .ok_or(ArmError::MissingField("label_info"))?;

        if self.resource.label_ref
            != calculate_label_ref(&label.forwarder_addr, &label.erc20_token_addr)
        {
            return Err(ArmError::LabelRefMismatch);
        }
        if self.resource.value_ref != persistent_value_ref(pk, payload) {
            return Err(ArmError::ValueRefMismatch);
        }

        let discovery = self.discovery_payload.clone().unwrap_or_default();
        Ok(AppData {
            resource_payload: Vec::from([Payload {
                data: payload.clone(),
                deletion_criterion: true,
            }]),
            discovery_payload: Vec::from([Payload {
                data: discovery,
                deletion_criterion: true,
            }]),
            ..AppData::default()
        })
    }
}
