//! # evm
//!
//! Implementation of external payload encoding

use alloc::vec::Vec;

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolValue, sol};

use crate::error::ArmError;

sol! {
    struct ForwarderCalldata {
        address untrustedForwarder;
        // logic_hiding_bytes are now sent alongside the external calls
        // one has to be careful that these are the same bytes to be
        // fed to the compliance
        bytes32 logicHidingBytes;
        bytes input;
        bytes output;
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
    enum CallType {
        Wrap,
        Unwrap,
    }

    struct WrapData {
        uint256 nonce;
        uint256 deadline;
        address owner;
        bytes32 actionTreeRoot;
        bytes32 r;
        bytes32 s;
        uint8 v;
    }

    struct UnwrapData {
        address receiver;
    }
}

/// ABI-encoding of the forwarder calldata
pub fn encode_forwarder_calldata(
    forwarder: &[u8],
    logic_hiding_bytes: [u8; 32],
    input: Vec<u8>,
    output: Vec<u8>,
) -> Result<Vec<u8>, ArmError> {
    let untrusted_forwarder = forwarder
        .try_into()
        .map_err(|_| ArmError::InvalidCalldata("forwarder address"))?;
    let hiding_bytes = logic_hiding_bytes
        .try_into()
        .map_err(|_| ArmError::InvalidCalldata("hiding bytes"))?;
    Ok(ForwarderCalldata {
        untrustedForwarder: untrusted_forwarder,
        logicHidingBytes: hiding_bytes,
        input: input.into(),
        output: output.into(),
    }
    .abi_encode_params())
}

/// ABI-encode the forwarder input for an unwrap.
pub fn encode_unwrap_forwarder_input(
    erc20_token_addr: &[u8],
    ethereum_account_addr: &[u8],
    quantity: u128,
) -> Result<Vec<u8>, ArmError> {
    let token: Address = erc20_token_addr
        .try_into()
        .map_err(|_| ArmError::InvalidCalldata("erc20 token address"))?;
    let receiver: Address = ethereum_account_addr
        .try_into()
        .map_err(|_| ArmError::InvalidCalldata("ethereum account address"))?;
    Ok((CallType::Unwrap, token, quantity, UnwrapData { receiver }).abi_encode_params())
}

/// ABI-encode the forwarder input for a wrap.
pub fn encode_wrap_forwarder_input(
    erc20_token_addr: &[u8],
    quantity: u128,
    nonce: &[u8],
    deadline: &[u8],
    ethereum_account_addr: &[u8],
    action_tree_root: &[u8],
    signature: &[u8],
) -> Result<Vec<u8>, ArmError> {
    let erc20_token: Address = erc20_token_addr
        .try_into()
        .map_err(|_| ArmError::InvalidCalldata("erc20 token address"))?;
    let owner: Address = ethereum_account_addr
        .try_into()
        .map_err(|_| ArmError::InvalidCalldata("ethereum account address"))?;
    if signature.len() != 65 {
        return Err(ArmError::InvalidCalldata(
            "permit signature must be 65 bytes",
        ));
    }
    let wrap_data = WrapData {
        nonce: U256::from_be_slice(nonce),
        deadline: U256::from_be_slice(deadline),
        owner,
        actionTreeRoot: B256::from_slice(action_tree_root),
        r: B256::from_slice(&signature[0..32]),
        s: B256::from_slice(&signature[32..64]),
        v: signature[64],
    };
    Ok((CallType::Wrap, erc20_token, quantity, wrap_data).abi_encode_params())
}
