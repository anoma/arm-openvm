use alloy_sol_types::{SolValue, sol};
use arm_core::instance::{AppData, Payload, ResourceLogicInstance};

sol! {
    struct SolLogicInstance {
       bytes32 tag;
       bytes32 actionTreeRoot;
       bool isConsumed;
       SolAppData appData;
    }

    struct SolAppData {
        SolPayload[] resourcePayload;
        SolPayload[] encryptionPayload;
        SolPayload[] externalPayload;
        SolPayload[] discoveryPayload;
    }

    struct SolPayload {
        bytes data;
        bool deletionCriterion;
    }
}

fn instance_to_abi(rust_instance: ResourceLogicInstance) -> SolLogicInstance {
    SolLogicInstance {
        tag: rust_instance.tag.into(),
        actionTreeRoot: rust_instance.action_root.into(),
        isConsumed: rust_instance.is_consumed,
        appData: app_data_to_abi(&rust_instance.app_data),
    }
}

pub fn app_data_to_abi(rust_appdata: &AppData) -> SolAppData {
    SolAppData {
        resourcePayload: rust_appdata
            .resource_payload
            .iter()
            .map(payload_to_abi)
            .collect(),
        encryptionPayload: rust_appdata
            .encryption_payload
            .iter()
            .map(payload_to_abi)
            .collect(),
        externalPayload: rust_appdata
            .external_payload
            .iter()
            .map(payload_to_abi)
            .collect(),
        discoveryPayload: rust_appdata
            .discovery_payload
            .iter()
            .map(payload_to_abi)
            .collect(),
    }
}

pub fn payload_to_abi(rust_payload: &Payload) -> SolPayload {
    SolPayload {
        data: rust_payload.data.clone().into(),
        deletionCriterion: rust_payload.deletion_criterion,
    }
}

fn main() {
    let witness: ResourceLogicInstance = openvm::io::read();
    openvm::io::reveal_bytes32(arm_core::hash::keccak256(
        &instance_to_abi(witness).abi_encode(),
    ));
}
