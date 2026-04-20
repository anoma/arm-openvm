use alloy_sol_types::{SolValue, sol};
use arm_core::compliance::ComplianceInstance as CoreInstance;

openvm::init!();

sol! {
    struct ConsumedInstance {
        bytes32 nullifier;
        bytes32 root;
        bytes32 logicRef;
    }

    struct CreatedInstance {
        bytes32 commitment;
        bytes32 logicRef;
    }

    struct ComplianceInstance {
        ConsumedInstance[] consumed;
        CreatedInstance[] created;
        bytes32 deltaX;
        bytes32 deltaY;
    }
}

fn to_abi(core: CoreInstance) -> ComplianceInstance {
    ComplianceInstance {
        consumed: core
            .consumed
            .into_iter()
            .map(|c| ConsumedInstance {
                nullifier: c.nullifier.into(),
                root: c.root.into(),
                logicRef: c.logic_ref.into(),
            })
            .collect(),
        created: core
            .created
            .into_iter()
            .map(|c| CreatedInstance {
                commitment: c.commitment.into(),
                logicRef: c.logic_ref.into(),
            })
            .collect(),
        deltaX: core.delta_x.into(),
        deltaY: core.delta_y.into(),
    }
}

fn main() {
    let witness: arm_core::compliance::ComplianceWitness = openvm::io::read();
    let core_instance = witness.constrain().unwrap();
    let abi_instance = to_abi(core_instance);
    let encoded: Vec<u8> = abi_instance.abi_encode();
    let digest = arm_core::hash::keccak256(&encoded);
    openvm::io::reveal_bytes32(digest);
}
