use alloy_sol_types::SolValue;
use arm_core::instance::ResourceLogicInstance;

fn main() {
    let witness: ResourceLogicInstance = openvm::io::read();
    openvm::io::reveal_bytes32(arm_core::hash::keccak256(&witness.to_sol().abi_encode()));
}
