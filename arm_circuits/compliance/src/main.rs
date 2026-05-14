use alloy_sol_types::SolValue;
use arm_core::{hash::keccak256, witness::ComplianceWitness};

openvm::init!();

fn main() {
    let witness: ComplianceWitness = openvm::io::read();
    let core_instance = witness.constrain().unwrap();
    let digest = keccak256(&core_instance.to_sol().abi_encode());
    openvm::io::reveal_bytes32(digest);
}
