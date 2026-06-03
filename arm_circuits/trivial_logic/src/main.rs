use arm_core::instance::ResourceLogicInstance;

fn main() {
    let witness: ResourceLogicInstance = openvm::io::read();
    openvm::io::reveal_bytes32(witness.logic_digest());
}
