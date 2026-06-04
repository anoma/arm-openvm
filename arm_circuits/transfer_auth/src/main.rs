use arm_core::transfer_auth::TransferAuthWitness;

openvm::init!();

fn main() {
    let witness: TransferAuthWitness = openvm::io::read();
    let instance = witness.constrain().unwrap();
    openvm::io::reveal_bytes32(instance.logic_digest());
}
