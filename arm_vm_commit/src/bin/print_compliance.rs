use arm_vm_commit::compute_compliance_vm_commit;

fn main() -> eyre::Result<()> {
    let bytes = compute_compliance_vm_commit()?;
    print!("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        print!("0x{:02x}", b);
    }
    println!("]");
    Ok(())
}
