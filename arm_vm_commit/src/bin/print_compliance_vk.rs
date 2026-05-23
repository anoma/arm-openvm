use std::io::Write;

fn main() -> eyre::Result<()> {
    let vmexe_path = std::env::args()
        .nth(1)
        .ok_or_else(|| eyre::eyre!("usage: print-compliance-vk <vmexe-path>"))?;
    let vmexe_bytes = std::fs::read(&vmexe_path)?;
    let vk = arm_vm_commit::construct_compliance_vk(&vmexe_bytes)?;
    let serialized = bincode::serde::encode_to_vec(&vk, bincode::config::standard())?;
    std::io::stdout().write_all(&serialized)?;
    Ok(())
}
