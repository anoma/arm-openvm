# arm_circuits

Guest programs and benchmarks for the OpenVM RM.

The three guests (`compliance/`, `trivial_logic/`, `transfer_auth/`) are separate
workspaces built with `cargo openvm build`; everything else here is host code.

See the [root README](../README.md) for prerequisites (Rust, `cargo-openvm`, the SNARK SRS).

## Building the guests

Build each guest's `.vmexe`:

```bash
cd arm_circuits/compliance    && cargo openvm build
cd arm_circuits/trivial_logic && cargo openvm build
cd arm_circuits/transfer_auth && cargo openvm build
```

## Running the bench

`bench-compliance` proves the two trivial logics, then the compliance proof, end to end:

```bash
cargo run --release -p arm_circuits --bin bench-compliance
```

Modes:
- **default** — STARK compliance proof (BabyBear).
- **`--features evm`** — wraps to an EVM-verifiable halo2/KZG SNARK (`prove_evm`).
- **`--features cuda`** — runs the prover on GPU.
- **`KIND_TABLE=<ANYTHING>`** (env var) — supplies a fabricated kind table, unset = empty table.

## Logic-proof cache

The two logic proofs are cached in `arm_circuits/cache/`.

A run loads them if all three files exist (`logic_proof_consumed.bin`, `logic_proof_created.bin`,
`logic_baseline.bin`), otherwise it proves and writes them.

## Proving key regeneration

A guest's proving key follows from its `.vmexe`, so regenerating it just means
rebuilding the guest (see [Building the guests](#building-the-guests)). Rebuild
whenever a guest's code or dependency changes.

## Verifying key regeneration

Only the compliance unit needs a committed verifying key at this point.

Regenerate `arm_core/compliance.vk` by:

```bash
cargo run --release -p arm_vm_commit --bin print-compliance-vk -- \
  arm_circuits/compliance/openvm/release/compliance-guest.vmexe > arm_core/compliance.vk
```

Then rebuild the NIF so the new key is re-embedded: `mix compile --force`.

## VM commit rebuild

`LOGIC_VM_COMMIT` / `COMPLIANCE_VM_COMMIT` / `TRANSFER_AUTH_VM_COMMIT` in
`arm_core/src/proving.rs` pin each guest's VM extension set. Regenerate them whenever
a VM config changes:

```bash
cargo run --release -p arm_vm_commit --bin print-logic-vm-commit
cargo run --release -p arm_vm_commit --bin print-compliance-vm-commit
cargo run --release -p arm_vm_commit --bin print-transfer-auth-vm-commit
```

and paste the printed arrays into `proving.rs`

## Cache rebuild

If any changes to the logics verified in bench are made, delete the cache.
