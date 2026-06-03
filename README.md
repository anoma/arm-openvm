# Anoma OpenVM Resource Machine (Prototype)

A shielded resource machine implementation built on the [OpenVM](https://github.com/openvm-org/openvm) zkVM.

**WARNING** This repo is a work-in-progress.

## Docs

- [General RM Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)
- [Risc0 RM Implementation](https://github.com/anoma/arm-risc0)

## Layout

- `arm_traits/` — shared trait definitions
- `arm_core/` — resource, witness, instance, delta, and action-tree types
- `arm_circuits/` — guest programs and benchmarks
  - `compliance/` — compliance unit guest (separate workspace)
  - `trivial_logic/` — placeholder resource-logic guest (separate workspace)
  - `src/bin/bench_compliance.rs` — compliance proving bench
- `arm_vm_commit/` — host tooling generating the embedded verifying key and VM-commit constants
- `arm_nif/` — Rustler NIFs exposing transaction verification to Elixir
- `lib/`, `mix.exs` — Elixir wrapper for the NIFs

## Dependencies

- **Rust** — host crates build on stable (tested with 1.92.0). The guest toolchain is a pinned nightly that `cargo openvm build` auto-installs via `rustup`.
- **Elixir** — `~> 1.17`, for the NIF wrapper.
- **openvm** — install `cargo-openvm` from the openvm revision the crates pin:
  ```bash
  cargo install --locked --git https://github.com/openvm-org/openvm.git --rev <pinned-rev> cargo-openvm
  ```
- **KZG SRS** — only for SNARK proofs:
  ```bash
  cargo openvm setup --evm --download
  ```

## Building & proving

Building the guests, running the bench (STARK / SNARK / GPU), the logic-proof cache,
and regenerating the proving/verifying keys and VM commits are documented in
[`arm_circuits/README.md`](arm_circuits/README.md).

## License

Apache-2.0 — see [LICENSE](./LICENSE).
