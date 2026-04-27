# Anoma OpenVM Resource Machine (Prototype)

A shielded resource machine implementation built on the beta tag of [OpenVM](https://github.com/openvm-org/openvm) zkVM.

**WARNING** This repo is a work-in-progress.

## Docs

- [General RM Specification](https://specs.anoma.net/latest/arch/system/state/resource_machine/index.html)
- [Risc0 RM Implementation](https://github.com/anoma/arm-risc0)

## Layout

- `arm_traits/` — shared trait definitions
- `arm_core/` — resource, compliance, and instance types; host + guest helpers
- `arm_circuits/` — host code and guest programs
  - `compliance/` — compliance unit guest (separate workspace, built with `cargo openvm`)

## Build

Compliance guest requires [`cargo-openvm`](https://github.com/openvm-org/openvm) of the appropriate tag:

```bash
cargo install --locked --git https://github.com/openvm-org/openvm.git --tag v2.0.0-beta.2 cargo-openvm
```

The .vmexe file can afterwards be generated via:

```bash
cd arm_circuits/compliance && cargo openvm build
```

One can run the compliance STARK-generation bench from root using:

```bash
cargo run --release -p arm_circuits --bin bench-compliance
```

## License

Apache-2.0 — see [LICENSE](./LICENSE).
