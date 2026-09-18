# Contributing to Repro It Core

## Change a shared contract

1. Change the canonical schema or vector in `specs/v1`.
2. Change the deterministic Rust implementation.
3. Add positive and negative tests for the boundary.
4. Run the formatter, strict linter, and complete test suite.
5. Run each fuzz target when parser behavior changes.
6. Publish one immutable Core identity.
7. Update the pinned Core identity in the SDK, CLI, and Cloud repositories.

Do not change consumers first. A consumer cannot define or repair a Core contract.

The Core crate includes generated copies of four canonical contracts so Cargo can package it
without the repository root. After you change these contracts, refresh the copies:

```sh
cp specs/v1/schemas.json specs/v1/cloud-api-schemas.json specs/v1/mcp-schemas.json \
  specs/v1/protocol-vectors.json crates/reproit-core/contracts/
```

The `packaged_contracts` test requires exact bytes. Edit the canonical files in `specs/v1`.

## Fuzz parsers

The `fuzz/` directory is a separate `cargo fuzz` workspace. It is not the property-test suite.

```sh
cargo fuzz run strict_json
cargo fuzz run candidate
cargo fuzz run replay_capsule
cargo fuzz run automatic_replay
```

Property and state-machine tests remain next to the package that owns the tested rule.
