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

## Fuzz parsers

The `fuzz/` directory is a separate `cargo fuzz` workspace. It is not the property-test suite.

```sh
cargo fuzz run strict_json
cargo fuzz run candidate
cargo fuzz run replay_capsule
```

Property and state-machine tests remain next to the package that owns the tested rule.
