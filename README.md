# Repro It Core

This repository is the source of truth for every shared Repro It v1 contract.

Core defines the exact bytes and deterministic rules used by the CLI, SDKs, and managed service.
Those products pin one immutable Core commit and release identity.

## Contents

- `crates/reproit-core` contains shared types, validation, cryptography, and deterministic rules.
- `crates/reproit-backend` contains the Backend profile capture and replay rules.
- `crates/reproit-cloud-api` contains public managed-service wire types.
- `crates/reproit-worker` contains the public execution-control wire contract.
- `specs/v1` contains canonical schemas and conformance vectors.
- `fuzz` contains parser fuzz targets.

Core contains no CLI, SDK integration, network service, database, managed Runtime, admission
service, worker implementation, or deployment code.

## Contract rule

Never copy or redefine a Core rule in another repository. Consumers must pin this repository and run
its conformance vectors.

A compatible change can add validation that rejects previously invalid input. A breaking wire or
semantic change requires a new protocol version. Published v1 bytes never change meaning.

## Verify Core

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the change sequence and fuzz commands.
