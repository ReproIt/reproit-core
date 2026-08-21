# Repro It Core

Repro It Core is the canonical v1 contract shared by the SDKs, CLI, and managed service. It defines
the public protocol bytes and deterministic rules. Each released component pins one exact Core
commit.

## Find the contract

| Task | Source |
| --- | --- |
| Change a schema or conformance vector | `specs/v1` |
| Change shared validation, identity, or cryptography | `crates/reproit-core` |
| Change Backend capture or replay rules | `crates/reproit-backend` |
| Change the managed service API contract | `crates/reproit-cloud-api` |
| Change the worker control contract | `crates/reproit-worker` |
| Test a public parser with arbitrary bytes | `fuzz` |

## Change a contract

1. Change the schema or vector in `specs/v1`.
2. Change the Rust rule that implements it.
3. Add positive and negative tests.
4. Run the complete verification commands.
5. Publish one immutable commit.
6. Update each consumer to that commit.

A v1 protocol value keeps one meaning. Use a new protocol version for a breaking wire or semantic
change.

## Verify Core

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you change a shared contract. Read
[fuzz/README.md](fuzz/README.md) when you change a public parser.
