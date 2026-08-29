# Repro It Core

Repro It Core is the canonical contract shared by the SDKs, CLI, and managed
service. It defines the public protocol bytes and deterministic rules. Each
released component pins one exact Core commit.

Core also defines the distributed fuzz campaign, Case Plan, signed context,
case result, and `reproit.operation-begin.v2` contracts. Version 2 adds bounded
campaign identity to an operation. It does not change version 1 production
capture or replay semantics.

## Find the contract

| Task | Source |
| --- | --- |
| Change a schema or conformance vector | `specs/v1` |
| Change shared validation, identity, or cryptography | `crates/reproit-core` |
| Change Backend capture or replay rules | `crates/reproit-backend` |
| Change the managed service API contract | `crates/reproit-cloud-api` |
| Change the worker control contract | `crates/reproit-worker` |
| Test a public parser with arbitrary bytes | `fuzz` |

The distributed fuzz schemas and positive and negative vectors are in
`specs/v1`. Consumers must use the same canonical digest and exact context
validation rules.

## Change a contract

1. Change the schema or vector in `specs/v1`.
2. Change the Rust rule that implements it.
3. Add positive and negative tests.
4. Run the complete verification commands.
5. Publish one immutable commit.
6. Update each consumer to that commit.

A v1 protocol value keeps one meaning. Use a new protocol version for a breaking wire or semantic
change.

## Release job route assumptions

The release job types define the public request and response bodies. Cloud integration assumes
these routes:

- `POST /v1/projects/{project_id}/release-jobs`
- `GET /v1/release-jobs/{release_job_id}`

These route names are not part of the v1 contract until Cloud implements them.

## Verify Core

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Read [CONTRIBUTING.md](CONTRIBUTING.md) before you change a shared contract. Read
[fuzz/README.md](fuzz/README.md) when you change a public parser.
