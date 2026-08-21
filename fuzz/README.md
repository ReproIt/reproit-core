# Parser fuzzing

This directory is a separate `cargo fuzz` workspace. It is not the property-test suite.

The targets accept arbitrary bytes and must not panic, hang, or accept invalid public data:

- `strict_json` tests the strict canonical JSON parser.
- `candidate` tests failed-operation parsing and validation.
- `replay_capsule` tests replay-data parsing and validation.

Install `cargo fuzz`, then run one target from the repository root:

```sh
cargo fuzz run strict_json
cargo fuzz run candidate
cargo fuzz run replay_capsule
```

`cargo fuzz` writes generated corpus and build output under `fuzz/`. Git ignores those generated
files.
