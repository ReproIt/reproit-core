# Parser fuzzing

Fuzzing sends arbitrary bytes to a parser. It finds crashes, hangs, and invalid input that the
parser accepts. Property tests remain with the package that owns each rule.

| Target | Parser |
| --- | --- |
| `strict_json` | Strict canonical JSON |
| `candidate` | Failed operation candidate |
| `replay_capsule` | Sealed replay data |

Install `cargo fuzz`. Run each affected target from the repository root:

```sh
cargo fuzz run strict_json
cargo fuzz run candidate
cargo fuzz run replay_capsule
```

Git ignores the generated corpus and build output under `fuzz/`.
