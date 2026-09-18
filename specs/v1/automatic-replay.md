# Automatic World replay

Resolve the sealed capsule with `resolve_replay_capsule` before automatic replay.
Verify each payload size and digest before use. Do not interpret candidate records
as replay inputs.

An automatic World has one recoverable point. Its provider is `automatic-world`,
its engine is `reproit-native`, and its engine version is `1.0.0`. Its capability
list contains only `capture.automatic-world.v1`. All payloads use
`application/octet-stream`.

State artifact URIs have this form:

```text
reproit-managed://automatic-world/{boundary_id}/{request_digest}/{session_position}/{outcome}
```

Only environment and filesystem observations use state artifacts. Other classes
use the `reproit-native` dependency transcript, version `1.0.0`. Transcript
interactions belong to the captured Trigger operation. The response outcome must
match the interaction or artifact outcome.

Environment position zero records the request `process-environment`. Its response
is a canonical JSON map of base64url names and values. Names must be nonempty and
must not contain `=` or NUL. Values must not contain NUL. The map has at most 4,096
entries and 524,288 decoded bytes. The encoded object has at most 1,048,576 bytes.

Clock position zero records the request `wall-clock`. Its response is a canonical
UTC timestamp. Both baseline observations must exist exactly once and succeed.
They describe the operation boundary. They do not replace later semantic reads.

Other records use the existing canonical semantic observation or semantic
dependency contracts. Each request or response has at most 65,536 bytes. The
combined baseline and semantic observation count has a limit of 1,024.

Session positions start at zero for each class and have no gaps or duplicates.
During replay, match the class, session position, and exact request digest before
returning a recorded response. Validate the semantic pair when the request becomes
available. State artifacts retain only the request digest and response.

Reject missing, additional, changed, unfinished, or unconsumed observations.
Never substitute a live effect when a recorded observation does not match.
