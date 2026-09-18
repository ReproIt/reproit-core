#![no_main]

use libfuzzer_sys::fuzz_target;
use reproit_backend::automatic_replay::resolve_automatic_replay;
use reproit_core::{
    Error, canonical,
    model::{LogicalObject, ReplayCapsule, resolve_replay_capsule},
};

fuzz_target!(|bytes: &[u8]| {
    if bytes.len() > 4 * 1_024 * 1_024 {
        return;
    }
    let Ok(value) = canonical::parse_strict::<serde_json::Value>(bytes) else {
        return;
    };
    let Ok(capsule) = serde_json::from_value::<ReplayCapsule>(value["capsule"].clone()) else {
        return;
    };
    let mut read = |object: &LogicalObject| {
        serde_json::from_value::<Vec<u8>>(value["objects"][object.object_id.to_string()].clone())
            .map_err(|_| Error::schema_invalid())
    };
    let Ok(resolved) = resolve_replay_capsule(&capsule, &mut read) else {
        return;
    };
    if let Ok(mut replay) = resolve_automatic_replay(&resolved, &mut read) {
        if let Some(requests) = value["requests"].as_array() {
            for request in requests.iter().take(1_024) {
                if let (Ok(class), Some(position), Ok(body)) = (
                    serde_json::from_value(request["observation_class"].clone()),
                    request["position"].as_u64(),
                    canonical::canonical_bytes(&request["request"]),
                ) {
                    let _ = replay.take_response(class, position, &body);
                }
            }
        }
        let _ = replay.require_complete();
    }
});
