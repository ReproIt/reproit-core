#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = reproit_core::canonical::parse_strict::<serde_json::Value>(bytes);
});
