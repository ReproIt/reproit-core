#![no_main]

use libfuzzer_sys::fuzz_target;
use reproit_core::model::{ReplayCapsule, Validate};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(capsule) = reproit_core::canonical::parse_strict::<ReplayCapsule>(bytes) {
        let _ = capsule.validate();
    }
});
