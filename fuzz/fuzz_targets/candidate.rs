#![no_main]

use libfuzzer_sys::fuzz_target;
use reproit_core::model::{Candidate, Validate};

fuzz_target!(|bytes: &[u8]| {
    if let Ok(candidate) = reproit_core::canonical::parse_strict::<Candidate>(bytes) {
        let _ = candidate.validate();
    }
});
