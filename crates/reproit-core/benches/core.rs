use criterion::{Criterion, criterion_group, criterion_main};
use reproit_core::canonical;
use serde_json::json;

fn canonical_digest(c: &mut Criterion) {
    let value = json!({
        "format": "reproit.proof.v1",
        "result": "TARGET_REPRODUCED",
        "run_index": 0
    });

    c.bench_function("canonical_digest_small", |b| {
        b.iter(|| canonical::digest_value(&value).expect("the fixed value is valid"));
    });
}

criterion_group!(benches, canonical_digest);
criterion_main!(benches);
