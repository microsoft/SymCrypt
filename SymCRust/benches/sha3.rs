//
// sha3.rs criterion benchmarking for SHA3
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use symcrust::sha3::sha3_impl::keccak_permute_pub_wrapper;

fn bench_keccak_permute(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);

    let mut test_state = [0u64; 25];
    rng.fill(&mut test_state);

    let mut group = c.benchmark_group("keccak_permute");
    group.bench_function("permute", |b| {
        b.iter(|| {
            keccak_permute_pub_wrapper(black_box(&mut test_state));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_keccak_permute);
criterion_main!(benches);