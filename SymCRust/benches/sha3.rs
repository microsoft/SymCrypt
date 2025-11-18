//
// sha3.rs criterion benchmarking for SHA3
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::prelude::*;
use symcrust::sha3::sha3_224::{Sha3_224HashState, SHA3_224_RESULT_SIZE};
use symcrust::sha3::sha3_impl::keccak_permute_pub_wrapper;
use symcrust::hash::Hash;

fn bench_sha3_224(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(42);

    let sizes = vec![144, 288, 576, 1152, (1 << 13)];

    let mut group = c.benchmark_group("sha3_224");
    for size in sizes.iter() {
        let mut data = vec![0u8; *size];
        rng.fill_bytes(&mut data);

        group.bench_with_input(BenchmarkId::new("hash", size), size, |b, _| {
            let mut result = [0u8; SHA3_224_RESULT_SIZE];
            let mut sha3_224_state = Sha3_224HashState::default();
            b.iter(|| {
                sha3_224_state.hash(black_box(&data), black_box(&mut result));
            });
        });
    }
    group.finish();
}

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

criterion_group!(benches, bench_sha3_224, bench_keccak_permute);
criterion_main!(benches);
