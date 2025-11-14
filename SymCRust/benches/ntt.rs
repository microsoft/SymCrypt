//
// ntt.rs criterion benchmarking for NTT/ITT
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//


use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion};
use rand::prelude::*;
use symcrust::mlkem::ntt;

fn criterion_benchmark(c: &mut Criterion) {
    let mut r = StdRng::seed_from_u64(0);
    let mut poly_element: [u16; 256] = [0; 256];
    r.fill(&mut poly_element);
    for x in poly_element.iter_mut() {
        *x = *x % 3329;
    }
    c.bench_function("ntt", |b| b.iter(|| ntt::poly_element_ntt(black_box(&mut poly_element))));
    c.bench_function("intt", |b| b.iter(|| ntt::poly_element_intt_and_mul_r(black_box(&mut poly_element))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
