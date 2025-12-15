//
// aes.rs criterion benchmarking for AES
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

use std::hint::black_box;
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use symcrust::aes::{AesExpandedKey, Aes128, Aes192, Aes256};
use symcrust::block_cipher::{BlockCipher, BlockCipherExpandedKey};

fn bench_key_expansion(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES Key Expansion");

    // AES-128 (16 bytes)
    let key_128 = [0u8; 16];
    group.bench_with_input(BenchmarkId::new("AES-128", "16 bytes"), &key_128, |b, key| {
        b.iter(|| {
            let expanded = black_box(AesExpandedKey::new(key));
            black_box(expanded);
        });
    });

    // AES-192 (24 bytes)
    let key_192 = [0u8; 24];
    group.bench_with_input(BenchmarkId::new("AES-192", "24 bytes"), &key_192, |b, key| {
        b.iter(|| {
            let expanded = black_box(AesExpandedKey::new(key));
            black_box(expanded);
        });
    });

    // AES-256 (32 bytes)
    let key_256 = [0u8; 32];
    group.bench_with_input(BenchmarkId::new("AES-256", "32 bytes"), &key_256, |b, key| {
        b.iter(|| {
            let expanded = black_box(AesExpandedKey::new(key));
            black_box(expanded);
        });
    });

    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES Encryption");

    let plaintext = [0u8; 16];

    // AES-128 encryption
    let key_128 = [0u8; 16];
    let expanded_key_128 = AesExpandedKey::new(&key_128);
    group.bench_with_input(BenchmarkId::new("AES-128", "single block"), &plaintext, |b, pt| {
        b.iter(|| {
            let mut block = *pt;
            Aes128::encrypt_block_in_place(black_box(&expanded_key_128), black_box(&mut block));
            black_box(block);
        });
    });

    // AES-192 encryption
    let key_192 = [0u8; 24];
    let expanded_key_192 = AesExpandedKey::new(&key_192);
    group.bench_with_input(BenchmarkId::new("AES-192", "single block"), &plaintext, |b, pt| {
        b.iter(|| {
            let mut block = *pt;
            Aes192::encrypt_block_in_place(black_box(&expanded_key_192), black_box(&mut block));
            black_box(block);
        });
    });

    // AES-256 encryption
    let key_256 = [0u8; 32];
    let expanded_key_256 = AesExpandedKey::new(&key_256);
    group.bench_with_input(BenchmarkId::new("AES-256", "single block"), &plaintext, |b, pt| {
        b.iter(|| {
            let mut block = *pt;
            Aes256::encrypt_block_in_place(black_box(&expanded_key_256), black_box(&mut block));
            black_box(block);
        });
    });

    group.finish();
}

fn bench_decryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("AES Decryption");

    // Generate ciphertext by encrypting some plaintext
    let plaintext = [0u8; 16];

    // AES-128 decryption
    let key_128 = [0u8; 16];
    let expanded_key_128 = AesExpandedKey::new(&key_128);
    let mut ciphertext_128 = plaintext;
    Aes128::encrypt_block_in_place(&expanded_key_128, &mut ciphertext_128);

    group.bench_with_input(BenchmarkId::new("AES-128", "single block"), &ciphertext_128, |b, ct| {
        b.iter(|| {
            let mut block = *ct;
            Aes128::decrypt_block_in_place(black_box(&expanded_key_128), black_box(&mut block));
            black_box(block);
        });
    });

    // AES-192 decryption
    let key_192 = [0u8; 24];
    let expanded_key_192 = AesExpandedKey::new(&key_192);
    let mut ciphertext_192 = plaintext;
    Aes192::encrypt_block_in_place(&expanded_key_192, &mut ciphertext_192);

    group.bench_with_input(BenchmarkId::new("AES-192", "single block"), &ciphertext_192, |b, ct| {
        b.iter(|| {
            let mut block: [u8; 16] = *ct;
            Aes192::decrypt_block_in_place(black_box(&expanded_key_192), black_box(&mut block));
            black_box(block);
        });
    });

    // AES-256 decryption
    let key_256 = [0u8; 32];
    let expanded_key_256 = AesExpandedKey::new(&key_256);
    let mut ciphertext_256 = plaintext;
    Aes256::encrypt_block_in_place(&expanded_key_256, &mut ciphertext_256);

    group.bench_with_input(BenchmarkId::new("AES-256", "single block"), &ciphertext_256, |b, ct| {
        b.iter(|| {
            let mut block = *ct;
            Aes256::decrypt_block_in_place(black_box(&expanded_key_256), black_box(&mut block));
            black_box(block);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_key_expansion, bench_encryption, bench_decryption);
criterion_main!(benches);

