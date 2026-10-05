//! Benchmarks for the Milestone 1 primitives.
//!
//! Run with `cargo bench -p pvault-core`. `cargo test --benches` runs each
//! benchmark once as a smoke test.

use std::hint::black_box;
use std::io;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use pvault_core::crypto::cascade::{self, Expected, StreamHeader, StreamKeys, StreamKind};
use pvault_core::crypto::kdf::{self, Argon2Params, PassphraseKey};
use pvault_core::crypto::mac;
use pvault_core::secrets::{SecretBuf, SecretBytes};

fn stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("cascade");
    for size in [64 * 1024_u64, 10 * 1024 * 1024] {
        let keys = StreamKeys::generate().unwrap();
        let header = StreamHeader {
            kind: StreamKind::Object,
            stream_id: [7; 16],
            context: 0,
            plain_size: size,
        };
        let plaintext = vec![0x5a_u8; usize::try_from(size).unwrap()];
        let mut encrypted = Vec::new();
        cascade::encrypt(&keys, &header, plaintext.as_slice(), &mut encrypted).unwrap();
        let expected = Expected {
            kind: StreamKind::Object,
            stream_id: [7; 16],
            context: 0,
            plain_size: Some(size),
            max_plain_size: u64::MAX,
        };

        group.throughput(Throughput::Bytes(size));
        group.bench_with_input(BenchmarkId::new("encrypt", size), &size, |b, _| {
            b.iter(|| cascade::encrypt(&keys, &header, plaintext.as_slice(), io::sink()).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("decrypt", size), &size, |b, _| {
            b.iter(|| {
                cascade::decrypt(&keys, &expected, encrypted.as_slice(), io::sink()).unwrap()
            });
        });
    }
    group.finish();
}

fn mac_and_hkdf(c: &mut Criterion) {
    let key = [3u8; 32];
    let data = vec![1u8; 1024];
    c.bench_function("hmac_sha512_1kib", |b| {
        b.iter(|| mac::hmac_sha512(black_box(&key), &[black_box(&data)]));
    });
    let master = SecretBytes::<32>::take_from(&mut [9u8; 32]).unwrap();
    c.bench_function("hkdf_sha512_subkey", |b| {
        b.iter(|| kdf::passphrase_subkey(black_box(&master), PassphraseKey::S1Wrap).unwrap());
    });
}

fn argon2id(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id");
    group.sample_size(10);
    let passphrase = SecretBuf::take_from(&mut b"benchmark passphrase words".to_vec());
    let salt = [0u8; 32];
    let minimum = Argon2Params {
        m_kib: Argon2Params::M_KIB_MIN,
        t: 3,
        p: 4,
    };
    group.bench_function("256MiB_t3_p4", |b| {
        b.iter(|| kdf::master_pw(&passphrase, &salt, minimum).unwrap());
    });
    // Defaults for new vaults (spec 7.3). Lanes run one after another: the
    // `parallel` feature would need `rayon`, which is not approved.
    group.bench_function("1GiB_t4_p4_default", |b| {
        b.iter(|| kdf::master_pw(&passphrase, &salt, Argon2Params::DEFAULT).unwrap());
    });
    group.finish();
}

criterion_group!(benches, stream, mac_and_hkdf, argon2id);
criterion_main!(benches);
