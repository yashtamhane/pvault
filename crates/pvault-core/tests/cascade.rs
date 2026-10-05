//! Chunked stream format (spec Section 7.7): round trips and rejection of
//! damaged or mismatched streams.

use proptest::prelude::*;
use pvault_core::Error;
use pvault_core::crypto::cascade::{
    self, CHUNK_SIZE, Expected, HEADER_LEN, StreamHeader, StreamKeys, StreamKind,
};

const KIB_64: u64 = CHUNK_SIZE as u64;

fn header(kind: StreamKind, plain_size: u64) -> StreamHeader {
    StreamHeader {
        kind,
        stream_id: [0x42; 16],
        context: if kind == StreamKind::KeyTable { 9 } else { 0 },
        plain_size,
    }
}

fn expected_for(h: &StreamHeader) -> Expected {
    Expected {
        kind: h.kind,
        stream_id: h.stream_id,
        context: h.context,
        plain_size: Some(h.plain_size),
        max_plain_size: u64::MAX,
    }
}

fn plaintext(size: u64) -> Vec<u8> {
    (0..size)
        .map(|i| (i.wrapping_mul(131) >> 3) as u8)
        .collect()
}

fn seal(keys: &StreamKeys, h: &StreamHeader, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    cascade::encrypt(keys, h, data, &mut out).unwrap();
    out
}

fn open(keys: &StreamKeys, expected: &Expected, stream: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    cascade::decrypt(keys, expected, stream, &mut out).map(|_| out)
}

/// Byte offset of record `i` in a stream whose earlier chunks are all full.
fn record_offset(i: usize) -> usize {
    HEADER_LEN + i * (4 + 24 + 12 + CHUNK_SIZE + 16 + 16)
}

#[test]
fn round_trips_at_the_acceptance_sizes() {
    let keys = StreamKeys::generate().unwrap();
    for kind in [StreamKind::Object, StreamKind::KeyTable] {
        for size in [0, 1, KIB_64, KIB_64 + 1, 10 * 1024 * 1024] {
            let h = header(kind, size);
            let data = plaintext(size);
            let stream = seal(&keys, &h, &data);
            assert_eq!(stream.len() as u64, h.encoded_len(), "{kind:?} {size}");
            assert_eq!(
                open(&keys, &expected_for(&h), &stream).unwrap(),
                data,
                "{kind:?} {size}"
            );
        }
    }
}

#[test]
fn every_encryption_uses_fresh_nonces() {
    let keys = StreamKeys::generate().unwrap();
    let h = header(StreamKind::Object, 100);
    let data = plaintext(100);
    assert_ne!(seal(&keys, &h, &data), seal(&keys, &h, &data));
}

#[test]
fn any_flipped_byte_is_rejected() {
    let keys = StreamKeys::generate().unwrap();
    let h = header(StreamKind::Object, 300);
    let stream = seal(&keys, &h, &plaintext(300));
    for at in 0..stream.len() {
        let mut damaged = stream.clone();
        damaged[at] ^= 0x01;
        assert!(
            matches!(open(&keys, &expected_for(&h), &damaged), Err(Error::Stream)),
            "flip at {at}"
        );
    }
}

#[test]
fn wrong_keys_are_rejected() {
    let h = header(StreamKind::Object, 10);
    let stream = seal(&StreamKeys::generate().unwrap(), &h, &plaintext(10));
    let other = StreamKeys::generate().unwrap();
    assert!(matches!(
        open(&other, &expected_for(&h), &stream),
        Err(Error::Stream)
    ));
}

#[test]
fn mismatched_expectations_are_rejected() {
    let keys = StreamKeys::generate().unwrap();
    let h = header(StreamKind::KeyTable, 50);
    let stream = seal(&keys, &h, &plaintext(50));
    let good = expected_for(&h);
    for expected in [
        Expected {
            kind: StreamKind::Object,
            ..good
        },
        Expected {
            stream_id: [0x43; 16],
            ..good
        },
        Expected {
            context: 10,
            ..good
        },
        Expected {
            plain_size: Some(49),
            ..good
        },
        Expected {
            plain_size: None,
            max_plain_size: 49,
            ..good
        },
    ] {
        assert!(matches!(
            open(&keys, &expected, &stream),
            Err(Error::Stream)
        ));
    }
    let unknown_size = Expected {
        plain_size: None,
        max_plain_size: 50,
        ..good
    };
    assert_eq!(open(&keys, &unknown_size, &stream).unwrap(), plaintext(50));
}

#[test]
fn truncation_and_trailing_bytes_are_rejected() {
    let keys = StreamKeys::generate().unwrap();
    let h = header(StreamKind::Object, KIB_64 + 1);
    let stream = seal(&keys, &h, &plaintext(KIB_64 + 1));
    let expected = expected_for(&h);
    for cut in [0, 1, HEADER_LEN, record_offset(1), stream.len() - 1] {
        assert!(
            matches!(open(&keys, &expected, &stream[..cut]), Err(Error::Stream)),
            "cut {cut}"
        );
    }
    let mut longer = stream.clone();
    longer.push(0);
    assert!(matches!(
        open(&keys, &expected, &longer),
        Err(Error::Stream)
    ));
}

#[test]
fn reordered_duplicated_and_swapped_chunks_are_rejected() {
    let keys = StreamKeys::generate().unwrap();
    let size = 3 * KIB_64;
    let h = header(StreamKind::Object, size);
    let stream = seal(&keys, &h, &plaintext(size));
    let expected = expected_for(&h);
    let rec = |i: usize| stream[record_offset(i)..record_offset(i + 1)].to_vec();

    let mut reordered = stream[..HEADER_LEN].to_vec();
    for i in [1, 0, 2] {
        reordered.extend(rec(i));
    }
    assert!(matches!(
        open(&keys, &expected, &reordered),
        Err(Error::Stream)
    ));

    let mut duplicated = stream[..HEADER_LEN].to_vec();
    for i in [0, 0, 2] {
        duplicated.extend(rec(i));
    }
    assert!(matches!(
        open(&keys, &expected, &duplicated),
        Err(Error::Stream)
    ));

    // A record from another stream with the same keys and size.
    let other_h = StreamHeader {
        stream_id: [0x99; 16],
        ..h
    };
    let other = seal(&keys, &other_h, &plaintext(size));
    let mut swapped = stream.clone();
    swapped[record_offset(1)..record_offset(2)]
        .copy_from_slice(&other[record_offset(1)..record_offset(2)]);
    assert!(matches!(
        open(&keys, &expected, &swapped),
        Err(Error::Stream)
    ));
}

#[test]
fn record_length_must_be_exact() {
    let keys = StreamKeys::generate().unwrap();
    let h = header(StreamKind::Object, 10);
    let stream = seal(&keys, &h, &plaintext(10));
    for delta in [-1_i64, 1] {
        let mut damaged = stream.clone();
        let at = HEADER_LEN;
        let len = u32::from_be_bytes(damaged[at..at + 4].try_into().unwrap());
        let changed = u32::try_from(i64::from(len) + delta).unwrap();
        damaged[at..at + 4].copy_from_slice(&changed.to_be_bytes());
        assert!(matches!(
            open(&keys, &expected_for(&h), &damaged),
            Err(Error::Stream)
        ));
    }
}

#[test]
fn plaintext_source_must_match_the_declared_size() {
    let keys = StreamKeys::generate().unwrap();
    let h = header(StreamKind::Object, 10);
    let mut sink = Vec::new();
    assert!(matches!(
        cascade::encrypt(&keys, &h, &plaintext(9)[..], &mut sink),
        Err(Error::InputLength)
    ));
    assert!(matches!(
        cascade::encrypt(&keys, &h, &plaintext(11)[..], &mut sink),
        Err(Error::InputLength)
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn arbitrary_sizes_round_trip(size in 0_u64..(3 * KIB_64 + 7), context in any::<u64>()) {
        let keys = StreamKeys::generate().unwrap();
        let h = StreamHeader { context, ..header(StreamKind::KeyTable, size) };
        let data = plaintext(size);
        let stream = seal(&keys, &h, &data);
        prop_assert_eq!(stream.len() as u64, h.encoded_len());
        prop_assert_eq!(open(&keys, &expected_for(&h), &stream).unwrap(), data);
    }
}
