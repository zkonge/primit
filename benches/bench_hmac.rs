#![feature(test)]

extern crate test;

use primit::mac::hmac::hmac_sha256;
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_hmac_sha256_large(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let k = black_box([233u8; 32]);
    let d = black_box([233u8; DATA_LENGTH]);

    b.iter(|| hmac_sha256(&k, &d));
}

#[bench]
fn bench_hmac_sha256_small(b: &mut Bencher) {
    b.bytes = 32;

    let k = black_box([233u8; 32]);
    let d = black_box([233u8; 32]);

    b.iter(|| hmac_sha256(&k, &d));
}
