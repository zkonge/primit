#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use test::{black_box, Bencher};

use primit::hash::sha256::sha256;

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_sha256(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let data = black_box([0u8; DATA_LENGTH]);

    b.iter(|| sha256(&data));
}
