#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::hash::md5::md5;
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_md5(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| md5(&d));
}
