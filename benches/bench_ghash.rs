#![feature(slice_as_chunks)]
#![feature(test)]

extern crate test;

use test::{black_box, Bencher};

use primit::mac::ghash::ghash;

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_ghash(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| ghash(&[0u8; 16], &mut d.as_chunks().0));
}
