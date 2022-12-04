#![feature(test)]

extern crate test;

use primit::mac::poly1305::poly1305;
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_poly1305(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| poly1305(&[0u8; 32], &d));
}
