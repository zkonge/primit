#![feature(test)]

extern crate test;

use test::{black_box, Bencher};

use primit::mac::poly1305::poly1305;

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_poly1305(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| poly1305(&[0u8; 32], &mut d));
}
