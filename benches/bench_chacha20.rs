#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::symmetry::chacha::ChaCha20;
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_chacha20(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut cipher = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| cipher.apply(&mut d));
}
