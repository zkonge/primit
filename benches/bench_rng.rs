#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::rng::{aes::Aes128Rng, chacha8::Chacha8Rng, Rng};
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_aes128_rng(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut rng = Aes128Rng::new_from_seed(&[0u8; 32]);
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        rng.fill_bytes(&mut d);
    });
}

#[bench]
fn bench_chacha8_rng(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut rng = Chacha8Rng::new_from_seed(&[0u8; 32]);
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        rng.fill_bytes(&mut d);
    });
}
