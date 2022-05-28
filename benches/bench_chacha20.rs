#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::cipher::chacha::ChaCha20;
use test::Bencher;

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_rc_chacha20(b: &mut Bencher) {
    use chacha20::cipher::{KeyIvInit, StreamCipher};
    use chacha20::ChaCha20;

    b.bytes = DATA_LENGTH as u64;

    let mut cp = ChaCha20::new(&[0u8; 32].into(), &[0u8; 12].into());
    let mut d = [0u8; DATA_LENGTH];
    b.iter(|| cp.apply_keystream(&mut d));
}

#[bench]
fn bench_chacha20(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut cp = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
    let mut d = [0u8; DATA_LENGTH];
    b.iter(|| cp.apply(&mut d));
}
