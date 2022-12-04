#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::symmetry::aes::AES128;
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_encrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut d = black_box([0u8; DATA_LENGTH]);
    let cipher = AES128::new(&[0u8; 16]);

    b.iter(|| {
        for chunk in d.as_chunks_mut::<16>().0 {
            cipher.encrypt(chunk)
        }
    });
}

#[bench]
fn bench_decrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut d = black_box([0u8; DATA_LENGTH]);
    let cipher = AES128::new(&[0u8; 16]);

    b.iter(|| {
        for chunk in d.as_chunks_mut::<16>().0 {
            cipher.decrypt(chunk)
        }
    });
}
