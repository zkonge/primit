#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use test::{black_box, Bencher};

use primit::aead::{aesgcm::AESGCM, Aead, Decryptor, Encryptor};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_aesgcm_encrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = AESGCM::new(&[0u8; 16]);

    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        let mut dec = alg.encryptor(&[0u8; 12], &[]);
        dec.encrypt(&mut d);
        dec.finalize();
    });
}

#[bench]
fn bench_aesgcm_decrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = AESGCM::new(&[0u8; 16]);

    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        let mut dec = alg.decryptor(&[0u8; 12], &[]);
        dec.decrypt(&mut d);
        dec.finalize(&[0u8; 16]).ok();
    });
}
