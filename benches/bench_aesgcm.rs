#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use aes::cipher::generic_array::GenericArray;
use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Tag};
use primit::aead::{aesgcm::AESGCM, Aead, Decryptor, Encryptor};
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_aesgcm_encrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = black_box(AESGCM::new(&[0u8; 16]));
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        alg.encryptor(&[0u8; 12], &[]).finalize(&mut d);
    });
}

#[bench]
fn bench_aesgcm_decrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = black_box(AESGCM::new(&[0u8; 16]));
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        alg.decryptor(black_box(&[0u8; 12]), black_box(&[]))
            .finalize(&mut d, black_box(&[0u8; 16]))
            .ok();
    });
}
#[bench]
fn bench_std_aesgcm_encrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = black_box(Aes128Gcm::new_from_slice(&[0u8; 16]).unwrap());
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        alg.encrypt_in_place_detached(
            black_box(GenericArray::from_slice(&[0u8; 12])),
            black_box(&[]),
            &mut d,
        )
        .ok();
    });
}

#[bench]
fn bench_std_aesgcm_decrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = black_box(Aes128Gcm::new_from_slice(&[0u8; 16]).unwrap());
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        alg.decrypt_in_place_detached(
            black_box(GenericArray::from_slice(&[0u8; 12])),
            black_box(&[]),
            &mut d,
            Tag::from_slice(&[0u8; 16]),
        )
        .ok();
    });
}
