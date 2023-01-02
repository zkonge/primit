#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::aead::{chacha20poly1305::Chacha20Poly1305, Aead, Decryptor, Encryptor};
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_chacha20pyly1305_encrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = Chacha20Poly1305::new(&[0u8; 32]);

    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        let enc = alg.encryptor(&[0u8; 12], &[]);
        enc.finalize(&mut d);
    });
}

#[bench]
fn bench_chacha20pyly1305_decrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let alg = Chacha20Poly1305::new(&[0u8; 32]);

    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        let dec = alg.decryptor(&[0u8; 12], &[]);
        dec.finalize(&mut d, &[0u8; 16]).ok()
    });
}

#[bench]
fn bench_std_chacha20pyly1305_decrypt(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;
    use chacha20poly1305::{
        aead::{AeadCore, AeadInPlace, KeyInit, OsRng},
        ChaCha20Poly1305,
    };

    let alg = ChaCha20Poly1305::new_from_slice(&[0u8; 32]).unwrap();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        alg.encrypt_in_place_detached(&nonce, b"", &mut d).ok();
    });
}
