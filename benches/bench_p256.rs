#![feature(test)]

extern crate test;

use primit::ec::{p256::P256, ECDH};
use test::{black_box, Bencher};

#[bench]
fn bench_p256(b: &mut Bencher) {
    let sk = black_box(P256::new(&[16u8; 32]));
    let pk = sk.to_public();

    b.iter(|| sk.exchange(&pk));
}
