#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::utils::hex::{decode, encode};
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_encode(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;
    let data = black_box([0u8; DATA_LENGTH]);
    let mut result = black_box([0u8; DATA_LENGTH * 2]);

    b.iter(|| encode(&data, &mut result).unwrap());
}

#[bench]
fn bench_decode(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;
    let data = black_box([0x30u8; DATA_LENGTH * 2]);
    let mut result = black_box([0u8; DATA_LENGTH]);

    b.iter(|| decode(&data, &mut result).unwrap());
}
