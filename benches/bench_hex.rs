#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::utils::hex::{decode, encode};
use test::Bencher;

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_encode(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;
    let data = [0u8; DATA_LENGTH];
    let mut result = [0u8; DATA_LENGTH * 2];

    b.iter(|| encode(&data, &mut result).unwrap());
}

#[bench]
fn bench_decode(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;
    let data = [0x30u8; DATA_LENGTH * 2];
    let mut result = [0u8; DATA_LENGTH];

    b.iter(|| decode(&data, &mut result).unwrap());
}
