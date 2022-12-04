#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use primit::rng::{cprng::FastRng, Rng};
use test::{black_box, Bencher};

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_fastrng(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;

    let mut rng = FastRng::new_from_seed(&[0u8; 32]);
    let mut d = black_box([0u8; DATA_LENGTH]);

    b.iter(|| {
        rng.fill_bytes(&mut d);
    });
}
