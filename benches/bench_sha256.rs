#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use test::Bencher;

use primit::hash::sha256::sha256;

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_rc_sha256(b: &mut Bencher) {
    use sha2::Digest;

    b.bytes = DATA_LENGTH as u64;
    let data = [0u8; DATA_LENGTH];
    b.iter(|| {
        let mut h = sha2::Sha256::new();
        h.update(&data);
        h.finalize();
    });
}

#[bench]
fn bench_sha256(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;
    let data = [0u8; DATA_LENGTH];
    b.iter(|| sha256(&data));
}
