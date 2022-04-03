#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use test::Bencher;

use primit::hash::md5::md5;

const DATA_LENGTH: usize = 1024 * 256;

#[bench]
fn bench_md5(b: &mut Bencher) {
    b.bytes = DATA_LENGTH as u64;
    let d = [0u8; DATA_LENGTH];
    b.iter(|| md5(&d));
}

#[bench]
fn bench_rc_md5(b: &mut Bencher) {
    use md5::Digest;

    b.bytes = DATA_LENGTH as u64;
    let d = [0u8; DATA_LENGTH];
    b.iter(|| {
        let mut h = md5::Md5::new();
        h.update(&d);
        h.finalize();
    });
}
