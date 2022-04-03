#![feature(test)]
#![feature(slice_as_chunks)]

extern crate test;

use test::Bencher;

use primit::cipher::aes::AES128;

#[bench]
fn bench_aes128(b: &mut Bencher) {
    b.bytes = 1024 * 256;
    let mut d = [0u8; 1024 * 256];
    let cp = AES128::new(&[0u8; 16]);
    b.iter(|| {
        for chunk in d.as_chunks_mut::<16>().0 {
            cp.decrypt(chunk)
        }
    });
}
