#![feature(slice_as_chunks)]

use std::time::Instant;

use primit::cipher::aes::AES128;

fn main() {
    let mut d = vec![0u8; 1024 * 1024 * 256];
    let cp = AES128::new(&[0u8; 16]);

    let t = Instant::now();

    d.as_chunks_mut().0.iter_mut().for_each(|d| cp.encrypt(d));
    println!("{:?}", t.elapsed());
    // println!("{:02x?}", sha256(&d));
}
