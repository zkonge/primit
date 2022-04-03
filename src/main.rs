#![feature(slice_as_chunks)]

use primit::cipher::aes::AES128;

fn main() {
    let mut d = [0u8; 16];
    let cp = AES128::new(&[0u8; 16]);

    cp.encrypt(&mut d);
    println!("{:02x?}", d);
}
