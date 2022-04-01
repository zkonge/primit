use primit::{cipher::chacha20::ChaCha20, utils::hex::encode_fix};

fn main() {
    let mut cp = ChaCha20::new(&[0u8; 32], &[0u8; 12]);
    let mut d = *b"1212112121";
    cp.apply(&mut d);
    println!("{:?}", encode_fix(&d));
}
