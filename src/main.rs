#![feature(slice_as_chunks)]

// use std::time::Instant;

use std::time::Instant;

// use primit::{cipher::aes::AES128, mac::ghash::Gf128};
use primit::rng::{cprng::FastRng, Rng};

fn main() {
    // let f = Gf128::from_bytes(&[1u8; 16]);

    // dbg!(Gf128::new(0, 0, 0, 0b1110_0001 << 24).to_bytes());
    // dbg!(f.times_x_reduce().to_bytes());
    let mut a = FastRng::new_from_system();
    let mut data = vec![0u8; 1024 * 1024 * 256];

    let t=Instant::now();
    a.fill_bytes(&mut data);
    dbg!(t.elapsed());

}
