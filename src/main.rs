use primit::hash::SHA256;

fn main() {
    let a = SHA256::compute(&[0u8; 32]);
    dbg!(a);
}
