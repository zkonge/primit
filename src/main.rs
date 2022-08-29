#![feature(slice_as_chunks)]

use primit::{
    aead::{chacha20poly1305::Chacha20Poly1305, Aead, Encryptor},
    ec::{p256::P256, ECDHE},
    hash::{md5::md5, sha256::sha256},
    rng::cprng::FastRng,
};

extern "C" {
    fn exit(_: i32);
}
fn main() {
    let mut res = sha256(b"haha");
    let cp = Chacha20Poly1305::new(&res);
    let mut enc = cp.encryptor(&res[..12].try_into().unwrap(), b"");
    enc.encrypt(&mut res);
    let mut rng = FastRng::new_from_system();
    let sk = P256::new(&mut rng);
    let data = sk.exchange(&sk.to_public()).unwrap_or([0u8; 32]);
    let ret = md5(&data).iter().fold(0, |acc, x| acc ^ (*x as i32));
    unsafe { exit(ret) };
}
