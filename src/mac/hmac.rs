use crate::{
    hash::{
        sha256::{sha256, SHA256},
        Digest,
    },
    utils::xor::xor,
};

// Rust trait can not handle assosiated const in generic
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256::LENGTH] {
    let key = if key.len() > SHA256::LENGTH {
        sha256(key)
    } else {
        let mut k = [0u8; SHA256::LENGTH];
        k[..key.len()].copy_from_slice(key);
        k
    };

    let mut i_msg = [0x36u8; SHA256::LENGTH];
    let mut o_msg = [0x5cu8; SHA256::LENGTH];
    xor(&mut i_msg, &key);
    xor(&mut o_msg, &key);

    let mut h=SHA256::new();
    h.update(&i_msg);
    h.update(message);

    let h_i = sha256(&h.digest());

    let mut h=SHA256::new();
    h.update(&o_msg);
    h.update(&h_i);
    h.digest()
}
