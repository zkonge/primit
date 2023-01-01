use crate::{
    hash::{sha256::SHA256, Digest},
    utils::xor::xor,
};

// Rust trait can not handle assosiated const in generic
// so hmac function returns two array:
// 1. the first array is the hmac result
// 2. the second array is the hmac internal key, you can always ignore it
pub fn hmac<H: Digest>(
    key: &[u8],
    message: &[u8],
) -> ([u8; H::DIGEST_LENGTH], [u8; H::BLOCK_LENGTH]) {
    let key = if key.len() > H::BLOCK_LENGTH {
        let mut k = [0u8; H::BLOCK_LENGTH];
        k[..H::BLOCK_LENGTH].copy_from_slice(&H::new().digest(key));
        k
    } else {
        let mut k = [0u8; H::BLOCK_LENGTH];
        // TODO: digest length larger than block size (wtf?)
        k[..key.len()].copy_from_slice(key);
        k
    };

    let mut o_key_pad = [0x5cu8; H::BLOCK_LENGTH];
    let mut i_key_pad = [0x36u8; H::BLOCK_LENGTH];
    xor(&mut o_key_pad, &key);
    xor(&mut i_key_pad, &key);

    let i_msg_hash = {
        let mut h = H::new();
        h.update(&i_key_pad);
        h.digest(message)
    };

    let mut h = H::new();
    h.update(&o_key_pad);
    (h.digest(&i_msg_hash), key)
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; SHA256::DIGEST_LENGTH] {
    hmac::<SHA256>(key, message).0
}
