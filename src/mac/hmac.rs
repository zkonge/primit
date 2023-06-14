use crate::{hash::Digest, utils::xor::xor_static};

// Rust trait can not handle assosiated const in generic
// so hmac function returns two array:
// 1. the first array is the hmac result
// 2. the second array is the hmac internal key, you can always ignore it
pub fn hmac<H: Digest>(key: &[u8], message: &[u8]) -> [u8; H::DIGEST_LENGTH]
where
    [(); H::BLOCK_LENGTH]:,
{
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

    let mut i_key_pad = [0x36u8; H::BLOCK_LENGTH];
    xor_static(&mut i_key_pad, &key);

    let i_msg_hash = {
        let mut h = H::new();
        h.update(&i_key_pad);
        h.digest(message)
    };

    let mut o_key_pad = [0x5cu8; H::BLOCK_LENGTH];
    xor_static(&mut o_key_pad, &key);

    let o_msg_hash = {
        let mut h = H::new();
        h.update(&o_key_pad);
        h.digest(&i_msg_hash)
    };

    o_msg_hash
}
