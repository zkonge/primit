pub mod ghash;
pub mod hmac;
pub mod poly1305;

pub trait Mac {
    const KEY_LENGTH: usize;
    const BLOCK_LENGTH: usize;
    const MAC_LENGTH: usize;

    fn new(key: &[u8; Self::KEY_LENGTH]) -> Self;
    fn update(&mut self, data: &[u8; Self::BLOCK_LENGTH]);
    fn finalize(self, remainder: &[u8]) -> [u8; Self::MAC_LENGTH];
}
