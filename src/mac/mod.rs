pub mod ghash;
pub mod poly1305;
pub mod hmac;

pub trait Mac {
    const KEY_LENGTH: usize;
    const MAC_LENGTH: usize;

    fn new(key: &[u8; Self::KEY_LENGTH]) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; Self::MAC_LENGTH];
}
