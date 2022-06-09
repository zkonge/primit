// pub mod ghash;
pub mod poly1305;

pub trait Mac<const KEY_LENGTH: usize, const MAC_LENGTH: usize> {
    fn new(key: &[u8; KEY_LENGTH]) -> Self;
    fn update(&mut self, data: &[u8]);
    fn finalize(self) -> [u8; MAC_LENGTH];
}
