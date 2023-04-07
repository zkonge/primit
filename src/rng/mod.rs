pub mod aes;
pub mod chacha8;

pub trait Rng {
    fn new_from_seed(seed: &[u8; 32]) -> Self;
    fn fill_bytes(&mut self, data: &mut [u8]);
}

#[cfg(feature = "aesni")]
pub type FastRng = aes::Aes128Rng;
#[cfg(not(feature = "aesni"))]
pub type FastRng = chacha8::Chacha8Rng;
