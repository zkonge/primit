use crate::error::AeadError;
// pub mod aesgcm;
pub mod chacha20poly1305;

pub trait Aead {
    const KEY_LENGTH: usize;
    const NONCE_LENGTH: usize;
    type Encryptor: Encryptor;
    type Decryptor: Decryptor;

    fn new(key: &[u8; Self::KEY_LENGTH]) -> Self;
    fn encryptor(&self, nonce: &[u8; Self::NONCE_LENGTH], ad: &[u8]) -> Self::Encryptor;
    fn decryptor(&self, nonce: &[u8; Self::NONCE_LENGTH], ad: &[u8]) -> Self::Decryptor;
}

pub trait Encryptor {
    const BLOCK_LENGTH: usize;
    const MAC_LENGTH: usize;

    fn encrypt(&mut self, data: &mut [u8; Self::BLOCK_LENGTH]);
    fn finalize(self, remainder: &mut [u8]) -> [u8; Self::MAC_LENGTH];
}
pub trait Decryptor {
    const BLOCK_LENGTH: usize;
    const MAC_LENGTH: usize;

    fn decrypt(&mut self, data: &mut [u8; Self::BLOCK_LENGTH]);
    fn finalize(self, remainder: &mut [u8], mac: &[u8; Self::MAC_LENGTH]) -> Result<(), AeadError>;
}
