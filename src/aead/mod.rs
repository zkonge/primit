use crate::error::AeadError;

pub trait Aead {
    const KEY_LENGTH: usize;
    const IV_LENGTH: usize;
    type Encryptor: Encryptor;
    type Decryptor: Decryptor;

    fn new(key: &[u8; Self::KEY_LENGTH]) -> Self;
    fn encryptor(&mut self, iv: &[u8; Self::IV_LENGTH]) -> Self::Encryptor;
    fn decryptor(&mut self, iv: &[u8; Self::IV_LENGTH]) -> Self::Decryptor;
}

pub trait Encryptor {
    const MAC_LENGTH: usize;

    fn encrypt(&mut self, data: &[u8], ad: &[u8]);
    fn finalize(self) -> [u8; Self::MAC_LENGTH];
}
pub trait Decryptor {
    const MAC_LENGTH: usize;

    fn decryptor(&mut self, data: &[u8], ad: &[u8]);
    fn finalize(self, mac: &[u8; Self::MAC_LENGTH]) -> Result<(), AeadError>;
}
