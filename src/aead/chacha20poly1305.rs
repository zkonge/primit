use super::{Aead, Decryptor, Encryptor};
use crate::{
    error::AeadError,
    mac::{poly1305::Poly1305, Mac},
    symmetry::chacha::ChaCha20,
};

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const BLOCK_LENGTH: usize = 64;
const MAC_LENGTH: usize = 16;

pub struct Chacha20Poly1305Encryptor {
    cipher: ChaCha20,
    mac: Poly1305,
    ad_length: usize,
    data_length: usize,
}

impl Encryptor for Chacha20Poly1305Encryptor {
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn encrypt(&mut self, data: &mut [u8; Self::BLOCK_LENGTH]) {
        self.cipher.apply(data);
        for block in data.as_chunks().0 {
            self.mac.update(block);
        }
        self.data_length += data.len();
    }

    fn finalize(mut self, remainder: &mut [u8]) -> [u8; MAC_LENGTH] {
        self.data_length += remainder.len();

        self.cipher.apply(remainder);

        // 16byte block for poly1305
        let (aligned_blocks, remainder) = remainder.as_chunks();
        for block in aligned_blocks {
            self.mac.update(block);
        }

        if remainder.len() != 0 {
            let mut buffer = [0u8; 16];
            buffer[..remainder.len()].copy_from_slice(remainder);
            self.mac.update(&buffer);
        }

        // apply lengthes
        let mut length_buffer = [0u8; 16];
        length_buffer[..8].copy_from_slice(&(self.ad_length as u64).to_le_bytes());
        length_buffer[8..].copy_from_slice(&(self.data_length as u64).to_le_bytes());

        self.mac.finalize(&length_buffer)
    }
}

pub struct Chacha20Poly1305Decryptor {
    cipher: ChaCha20,
    mac: Poly1305,
    ad_length: usize,
    data_length: usize,
}

impl Decryptor for Chacha20Poly1305Decryptor {
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn decrypt(&mut self, data: &mut [u8; Self::BLOCK_LENGTH]) {
        for block in data.as_chunks().0 {
            self.mac.update(block);
        }
        self.cipher.apply(data);
        self.data_length += data.len();
    }

    fn finalize(mut self, remainder: &mut [u8], mac: &[u8; MAC_LENGTH]) -> Result<(), AeadError> {
        self.data_length += remainder.len();

        // 16byte block for poly1305
        let (aligned_blocks, remainder_cipher) = remainder.as_chunks();
        for block in aligned_blocks {
            self.mac.update(block);
        }

        if remainder_cipher.len() != 0 {
            let mut buffer = [0u8; 16];
            buffer[..remainder_cipher.len()].copy_from_slice(remainder_cipher);
            self.mac.update(&buffer);
        }

        // apply lengthes
        let mut length_buffer = [0u8; 16];
        length_buffer[..8].copy_from_slice(&(self.ad_length as u64).to_le_bytes());
        length_buffer[8..].copy_from_slice(&(self.data_length as u64).to_le_bytes());

        self.cipher.apply(remainder);

        if mac == &self.mac.finalize(&length_buffer) {
            Ok(())
        } else {
            Err(AeadError::BadMac)
        }
    }
}

pub struct Chacha20Poly1305([u8; KEY_LENGTH]);

impl Aead for Chacha20Poly1305 {
    const KEY_LENGTH: usize = KEY_LENGTH;
    const NONCE_LENGTH: usize = NONCE_LENGTH;
    type Encryptor = Chacha20Poly1305Encryptor;
    type Decryptor = Chacha20Poly1305Decryptor;

    fn new(key: &[u8; Self::KEY_LENGTH]) -> Self {
        Self(*key)
    }

    fn encryptor(&self, nonce: &[u8; Self::NONCE_LENGTH], ad: &[u8]) -> Self::Encryptor {
        let mut cipher = ChaCha20::new(&self.0, nonce);

        //extract first round stream for poly1305 key
        let mut first_round = [0u8; 64];
        cipher.apply(&mut first_round);
        let mut mac = Poly1305::new(&first_round[..32].try_into().unwrap());

        // apply ad
        let (aligned_blocks, remainder_ad) = ad.as_chunks();
        for block in aligned_blocks {
            mac.update(block);
        }
        if remainder_ad.len() != 0 {
            let mut buffer = [0u8; 16];
            buffer[..remainder_ad.len()].copy_from_slice(remainder_ad);
            mac.update(&buffer);
        }

        Chacha20Poly1305Encryptor {
            cipher,
            mac,
            ad_length: ad.len(),
            data_length: 0,
        }
    }

    fn decryptor(&self, nonce: &[u8; Self::NONCE_LENGTH], ad: &[u8]) -> Self::Decryptor {
        let encryptor = self.encryptor(nonce, ad);
        Chacha20Poly1305Decryptor {
            cipher: encryptor.cipher,
            mac: encryptor.mac,
            ad_length: encryptor.ad_length,
            data_length: encryptor.data_length,
        }
    }
}
