use super::{Aead, Decryptor, Encryptor};
use crate::{
    error::AeadError,
    mac::{poly1305::Poly1305, Mac},
    symmetry::chacha::ChaCha20,
};

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const MAC_LENGTH: usize = 16;

pub struct Chacha20Poly1305Encryptor {
    cipher: ChaCha20,
    mac: Poly1305,
    ad_length: usize,
    data_length: usize,
}

impl Encryptor for Chacha20Poly1305Encryptor {
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn encrypt(&mut self, data: &mut [u8]) {
        self.cipher.apply(data);
        self.mac.update(data);
        self.data_length += data.len();
    }

    fn finalize(mut self) -> [u8; MAC_LENGTH] {
        let left = self.data_length % 16;
        if left != 0 {
            self.mac.update(&[0u8; 16][..16 - left]);
        }
        // apply lengthes
        self.mac.update(&(self.ad_length as u64).to_le_bytes());
        self.mac.update(&(self.data_length as u64).to_le_bytes());

        self.mac.finalize()
    }
}

pub struct Chacha20Poly1305Decryptor {
    cipher: ChaCha20,
    mac: Poly1305,
    ad_length: usize,
    data_length: usize,
}

impl Decryptor for Chacha20Poly1305Decryptor {
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn decrypt(&mut self, data: &mut [u8]) {
        self.mac.update(data);
        self.cipher.apply(data);
        self.data_length += data.len();
    }

    fn finalize(mut self, mac: &[u8; MAC_LENGTH]) -> Result<(), AeadError> {
        let left = self.data_length % 16;
        if left != 0 {
            self.mac.update(&[0u8; 16][..16 - left]);
        }
        // apply lengthes
        self.mac.update(&(self.ad_length as u64).to_le_bytes());
        self.mac.update(&(self.data_length as u64).to_le_bytes());

        if mac == &self.mac.finalize() {
            Ok(())
        } else {
            Err(AeadError::InvalidMac)
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
        mac.update(ad);
        let left = ad.len() % 16;
        if left != 0 {
            mac.update(&[0u8; 16][..16 - left]);
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
