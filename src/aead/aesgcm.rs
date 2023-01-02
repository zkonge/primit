use super::{Aead, Decryptor, Encryptor};
use crate::{
    error::AeadError,
    mac::{ghash::GHash, Mac},
    symmetry::aes::AES128,
    utils::xor::xor,
};

const KEY_LENGTH: usize = 16;
const BLOCK_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const MAC_LENGTH: usize = 16;

pub struct AESGCMEncryptor {
    cipher: AES128,
    state: [u8; 16],
    mac: GHash,
    ad_length: usize,
    data_length: usize,
}

impl AESGCMEncryptor {
    fn next_key(&mut self) -> [u8; 16] {
        let mut key = self.state;

        // increase counter
        let counter_slice = &mut self.state[12..16];
        let mut count = u32::from_be_bytes(counter_slice.try_into().unwrap());
        count = count.wrapping_add(1);
        counter_slice.copy_from_slice(&count.to_be_bytes());

        self.cipher.encrypt(&mut key);
        key
    }
}

impl Encryptor for AESGCMEncryptor {
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn encrypt(&mut self, data: &mut [u8; Self::BLOCK_LENGTH]) {
        xor(data, &self.next_key());
        self.mac.update(data);
        self.data_length += data.len();
    }

    fn finalize(mut self, remainder: &mut [u8]) -> [u8; Self::MAC_LENGTH] {
        let (blocks, remainder) = remainder.as_chunks_mut();
        for block in blocks {
            self.encrypt(block);
        }

        if !remainder.is_empty() {
            self.data_length += remainder.len();
            xor(remainder, &self.next_key());
            let mut buffer = [0u8; 16];
            buffer[..remainder.len()].copy_from_slice(remainder);

            self.mac.update(&buffer);
        }

        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(self.ad_length * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(self.data_length * 8).to_be_bytes());
        self.mac.update(&len_block);

        let mut head_block = self.state;
        // NIST SP800-38D
        head_block[12..16].copy_from_slice(&[0, 0, 0, 1]);

        self.cipher.encrypt(&mut head_block);
        xor(&mut head_block, &self.mac.finalize(&[]));

        head_block
    }
}

pub struct AESGCMDecryptor {
    cipher: AES128,
    state: [u8; 16],
    mac: GHash,
    ad_length: usize,
    data_length: usize,
}

impl AESGCMDecryptor {
    fn next_key(&mut self) -> [u8; 16] {
        let mut key = self.state;

        // increase counter
        let counter_slice = &mut self.state[12..16];
        let mut count = u32::from_be_bytes(counter_slice.try_into().unwrap());
        count = count.wrapping_add(1);
        counter_slice.copy_from_slice(&count.to_be_bytes());

        self.cipher.encrypt(&mut key);
        key
    }
}

impl Decryptor for AESGCMDecryptor {
    const BLOCK_LENGTH: usize = BLOCK_LENGTH;
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn decrypt(&mut self, data: &mut [u8; Self::BLOCK_LENGTH]) {
        self.mac.update(data);
        xor(data, &self.next_key());
        self.data_length += data.len();
    }

    fn finalize(
        mut self,
        remainder: &mut [u8],
        mac: &[u8; Self::MAC_LENGTH],
    ) -> Result<(), AeadError> {
        let (blocks, remainder) = remainder.as_chunks_mut();
        for block in blocks {
            self.decrypt(block);
        }

        if !remainder.is_empty() {
            self.data_length += remainder.len();
            let mut buffer = [0u8; 16];
            buffer[..remainder.len()].copy_from_slice(remainder);
            self.mac.update(&buffer);

            xor(remainder, &self.next_key());
        }

        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(self.ad_length * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(self.data_length * 8).to_be_bytes());
        self.mac.update(&len_block);

        let mut head_block = self.state;
        // NIST SP800-38D
        head_block[12..16].copy_from_slice(&[0, 0, 0, 1]);
        self.cipher.encrypt(&mut head_block);

        xor(&mut head_block, &self.mac.finalize(&[]));

        if mac == &head_block {
            Ok(())
        } else {
            Err(AeadError::BadMac)
        }
    }
}

pub struct AESGCM(AES128);

impl Aead for AESGCM {
    const KEY_LENGTH: usize = KEY_LENGTH;
    const NONCE_LENGTH: usize = NONCE_LENGTH;

    type Encryptor = AESGCMEncryptor;
    type Decryptor = AESGCMDecryptor;

    fn new(key: &[u8; Self::KEY_LENGTH]) -> Self {
        Self(AES128::new(key))
    }

    fn encryptor(&self, nonce: &[u8; Self::NONCE_LENGTH], ad: &[u8]) -> Self::Encryptor {
        let mut ghash_key = [0u8; 16];
        self.0.encrypt(&mut ghash_key);

        let mut mac = GHash::new(&ghash_key);

        let mut state = [0u8; 16];
        state[..NONCE_LENGTH].copy_from_slice(nonce);

        // apply ad
        let (ad_blocks, ad_remainder) = ad.as_chunks();
        for block in ad_blocks {
            mac.update(block);
        }
        if !ad_remainder.is_empty() {
            let mut buffer = [0u8; 16];
            buffer[..ad_remainder.len()].copy_from_slice(ad_remainder);
            mac.update(&buffer);
        }

        state[15] = 2;

        AESGCMEncryptor {
            cipher: self.0,
            state,
            mac,
            ad_length: ad.len(),
            data_length: 0,
        }
    }

    fn decryptor(&self, nonce: &[u8; Self::NONCE_LENGTH], ad: &[u8]) -> Self::Decryptor {
        let encryptor = self.encryptor(nonce, ad);
        AESGCMDecryptor {
            cipher: self.0,
            state: encryptor.state,
            mac: encryptor.mac,
            ad_length: encryptor.ad_length,
            data_length: encryptor.data_length,
        }
    }
}
