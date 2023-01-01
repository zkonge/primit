use super::{Aead, Decryptor, Encryptor};
use crate::{
    error::AeadError,
    mac::{ghash::GHash, Mac},
    symmetry::aes::AES128,
    utils::xor::xor,
};

const KEY_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const MAC_LENGTH: usize = 16;

pub struct AESGCMEncryptor {
    cipher: AES128,
    head_block: [u8; 16],
    state: [u8; 16],
    keystream_buffer: [u8; 16],
    mac: GHash,
    ad_length: usize,
    data_length: usize,
}

impl AESGCMEncryptor {
    fn next_key(&mut self) -> [u8; 16] {
        // increase counter
        let counter_slice = &mut self.state[12..16];
        let mut count = u32::from_be_bytes(counter_slice.try_into().unwrap());
        count = count.wrapping_add(1);
        counter_slice.copy_from_slice(&count.to_be_bytes());

        let mut key = self.state;
        self.cipher.encrypt(&mut key);
        key
    }
}

impl Encryptor for AESGCMEncryptor {
    const MAC_LENGTH: usize = MAC_LENGTH;
 
    fn encrypt(&mut self, data: &mut [u8]) {
        // leftover keystream
        let key_stream_buffer_offset = self.data_length % 16;
        xor(data, &self.keystream_buffer[key_stream_buffer_offset..]);

        if data.len() < self.keystream_buffer[key_stream_buffer_offset..].len() {
            self.data_length += data.len();
            return;
        }

        // padded data
        let (chunks, remain) = data[16 - key_stream_buffer_offset..].as_chunks_mut::<16>();
        for chunk in chunks {
            xor(chunk, &self.next_key());
        }
        self.keystream_buffer = self.next_key();

        xor(remain, &self.keystream_buffer);
        self.mac.update(data);
        self.data_length += data.len();
    }

    fn finalize(mut self) -> [u8; Self::MAC_LENGTH] {
        let buffer_offset = self.data_length % 16;
        if buffer_offset != 0 {
            self.mac.update(&[0u8; 16][..16 - buffer_offset]);
        }
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(self.ad_length * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(self.data_length * 8).to_be_bytes());
        self.mac.update(&len_block);

        xor(&mut self.head_block, &self.mac.finalize());

        self.head_block
    }
}

pub struct AESGCMDecryptor {
    cipher: AES128,
    head_block: [u8; 16],
    state: [u8; 16],
    keystream_buffer: [u8; 16],
    mac: GHash,
    ad_length: usize,
    data_length: usize,
}

impl AESGCMDecryptor {
    fn next_key(&mut self) -> [u8; 16] {
        // increase counter
        let counter_slice = &mut self.state[12..16];
        let mut count = u32::from_be_bytes(counter_slice.try_into().unwrap());
        count = count.wrapping_add(1);
        counter_slice.copy_from_slice(&count.to_be_bytes());

        let mut key = self.state;
        self.cipher.encrypt(&mut key);
        key
    }
}

impl Decryptor for AESGCMDecryptor {
    const MAC_LENGTH: usize = MAC_LENGTH;

    fn decrypt(&mut self, data: &mut [u8]) {
        self.mac.update(data);

        // leftover keystream
        let key_stream_buffer_offset = self.data_length % 16;
        xor(data, &self.keystream_buffer[key_stream_buffer_offset..]);

        if data.len() < self.keystream_buffer[key_stream_buffer_offset..].len() {
            self.data_length += data.len();
            return;
        }

        // padded data
        let (chunks, remain) = data[16 - key_stream_buffer_offset..].as_chunks_mut::<16>();
        for chunk in chunks {
            xor(chunk, &self.next_key());
        }
        self.keystream_buffer = self.next_key();

        xor(remain, &self.keystream_buffer);
        self.data_length += data.len();
    }

    fn finalize(mut self, mac: &[u8; Self::MAC_LENGTH]) -> Result<(), AeadError> {
        let buffer_offset = self.data_length % 16;
        if buffer_offset != 0 {
            self.mac.update(&[0u8; 16][..16 - buffer_offset]);
        }
        let mut len_block = [0u8; 16];
        len_block[..8].copy_from_slice(&(self.ad_length * 8).to_be_bytes());
        len_block[8..].copy_from_slice(&(self.data_length * 8).to_be_bytes());
        self.mac.update(&len_block);

        xor(&mut self.head_block, &self.mac.finalize());

        if mac == &self.head_block {
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
        // NIST SP800-38D
        state[15] = 1;
        let mut head_block = state;
        self.0.encrypt(&mut head_block);

        // apply ad
        mac.update(ad);
        let left = ad.len() % 16;
        if left != 0 {
            mac.update(&[0u8; 16][..16 - left]);
        }

        state[15] = 2;
        let mut keystream_buffer = state;
        self.0.encrypt(&mut keystream_buffer);

        AESGCMEncryptor {
            cipher: self.0,
            head_block,
            state,
            keystream_buffer,
            mac,
            ad_length: ad.len(),
            data_length: 0,
        }
    }

    fn decryptor(&self, nonce: &[u8; Self::NONCE_LENGTH], ad: &[u8]) -> Self::Decryptor {
        let encryptor = self.encryptor(nonce, ad);
        AESGCMDecryptor {
            cipher: self.0,
            head_block: encryptor.head_block,
            state: encryptor.state,
            keystream_buffer: encryptor.keystream_buffer,
            mac: encryptor.mac,
            ad_length: ad.len(),
            data_length: 0,
        }
    }
}
