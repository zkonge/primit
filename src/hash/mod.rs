use core::marker::PhantomData;

use self::sha256::SHA256Compressor;

pub mod md5;
pub mod sha256;

//Merkle-Damgård structure
pub trait Compressor<const STATE_SIZE: usize, const COMPRESS_SIZE: usize> {
    const INIT_VECTOR: [u32; STATE_SIZE];
    const LENGTH: usize;
    fn compress(state: &mut [u32; STATE_SIZE], data: &[u8; COMPRESS_SIZE]);
}

pub struct MDHash<
    const STATE_SIZE: usize,
    const COMPRESS_SIZE: usize,
    C: Compressor<STATE_SIZE, COMPRESS_SIZE>,
> {
    count: u64,
    state: [u32; STATE_SIZE],
    buffer: [u8; COMPRESS_SIZE],
    buffer_offset: usize,
    _p: PhantomData<C>,
}

impl<const SS: usize, const CS: usize, C: Compressor<SS, CS>> MDHash<SS, CS, C> {
    pub fn new() -> Self {
        Self {
            count: 0,
            state: C::INIT_VECTOR,
            buffer: [0; CS],
            buffer_offset: 0,
            _p: PhantomData,
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        let Self {
            count,
            buffer,
            buffer_offset,
            state,
            ..
        } = self;

        // deal with previous block
        let data_length = data.len();

        if *buffer_offset + data_length < CS {
            buffer[*buffer_offset..*buffer_offset + data_length].copy_from_slice(data);
            *buffer_offset += data_length;
            *count += data_length as u64;
            return;
        }

        buffer[*buffer_offset..].copy_from_slice(&data[..CS - *buffer_offset]);
        C::compress(state, buffer);
        *count += CS as u64;

        // process current blocks
        let (chunks, remainder) = data[CS - *buffer_offset..].as_chunks();
        for chunk in chunks {
            C::compress(state, chunk);
            *count += CS as u64;
        }

        buffer[..remainder.len()].copy_from_slice(remainder);
        *buffer_offset += remainder.len();
    }
    pub fn digest(mut self) -> [u8; C::LENGTH] {
        let mut digest = [0u8; C::LENGTH];

        // padding
        let length = self.count as usize % CS;
        self.buffer[length] = 0x80;

        // not enough space for bit size
        if length < CS - 8 {
            self.buffer[length + 1..CS - 8].fill(0);
        } else {
            C::compress(&mut self.state, &self.buffer);
            self.buffer.fill(0);
        }

        self.buffer[CS - 8..].copy_from_slice(&(self.count * 8).to_be_bytes());

        C::compress(&mut self.state, &self.buffer);

        for (output, input) in digest.as_chunks_mut().0.iter_mut().zip(self.state) {
            *output = input.to_be_bytes();
        }
        digest
    }

    pub fn compute(data: &[u8]) -> [u8; C::LENGTH] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.digest()
    }
}

pub type SHA256 = MDHash<{ sha256::STATE_SIZE }, { sha256::COMPRESS_SIZE }, SHA256Compressor>;
