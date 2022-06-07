pub mod md5;
pub mod sha256;

// Merkle-Damgård structure

// use crate::util::endian::EndianConvertion;

pub trait Digest {
    const LENGTH: usize;

    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn digest(self) -> [u8; Self::LENGTH];
}

// pub(crate) fn general_update<E, const STATE_SIZE: usize, const COMPRESS_SIZE: usize>(
//     count: &mut u64,
//     state: &mut [u32; STATE_SIZE],
//     buffer: &mut [u8; COMPRESS_SIZE],
//     buffer_offset: &mut usize,
//     compress: fn(&mut [u32; STATE_SIZE], &[u8; COMPRESS_SIZE]),
//     data: &[u8],
// ) where
//     E: EndianConvertion,
// {
//     let data_length = data.len();

//     // process previous block
//     if *buffer_offset + data_length < COMPRESS_SIZE {
//         buffer[*buffer_offset..*buffer_offset + data_length].copy_from_slice(data);
//         *buffer_offset += data_length;
//         *count += data_length as u64;
//         return;
//     }

//     // compress buffer
//     buffer[*buffer_offset..].copy_from_slice(&data[..COMPRESS_SIZE - *buffer_offset]);
//     compress(state, buffer);
//     *count += COMPRESS_SIZE as u64;

//     // process current blocks
//     let (chunks, remain) = data[COMPRESS_SIZE - *buffer_offset..].as_chunks();
//     for chunk in chunks {
//         compress(state, chunk);
//     }
//     *count += COMPRESS_SIZE as u64 * chunks.len() as u64;

//     // move remainder to buffer
//     buffer[..remain.len()].copy_from_slice(remain);
//     *buffer_offset = remain.len();
//     *count += remain.len() as u64;
// }

// pub(crate) fn general_digest<
//     E,
//     const STATE_SIZE: usize,
//     const COMPRESS_SIZE: usize,
//     const LENGTH: usize,
// >(
//     count: u64,
//     mut state: [u32; STATE_SIZE],
//     mut buffer: [u8; COMPRESS_SIZE],
//     buffer_offset: usize,
//     compress: fn(&mut [u32; STATE_SIZE], &[u8; COMPRESS_SIZE]),
// ) -> [u8; LENGTH]
// where
//     E: EndianConvertion,
// {
//     let mut result = [0u8; LENGTH];

//     // padding
//     buffer[buffer_offset] = 0x80;
//     buffer[buffer_offset + 1..].fill(0);

//     if buffer_offset >= COMPRESS_SIZE - 8 {
//         // not enough space for bit size
//         compress(&mut state, &buffer);
//         buffer.fill(0);
//     }

//     buffer[COMPRESS_SIZE - 8..].copy_from_slice(&(count * 8).to_be_bytes());

//     compress(&mut state, &buffer);

//     E::to_bytes(&mut result, &state);
//     result
// }
