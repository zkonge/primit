// RFC1321 https://tools.ietf.org/html/rfc1321

use core::mem::size_of;

use super::Digest;
use crate::utils::endian::{EndianConvertion, LittleEndian};

pub const STATE_SIZE: usize = 4;
pub const COMPRESS_SIZE: usize = 64;
pub const COUNTER_SIZE: usize = size_of::<u64>();

const R: [u8; 64] = [
    0x07, 0x0c, 0x11, 0x16, 0x07, 0x0c, 0x11, 0x16, 0x07, 0x0c, 0x11, 0x16, 0x07, 0x0c, 0x11, 0x16,
    0x05, 0x09, 0x0e, 0x14, 0x05, 0x09, 0x0e, 0x14, 0x05, 0x09, 0x0e, 0x14, 0x05, 0x09, 0x0e, 0x14,
    0x04, 0x0b, 0x10, 0x17, 0x04, 0x0b, 0x10, 0x17, 0x04, 0x0b, 0x10, 0x17, 0x04, 0x0b, 0x10, 0x17,
    0x06, 0x0a, 0x0f, 0x15, 0x06, 0x0a, 0x0f, 0x15, 0x06, 0x0a, 0x0f, 0x15, 0x06, 0x0a, 0x0f, 0x15,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const INIT_VECTOR: [u32; STATE_SIZE] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

#[derive(Debug)]
pub struct MD5 {
    count: u64,
    state: [u32; STATE_SIZE],
}

impl Digest for MD5 {
    const BLOCK_LENGTH: usize = COMPRESS_SIZE;
    const DIGEST_LENGTH: usize = 16;

    fn new() -> Self {
        Self {
            count: 0,
            state: INIT_VECTOR,
        }
    }

    fn update(&mut self, data: &[u8; Self::BLOCK_LENGTH]) {
        let Self { count, state } = self;
        compress(state, data);
        *count += Self::BLOCK_LENGTH as u64;
    }

    fn digest(mut self, remainder: &[u8]) -> [u8; Self::DIGEST_LENGTH] {
        let (aligned_blocks, remainder) = remainder.as_chunks();
        for block in aligned_blocks {
            self.update(block);
        }

        let mut buffer = [0u8; Self::BLOCK_LENGTH];
        buffer[..remainder.len()].copy_from_slice(remainder);

        let Self { mut count, mut state } = self;
        count += remainder.len() as u64;

        let mut result = [0u8; Self::DIGEST_LENGTH];

        // padding
        buffer[remainder.len()] = 0x80;
        buffer[remainder.len() + 1..].fill(0);

        if remainder.len() >= COMPRESS_SIZE - COUNTER_SIZE {
            // not enough space for bit size
            compress(&mut state, &buffer);
            buffer.fill(0);
        }

        buffer[COMPRESS_SIZE - COUNTER_SIZE..].copy_from_slice(&(count * 8).to_le_bytes());

        compress(&mut state, &buffer);

        LittleEndian::to_bytes(&mut result, &state);
        result
    }
}

fn compress(state: &mut [u32; STATE_SIZE], data: &[u8; COMPRESS_SIZE]) {
    let [mut a, mut b, mut c, mut d] = state;
    let mut w = [0u32; COMPRESS_SIZE / 4];
    LittleEndian::from_bytes(&mut w, data);

    for i in 0..64 {
        let (f, g) = match i {
            0..16 => ((b & c) | ((!b) & d), i),
            16..32 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
            32..48 => (b ^ c ^ d, (3 * i + 5) % 16),
            48..64 => (c ^ (b | !d), (7 * i % 16)),
            _ => unreachable!(),
        };
        let temp = d;
        d = c;
        c = b;
        b = (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(w[g]))
            .rotate_left(R[i] as u32)
            .wrapping_add(b);
        a = temp;
    }

    state
        .iter_mut()
        .zip([a, b, c, d])
        .for_each(|(s, x)| *s = s.wrapping_add(x));
}

pub fn md5(input: &[u8]) -> [u8; MD5::DIGEST_LENGTH] {
    MD5::new().digest(input)
}
