// RFC1321 https://tools.ietf.org/html/rfc1321

use core::mem::size_of;

use crate::utils::endian::{EndianConvertion, LittleEndian};

use super::Digest;

pub const STATE_SIZE: usize = 4;
pub const COMPRESS_SIZE: usize = 64;
pub const COUNTER_SIZE: usize = size_of::<u64>();

const R: [u8; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
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

pub struct MD5 {
    count: u64,
    state: [u32; STATE_SIZE],
    buffer: [u8; COMPRESS_SIZE],
    buffer_offset: usize,
}

impl Digest for MD5 {
    const LENGTH: usize = 16;

    fn new() -> Self {
        Self {
            count: 0,
            state: INIT_VECTOR,
            buffer: [0; COMPRESS_SIZE],
            // point to first unused position
            buffer_offset: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        let Self {
            count,
            buffer,
            buffer_offset,
            state,
        } = self;

        let data_length = data.len();

        // process previous block
        if *buffer_offset + data_length < COMPRESS_SIZE {
            buffer[*buffer_offset..*buffer_offset + data_length].copy_from_slice(data);
            *buffer_offset += data_length;
            *count += data_length as u64;
            return;
        }

        // compress buffer
        buffer[*buffer_offset..].copy_from_slice(&data[..COMPRESS_SIZE - *buffer_offset]);
        compress(state, buffer);
        *count += COMPRESS_SIZE as u64;

        // process current blocks
        let (chunks, remain) = data[COMPRESS_SIZE - *buffer_offset..].as_chunks();
        for chunk in chunks {
            compress(state, chunk);
        }
        *count += COMPRESS_SIZE as u64 * chunks.len() as u64;

        // move remainder to buffer
        buffer[..remain.len()].copy_from_slice(remain);
        *buffer_offset = remain.len();
        *count += remain.len() as u64;
    }

    fn digest(self) -> [u8; Self::LENGTH] {
        let Self {
            count,
            mut state,
            mut buffer,
            buffer_offset,
        } = self;

        let mut result = [0u8; Self::LENGTH];

        // padding
        buffer[buffer_offset] = 0x80;
        buffer[buffer_offset + 1..].fill(0);

        if buffer_offset >= COMPRESS_SIZE - COUNTER_SIZE {
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
            .rotate_left(R[i as usize] as u32)
            .wrapping_add(b);
        a = temp;
    }

    state
        .iter_mut()
        .zip([a, b, c, d])
        .for_each(|(s, x)| *s = s.wrapping_add(x));
}

pub fn md5(input: &[u8]) -> [u8; MD5::LENGTH] {
    let mut hasher = MD5::new();
    hasher.update(input);
    hasher.digest()
}

// #[cfg(test)]
// mod tests {
//     use rand::{rngs, Rng, SeedableRng};
//     use test::Bencher;

//     use crate::utils::hex::decode;

//     use super::*;

//     #[test]
//     fn test_md5() {
//         let inputs = [
//             "",
//             "a",
//             "abc",
//             "message digest",
//             "abcdefghijklmnopqrstuvwxyz",
//             "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
//             "0123456789012345678901234567890123456789012345678901234567890123",
//             "1234567890123456789012345678901234567890123456789012345678901234",
//             "12345678901234567890123456789012345678901234567890123456789012345",
//             "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
//         ];
//         let outputs = [
//             "d41d8cd98f00b204e9800998ecf8427e",
//             "0cc175b9c0f1b6a831c399e269772661",
//             "900150983cd24fb0d6963f7d28e17f72",
//             "f96b697d7cb7938d525a2f31aaf161d0",
//             "c3fcd3d76192e4007dfb496cca67e13b",
//             "d174ab98d277d9f5a5611c2c9f419d9f",
//             "7f7bfd348709deeaace19e3f535f8c54",
//             "eb6c4179c0a7c82cc2828c1e6338e165",
//             "823cc889fc7318dd33dde0654a80b70a",
//             "57edf4a22be3c955ac49da2e2107b67a",
//         ];
//         for (input, &output) in inputs.iter().zip(outputs.iter()) {
//             let mut output_bytes = [0u8; MD5::LENGTH];
//             decode(output.as_bytes(), &mut output_bytes).unwrap();

//             let hash = md5(input.as_bytes());

//             assert_eq!(hash, output_bytes);
//         }
//     }

//     #[test]
//     fn test_md5_fuzz() {
//         use md5::Digest;

//         let mut rng = rngs::StdRng::seed_from_u64(0);
//         let mut input = [0u8; 256];
//         for l in 0..input.len() {
//             for _ in 0..50 {
//                 rng.fill(&mut input[..l]);

//                 let mut h = md5::Md5::new();
//                 h.update(&input[..l]);

//                 let output = md5(&input[..l]);

//                 assert_eq!(h.finalize().as_slice(), &output);
//             }
//         }
//     }

//     const DATA_LENGTH: usize = 1024 * 256;

//     #[bench]
//     fn bench_md5(b: &mut Bencher) {
//         b.bytes = DATA_LENGTH as u64;
//         let d = [0u8; DATA_LENGTH];
//         b.iter(|| md5(&d));
//     }

//     #[bench]
//     fn bench_rc_md5(b: &mut Bencher) {
//         use md5::Digest;

//         b.bytes = DATA_LENGTH as u64;
//         let d = [0u8; DATA_LENGTH];
//         b.iter(|| {
//             let mut h = md5::Md5::new();
//             h.update(&d);
//             h.finalize();
//         });
//     }
// }
