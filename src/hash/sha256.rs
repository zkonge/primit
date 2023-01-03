// http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf

use core::{mem::size_of, num::Wrapping};

use super::Digest;
use crate::utils::endian::{assert_len_mut, BigEndian, EndianConvertion};

pub const STATE_SIZE: usize = 8;
pub const COMPRESS_SIZE: usize = 64;
pub const COUNTER_SIZE: usize = size_of::<u64>();

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const INIT_VECTOR: [u32; STATE_SIZE] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

#[derive(Debug)]
pub struct SHA256 {
    count: u64,
    state: [u32; STATE_SIZE],
    buffer: [u8; COMPRESS_SIZE],
    buffer_offset: usize,
}

impl Digest for SHA256 {
    const LENGTH: usize = 32;

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

        buffer[COMPRESS_SIZE - COUNTER_SIZE..].copy_from_slice(&(count * 8).to_be_bytes());

        compress(&mut state, &buffer);

        BigEndian::to_bytes(&mut result, &state);
        result
    }
}

fn compress(state: &mut [u32; STATE_SIZE], data: &[u8; COMPRESS_SIZE]) {
    let w = {
        let mut w = [0u32; 64];

        BigEndian::from_bytes(assert_len_mut::<16, _>(&mut w[..16]), data);

        for j in 16..64 {
            let wj15 = w[j - 15];
            let sig0 = wj15.rotate_right(7) ^ wj15.rotate_right(18) ^ (wj15 >> 3);

            let wj2 = w[j - 2];
            let sig1 = wj2.rotate_right(17) ^ wj2.rotate_right(19) ^ (wj2 >> 10);
            w[j] = (Wrapping(sig0) + Wrapping(sig1) + Wrapping(w[j - 7]) + Wrapping(w[j - 16])).0;
        }

        w
    };

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;

    for j in 0..64 {
        let ch = (e & f) ^ ((!e) & g);
        let maj = (a & b) ^ (a & c) ^ (b & c);

        let sig0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let sig1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

        let t1 = (Wrapping(h) + Wrapping(sig1) + Wrapping(ch) + Wrapping(K[j]) + Wrapping(w[j])).0;

        let t2 = (Wrapping(sig0) + Wrapping(maj)).0;

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state
        .iter_mut()
        .zip([a, b, c, d, e, f, g, h])
        .for_each(|(v, x)| *v = v.wrapping_add(x));
}

pub fn sha256(data: &[u8]) -> [u8; SHA256::LENGTH] {
    let mut h = SHA256::new();
    h.update(data);
    h.digest()
}
