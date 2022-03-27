// http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf

use core::mem::size_of;
use core::num::Wrapping;

use super::Compressor;

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

const INIT_VECTOR: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub const COMPRESS_SIZE: usize = 64;
pub const STATE_SIZE: usize = 8;
pub const COUNTER_SIZE: usize = size_of::<u64>();

pub struct SHA256Compressor;

impl Compressor<STATE_SIZE, COMPRESS_SIZE> for SHA256Compressor {
    const INIT_VECTOR: [u32; STATE_SIZE] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const LENGTH: usize = 32;

    fn compress(state: &mut [u32; STATE_SIZE], data: &[u8; COMPRESS_SIZE]) {
        let val = state;

        let w = {
            let mut w = [0u32; 64];

            for (output, input) in w.iter_mut().zip(data.as_chunks().0) {
                *output = u32::from_be_bytes(*input);
            }

            for j in 16..64 {
                let wj15 = w[j - 15];
                let sig0 = wj15.rotate_right(7) ^ wj15.rotate_right(18) ^ (wj15 >> 3);

                let wj2 = w[j - 2];
                let sig1 = wj2.rotate_right(17) ^ wj2.rotate_right(19) ^ (wj2 >> 10);
                w[j] =
                    (Wrapping(sig0) + Wrapping(sig1) + Wrapping(w[j - 7]) + Wrapping(w[j - 16])).0;
            }

            w
        };

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = val;

        for j in 0..64 {
            let ch = (e & f) ^ ((!e) & g);
            let maj = (a & b) ^ (a & c) ^ (b & c);

            let sig0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let sig1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);

            let t1 =
                (Wrapping(h) + Wrapping(sig1) + Wrapping(ch) + Wrapping(K[j]) + Wrapping(w[j])).0;

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

        val.iter_mut()
            .zip([a, b, c, d, e, f, g, h])
            .for_each(|(v, x)| *v = v.wrapping_add(x));
    }
}

pub struct SHA256Old {
    state: [u32; STATE_SIZE],
    count: u64,
    buffer: [u8; COMPRESS_SIZE],
    buffer_offset: usize,
}

impl SHA256Old {
    const LENGTH: usize = 32;

    fn new() -> Self {
        Self {
            count: 0,
            buffer: [0u8; COMPRESS_SIZE],
            buffer_offset: 0,
            state: INIT_VECTOR,
        }
    }
    fn update(&mut self, data: &[u8]) {
        let Self {
            count,
            buffer,
            buffer_offset,
            state,
        } = self;

        // deal with previous block
        let data_length = data.len();

        if *buffer_offset + data_length < COMPRESS_SIZE {
            buffer[*buffer_offset..*buffer_offset + data_length].copy_from_slice(data);
            *buffer_offset += data_length;
            *count += data_length as u64;
            return;
        }

        buffer[*buffer_offset..].copy_from_slice(&data[..COMPRESS_SIZE - *buffer_offset]);
        compress(state, buffer);
        *count += COMPRESS_SIZE as u64;

        // process current blocks
        let (chunks, remainder) = data[COMPRESS_SIZE - *buffer_offset..].as_chunks();
        for chunk in chunks {
            compress(state, chunk);
            *count += COMPRESS_SIZE as u64;
        }

        buffer[..remainder.len()].copy_from_slice(remainder);
        *buffer_offset += remainder.len();
    }

    fn digest(mut self) -> [u8; Self::LENGTH] {
        let mut digest = [0u8; Self::LENGTH];

        // padding
        let length = self.count as usize % COMPRESS_SIZE;
        self.buffer[length] = 0x80;

        // not enough space for bit size
        if length < COMPRESS_SIZE - COUNTER_SIZE {
            self.buffer[length + 1..COMPRESS_SIZE - COUNTER_SIZE].fill(0);
        } else {
            compress(&mut self.state, &self.buffer);
            self.buffer.fill(0);
        }

        self.buffer[COMPRESS_SIZE - COUNTER_SIZE..]
            .copy_from_slice(&(self.count * 8).to_be_bytes());

        compress(&mut self.state, &self.buffer);

        for (output, input) in digest.as_chunks_mut().0.iter_mut().zip(self.state) {
            *output = input.to_be_bytes();
        }
        digest
    }
}

fn compress(state: &mut [u32; 8], data: &[u8; COMPRESS_SIZE]) {
    let val = state;

    let w = {
        let mut w = [0u32; 64];

        for (output, input) in w.iter_mut().zip(data.as_chunks().0) {
            *output = u32::from_be_bytes(*input);
        }

        for j in 16..64 {
            let wj15 = w[j - 15];
            let sig0 = wj15.rotate_right(7) ^ wj15.rotate_right(18) ^ (wj15 >> 3);

            let wj2 = w[j - 2];
            let sig1 = wj2.rotate_right(17) ^ wj2.rotate_right(19) ^ (wj2 >> 10);
            w[j] = (Wrapping(sig0) + Wrapping(sig1) + Wrapping(w[j - 7]) + Wrapping(w[j - 16])).0;
        }

        w
    };

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = val;

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

    val.iter_mut()
        .zip([a, b, c, d, e, f, g, h])
        .for_each(|(v, x)| *v = v.wrapping_add(x));
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = SHA256Old::new();
    hasher.update(data);
    hasher.digest()
}

#[cfg(test)]
mod test {
    use test::Bencher;

    use super::sha256;

    #[test]
    fn test_sha256() {
        static ANSWERS: &'static [(&'static [u8], &'static [u8])] = &[
            (
                b"",
                b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55",
            ),
            (
                b"abc",
                b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                b"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1",
            ),
            (
                &[0u8;64],
                b"\xf5\xa5\xfd\x42\xd1\x6a\x20\x30\x27\x98\xef\x6e\xd3\x09\x97\x9b\x43\x00\x3d\x23\x20\xd9\xf0\xe8\xea\x98\x31\xa9\x27\x59\xfb\x4b"
            ),
            (
                &[0u8;1024],
                b"\x5f\x70\xbf\x18\xa0\x86\x00\x70\x16\xe9\x48\xb0\x4a\xed\x3b\x82\x10\x3a\x36\xbe\xa4\x17\x55\xb6\xcd\xdf\xaf\x10\xac\xe3\xc6\xef"
            ),
        ];

        for &(input, expected) in ANSWERS.iter() {
            let computed = sha256(input);
            assert_eq!(expected, &computed);
        }
    }

    const DATA_LENGTH: usize = 1024 * 256;

    #[bench]
    fn bench_rc_sha256(b: &mut Bencher) {
        use sha2::Digest;

        b.bytes = DATA_LENGTH as u64;
        let data = [0u8; DATA_LENGTH];
        b.iter(|| {
            let mut h = sha2::Sha256::new();
            h.update(&data);
            h.finalize();
        });
    }

    #[bench]
    fn bench_ring_sha256(b: &mut Bencher) {
        use ring::digest;

        b.bytes = DATA_LENGTH as u64;
        let data = [0u8; DATA_LENGTH];
        b.iter(|| digest::digest(&digest::SHA256, &data));
    }

    #[bench]
    fn bench_sha256(b: &mut Bencher) {
        b.bytes = DATA_LENGTH as u64;
        let data = [0u8; DATA_LENGTH];
        b.iter(|| sha256(&data));
    }
}
