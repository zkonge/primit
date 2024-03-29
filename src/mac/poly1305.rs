// https://cr.yp.to/mac/poly1305-20050329.pdf
// https://github.com/floodyberry/poly1305-donna

use super::Mac;
use crate::utils::endian::{assert_len, EndianConvertion, LittleEndian};

#[derive(Debug, Default)]
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Mac for Poly1305 {
    const KEY_LENGTH: usize = 32;
    const BLOCK_LENGTH: usize = 16;
    const MAC_LENGTH: usize = 16;

    fn new(key: &[u8; 32]) -> Self {
        let mut p = Poly1305::default();

        // r &= 0xffffffc0ffffffc0ffffffc0fffffff
        p.r[0] = (u32::from_le_bytes(key[..4].try_into().unwrap())) & 0x3ff_ffff;
        p.r[1] = (u32::from_le_bytes(key[3..7].try_into().unwrap()) >> 2) & 0x3ff_ff03;
        p.r[2] = (u32::from_le_bytes(key[6..10].try_into().unwrap()) >> 4) & 0x3ff_c0ff;
        p.r[3] = (u32::from_le_bytes(key[9..13].try_into().unwrap()) >> 6) & 0x3f0_3fff;
        p.r[4] = (u32::from_le_bytes(key[12..16].try_into().unwrap()) >> 8) & 0x00f_ffff;

        LittleEndian::from_bytes(&mut p.pad, assert_len(&key[16..32]));

        p
    }

    fn update(&mut self, data: &[u8; Self::BLOCK_LENGTH]) {
        compress(self, data);
    }

    fn finalize(mut self, remainder: &[u8]) -> [u8; 16] {
        let (aligned_blocks, remainder) = remainder.as_chunks();
        for block in aligned_blocks {
            self.update(block);
        }

        if !remainder.is_empty() {
            let mut buffer = [0u8; Self::BLOCK_LENGTH];
            buffer[..remainder.len()].copy_from_slice(remainder);
            compress(&mut self, &buffer);
        }

        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;

        // fully carry h
        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;

        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;

        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;

        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;

        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        // compute h + -p
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;

        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;

        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;

        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;

        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // select h if h < p, or h + -p if h >= p
        if g4 >> 31 == 0 {
            [h0, h1, h2, h3, h4] = [g0, g1, g2, g3, g4]
        }

        // h = h % (2^128)
        h0 |= h1 << 26;
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        // h = mac = (h + pad) % (2^128)
        let mut f: u64;
        f = u64::from(h0) + u64::from(self.pad[0]);
        h0 = f as u32;

        f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
        h1 = f as u32;

        f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
        h2 = f as u32;

        f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
        h3 = f as u32;

        let mut r = [0u8; 16];
        LittleEndian::to_bytes(&mut r, &[h0, h1, h2, h3]);
        r
    }
}

fn compress(state: &mut Poly1305, data: &[u8; Poly1305::BLOCK_LENGTH]) {
    let [r0, r1, r2, r3, r4] = state.r.map(Into::<u64>::into);
    let [mut h0, mut h1, mut h2, mut h3, mut h4] = state.h;
    let [s1, s2, s3, s4] = [r1, r2, r3, r4].map(|x| x * 5);

    // h += m
    h0 += (u32::from_le_bytes(data[0..4].try_into().unwrap())) & 0x3ff_ffff;
    h1 += (u32::from_le_bytes(data[3..7].try_into().unwrap()) >> 2) & 0x3ff_ffff;
    h2 += (u32::from_le_bytes(data[6..10].try_into().unwrap()) >> 4) & 0x3ff_ffff;
    h3 += (u32::from_le_bytes(data[9..13].try_into().unwrap()) >> 6) & 0x3ff_ffff;
    h4 += (u32::from_le_bytes(data[12..16].try_into().unwrap()) >> 8) | 0x100_0000;

    let [h0, h1, h2, h3, h4] = [h0, h1, h2, h3, h4].map(Into::<u64>::into);
    // h *= r
    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

    let (mut h0, mut h1, h2, h3, h4);

    // (partial) h %= p
    let mut c: u32;
    c = (d0 >> 26) as u32;
    h0 = d0 as u32 & 0x3ff_ffff;
    d1 += c as u64;

    c = (d1 >> 26) as u32;
    h1 = d1 as u32 & 0x3ff_ffff;
    d2 += c as u64;

    c = (d2 >> 26) as u32;
    h2 = d2 as u32 & 0x3ff_ffff;
    d3 += c as u64;

    c = (d3 >> 26) as u32;
    h3 = d3 as u32 & 0x3ff_ffff;
    d4 += c as u64;

    c = (d4 >> 26) as u32;
    h4 = d4 as u32 & 0x3ff_ffff;
    h0 += c * 5;

    c = h0 >> 26;
    h0 &= 0x3ff_ffff;
    h1 += c;

    state.h = [h0, h1, h2, h3, h4];
}

pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    Poly1305::new(key).finalize(msg)
}
