use core::{
    num::Wrapping,
    ops::{Add, Mul},
};

use super::Mac;

fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;

    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

pub struct GHash(Polyval);

impl Mac for GHash {
    const KEY_LENGTH: usize = 16;
    const MAC_LENGTH: usize = 16;

    fn new(h: &[u8; 16]) -> Self {
        let mut h = *h;
        h.reverse();

        GHash(Polyval::new(&mulx(&h)))
    }

    fn update(&mut self, x: &[u8]) {
        debug_assert_eq!(x.len(), 16);
        let x: &mut [u8; 16] = &mut x.try_into().unwrap();
        x.reverse();

        self.0.update(x);
    }

    fn finalize(self) -> [u8; 16] {
        let mut output = self.0.finalize();
        output.reverse();
        output
    }
}

struct Polyval {
    h: U32x4,
    s: U32x4,
}

impl Polyval {
    fn new(h: &[u8; 16]) -> Self {
        Self {
            h: h.into(),
            s: U32x4::default(),
        }
    }
}

impl Polyval {
    fn update(&mut self, x: &[u8; 16]) {
        let x = U32x4::from(x);
        self.s = (self.s + x) * self.h;
    }

    fn finalize(self) -> [u8; 16] {
        let mut block = [0u8; 16];

        for (chunk, i) in block
            .chunks_mut(4)
            .zip(&[self.s.0, self.s.1, self.s.2, self.s.3])
        {
            chunk.copy_from_slice(&i.to_le_bytes());
        }

        block
    }
}

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
struct U32x4(u32, u32, u32, u32);

impl From<&[u8; 16]> for U32x4 {
    fn from(bytes: &[u8; 16]) -> U32x4 {
        U32x4(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            u32::from_le_bytes(bytes[12..].try_into().unwrap()),
        )
    }
}

impl Add for U32x4 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        U32x4(
            self.0 ^ rhs.0,
            self.1 ^ rhs.1,
            self.2 ^ rhs.2,
            self.3 ^ rhs.3,
        )
    }
}

impl Mul for U32x4 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let hw = [self.0, self.1, self.2, self.3];
        let yw = [rhs.0, rhs.1, rhs.2, rhs.3];
        let hwr = [hw[0], hw[1], hw[2], hw[3]].map(u32::reverse_bits);

        let mut a = [0u32; 18];

        a[0] = yw[0];
        a[1] = yw[1];
        a[2] = yw[2];
        a[3] = yw[3];
        a[4] = a[0] ^ a[1];
        a[5] = a[2] ^ a[3];
        a[6] = a[0] ^ a[2];
        a[7] = a[1] ^ a[3];
        a[8] = a[6] ^ a[7];
        a[9] = yw[0].reverse_bits();
        a[10] = yw[1].reverse_bits();
        a[11] = yw[2].reverse_bits();
        a[12] = yw[3].reverse_bits();
        a[13] = a[9] ^ a[10];
        a[14] = a[11] ^ a[12];
        a[15] = a[9] ^ a[11];
        a[16] = a[10] ^ a[12];
        a[17] = a[15] ^ a[16];

        let mut b = [0u32; 18];

        b[0] = hw[0];
        b[1] = hw[1];
        b[2] = hw[2];
        b[3] = hw[3];
        b[4] = b[0] ^ b[1];
        b[5] = b[2] ^ b[3];
        b[6] = b[0] ^ b[2];
        b[7] = b[1] ^ b[3];
        b[8] = b[6] ^ b[7];
        b[9] = hwr[0];
        b[10] = hwr[1];
        b[11] = hwr[2];
        b[12] = hwr[3];
        b[13] = b[9] ^ b[10];
        b[14] = b[11] ^ b[12];
        b[15] = b[9] ^ b[11];
        b[16] = b[10] ^ b[12];
        b[17] = b[15] ^ b[16];

        let mut c = [0u32; 18];

        for i in 0..18 {
            c[i] = bmul32(a[i], b[i]);
        }

        c[4] ^= c[0] ^ c[1];
        c[5] ^= c[2] ^ c[3];
        c[8] ^= c[6] ^ c[7];

        c[13] ^= c[9] ^ c[10];
        c[14] ^= c[11] ^ c[12];
        c[17] ^= c[15] ^ c[16];

        let mut zw = [0u32; 8];

        zw[0] = c[0];
        zw[1] = c[4] ^ c[9].reverse_bits() >> 1;
        zw[2] = c[1] ^ c[0] ^ c[2] ^ c[6] ^ c[13].reverse_bits() >> 1;
        zw[3] = c[4] ^ c[5] ^ c[8] ^ (c[10] ^ c[9] ^ c[11] ^ c[15]).reverse_bits() >> 1;
        zw[4] = c[2] ^ c[1] ^ c[3] ^ c[7] ^ (c[13] ^ c[14] ^ c[17]).reverse_bits() >> 1;
        zw[5] = c[5] ^ (c[11] ^ c[10] ^ c[12] ^ c[16]).reverse_bits() >> 1;
        zw[6] = c[3] ^ c[14].reverse_bits() >> 1;
        zw[7] = c[12].reverse_bits() >> 1;

        for i in 0..4 {
            let lw = zw[i];
            zw[i + 4] ^= lw ^ (lw >> 1) ^ (lw >> 2) ^ (lw >> 7);
            zw[i + 3] ^= (lw << 31) ^ (lw << 30) ^ (lw << 25);
        }

        U32x4(zw[4], zw[5], zw[6], zw[7])
    }
}

fn bmul32(x: u32, y: u32) -> u32 {
    let x0 = Wrapping(x & 0x1111_1111);
    let x1 = Wrapping(x & 0x2222_2222);
    let x2 = Wrapping(x & 0x4444_4444);
    let x3 = Wrapping(x & 0x8888_8888);
    let y0 = Wrapping(y & 0x1111_1111);
    let y1 = Wrapping(y & 0x2222_2222);
    let y2 = Wrapping(y & 0x4444_4444);
    let y3 = Wrapping(y & 0x8888_8888);

    let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
    let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
    let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
    let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

    z0 &= 0x1111_1111;
    z1 &= 0x2222_2222;
    z2 &= 0x4444_4444;
    z3 &= 0x8888_8888;

    z0 | z1 | z2 | z3
}

pub fn ghash(key: &[u8; 16], msg: &[[u8; 16]]) -> [u8; 16] {
    let mut ghash = GHash::new(key);
    for chunk in msg {
        ghash.update(chunk);
    }
    ghash.finalize()
}
