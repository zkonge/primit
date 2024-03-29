use core::arch::x86_64::{
    __m128i, _mm_clmulepi64_si128, _mm_loadu_si128, _mm_setzero_si128, _mm_shuffle_epi32,
    _mm_slli_epi64, _mm_srli_epi64, _mm_storeu_si128, _mm_unpacklo_epi64, _mm_xor_si128,
};

use crate::mac::Mac;

fn mulx(block: &[u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(*block);
    let v_hi = v >> 127;

    v <<= 1;
    v ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    v.to_le_bytes()
}

pub struct GHash {
    core: Polyval,
}

impl Mac for GHash {
    const KEY_LENGTH: usize = 16;
    const BLOCK_LENGTH: usize = 16;
    const MAC_LENGTH: usize = 16;

    fn new(h: &[u8; 16]) -> Self {
        let mut h = *h;
        h.reverse();

        GHash {
            core: Polyval::new(&mulx(&h)),
        }
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
        let mut output = self.core.finalize();
        output.reverse();
        output
    }
}

fn compress(state: &mut GHash, data: &[u8; GHash::BLOCK_LENGTH]) {
    let mut x = *data;
    x.reverse();

    state.core.update(&x);
}

struct Polyval {
    h: __m128i,
    s: __m128i,
}

impl Polyval {
    fn new(h: &[u8; 16]) -> Self {
        unsafe {
            Self {
                h: _mm_loadu_si128(h.as_ptr().cast()),
                s: _mm_setzero_si128(),
            }
        }
    }

    fn update(&mut self, x: &[u8; 16]) {
        unsafe {
            let h = self.h;

            let x = _mm_loadu_si128(x.as_ptr().cast());
            let y = _mm_xor_si128(self.s, x);

            let h0 = h;
            let h1 = _mm_shuffle_epi32(h, 0x0E);
            let h2 = _mm_xor_si128(h0, h1);
            let y0 = y;

            let y1 = _mm_shuffle_epi32(y, 0x0E);
            let y2 = _mm_xor_si128(y0, y1);
            let t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
            let t1 = _mm_clmulepi64_si128(y, h, 0x11);
            let t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
            let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
            let v0 = t0;
            let v1 = _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2);
            let v2 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
            let v3 = _mm_shuffle_epi32(t1, 0x0E);

            let v2 = xor5(
                v2,
                v0,
                _mm_srli_epi64(v0, 1),
                _mm_srli_epi64(v0, 2),
                _mm_srli_epi64(v0, 7),
            );

            let v1 = xor4(
                v1,
                _mm_slli_epi64(v0, 63),
                _mm_slli_epi64(v0, 62),
                _mm_slli_epi64(v0, 57),
            );

            let v3 = xor5(
                v3,
                v1,
                _mm_srli_epi64(v1, 1),
                _mm_srli_epi64(v1, 2),
                _mm_srli_epi64(v1, 7),
            );

            let v2 = xor4(
                v2,
                _mm_slli_epi64(v1, 63),
                _mm_slli_epi64(v1, 62),
                _mm_slli_epi64(v1, 57),
            );

            self.s = _mm_unpacklo_epi64(v2, v3);
        }
    }

    fn finalize(self) -> [u8; 16] {
        let mut block = [0u8; 16];

        unsafe { _mm_storeu_si128(block.as_mut_ptr().cast(), self.s) };

        block
    }
}

#[inline(always)]
unsafe fn xor4(e1: __m128i, e2: __m128i, e3: __m128i, e4: __m128i) -> __m128i {
    _mm_xor_si128(_mm_xor_si128(e1, e2), _mm_xor_si128(e3, e4))
}

#[inline(always)]
unsafe fn xor5(e1: __m128i, e2: __m128i, e3: __m128i, e4: __m128i, e5: __m128i) -> __m128i {
    _mm_xor_si128(
        e1,
        _mm_xor_si128(_mm_xor_si128(e2, e3), _mm_xor_si128(e4, e5)),
    )
}
