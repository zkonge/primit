#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

use core::mem;

macro_rules! gen_round_key {
    ($rk:ident, $i:literal, $rcon:literal) => {{
        let mut key = $rk[$i - 1];
        let gen = _mm_shuffle_epi32(_mm_aeskeygenassist_si128::<$rcon>(key), 0xff);
        key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
        key = _mm_xor_si128(key, _mm_slli_si128(key, 8));
        $rk[$i] = _mm_xor_si128(key, gen);
    }};
}

#[derive(Debug, Clone, Copy)]
pub struct AES128 {
    round_key: [__m128i; 20],
}

impl AES128 {
    pub fn new(key: &[u8; 16]) -> Self {
        unsafe {
            let mut rk: [__m128i; 20] = mem::zeroed();

            rk[0] = _mm_loadu_si128(key.as_ptr().cast());

            gen_round_key!(rk, 1, 0x01);
            gen_round_key!(rk, 2, 0x02);
            gen_round_key!(rk, 3, 0x04);
            gen_round_key!(rk, 4, 0x08);
            gen_round_key!(rk, 5, 0x10);
            gen_round_key!(rk, 6, 0x20);
            gen_round_key!(rk, 7, 0x40);
            gen_round_key!(rk, 8, 0x80);
            gen_round_key!(rk, 9, 0x1b);
            gen_round_key!(rk, 10, 0x36);

            rk[11] = _mm_aesimc_si128(rk[9]);
            rk[12] = _mm_aesimc_si128(rk[8]);
            rk[13] = _mm_aesimc_si128(rk[7]);
            rk[14] = _mm_aesimc_si128(rk[6]);
            rk[15] = _mm_aesimc_si128(rk[5]);
            rk[16] = _mm_aesimc_si128(rk[4]);
            rk[17] = _mm_aesimc_si128(rk[3]);
            rk[18] = _mm_aesimc_si128(rk[2]);
            rk[19] = _mm_aesimc_si128(rk[1]);

            Self { round_key: rk }
        }
    }

    pub fn encrypt(&self, data: &mut [u8; 16]) {
        unsafe {
            let mut b = _mm_loadu_si128(data.as_ptr().cast());
            b = _mm_xor_si128(b, self.round_key[0]);
            b = _mm_aesenc_si128(b, self.round_key[1]);
            b = _mm_aesenc_si128(b, self.round_key[2]);
            b = _mm_aesenc_si128(b, self.round_key[3]);
            b = _mm_aesenc_si128(b, self.round_key[4]);
            b = _mm_aesenc_si128(b, self.round_key[5]);
            b = _mm_aesenc_si128(b, self.round_key[6]);
            b = _mm_aesenc_si128(b, self.round_key[7]);
            b = _mm_aesenc_si128(b, self.round_key[8]);
            b = _mm_aesenc_si128(b, self.round_key[9]);
            b = _mm_aesenclast_si128(b, self.round_key[10]);
            _mm_storeu_si128(data.as_mut_ptr().cast(), b);
        }
    }

    pub fn decrypt(&self, data: &mut [u8; 16]) {
        unsafe {
            let mut b = _mm_loadu_si128(data.as_ptr().cast());
            b = _mm_xor_si128(b, self.round_key[10]);
            b = _mm_aesdec_si128(b, self.round_key[11]);
            b = _mm_aesdec_si128(b, self.round_key[12]);
            b = _mm_aesdec_si128(b, self.round_key[13]);
            b = _mm_aesdec_si128(b, self.round_key[14]);
            b = _mm_aesdec_si128(b, self.round_key[15]);
            b = _mm_aesdec_si128(b, self.round_key[16]);
            b = _mm_aesdec_si128(b, self.round_key[17]);
            b = _mm_aesdec_si128(b, self.round_key[18]);
            b = _mm_aesdec_si128(b, self.round_key[19]);
            b = _mm_aesdeclast_si128(b, self.round_key[0]);
            _mm_storeu_si128(data.as_mut_ptr().cast(), b);
        }
    }
}
