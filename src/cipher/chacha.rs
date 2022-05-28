use crate::utils::{
    endian::{EndianConvertion, LittleEndian},
    xor::xor,
};

// "expand 32-byte k"
const INIT_VECTOR: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

pub(crate) struct ChaChaInner<const R: usize>([u32; 16]);

impl<const R: usize> ChaChaInner<R> {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0; 16];

        state[0..4].copy_from_slice(&INIT_VECTOR);
        LittleEndian::from_bytes(&mut state[4..12], key);
        state[12] = 0;
        LittleEndian::from_bytes(&mut state[13..16], nonce);

        Self(state)
    }

    fn round(&self) -> [u32; 16] {
        fn quarter_round_idx(e: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
            macro_rules! quarter_round {
                ($a:expr, $b:expr, $c:expr, $d:expr) => {{
                    $a = $a.wrapping_add($b);
                    $d ^= $a;
                    $d = $d.rotate_left(16);

                    $c = $c.wrapping_add($d);
                    $b ^= $c;
                    $b = $b.rotate_left(12);

                    $a = $a.wrapping_add($b);
                    $d ^= $a;
                    $d = $d.rotate_left(8);

                    $c = $c.wrapping_add($d);
                    $b ^= $c;
                    $b = $b.rotate_left(7);
                }};
            }
            macro_rules! quarter_round_idx {
                ($e:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
                    quarter_round!($e[$a], $e[$b], $e[$c], $e[$d])
                };
            }
            quarter_round_idx!(e, a, b, c, d);
        }

        let mut state = self.0;
        for _ in 0..R / 2 {
            // column round
            quarter_round_idx(&mut state, 0x0, 0x4, 0x8, 0xC);
            quarter_round_idx(&mut state, 0x1, 0x5, 0x9, 0xD);
            quarter_round_idx(&mut state, 0x2, 0x6, 0xA, 0xE);
            quarter_round_idx(&mut state, 0x3, 0x7, 0xB, 0xF);

            // diagonal round
            quarter_round_idx(&mut state, 0x0, 0x5, 0xA, 0xF);
            quarter_round_idx(&mut state, 0x1, 0x6, 0xB, 0xC);
            quarter_round_idx(&mut state, 0x2, 0x7, 0x8, 0xD);
            quarter_round_idx(&mut state, 0x3, 0x4, 0x9, 0xE);
        }

        state
            .iter_mut()
            .zip(self.0)
            .for_each(|(o, i)| *o = o.wrapping_add(i));

        state
    }

    pub(crate) fn next_key(&mut self) -> [u8; 64] {
        let mut k = [0u8; 64];
        let carry;
        (self.0[12], carry) = self.0[12].carrying_add(1, false);
        self.0[13] = self.0[13].wrapping_add(carry as u32);
        LittleEndian::to_bytes(&mut k, &self.round());
        k
    }
}

pub struct ChaCha20 {
    inner: ChaChaInner<20>,
    buffer: [u8; 64],
    buffer_offset: usize,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut inner = ChaChaInner::new(key, nonce);
        let buffer = inner.next_key();
        ChaCha20 {
            inner,
            buffer,
            buffer_offset: 0,
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        xor(data, &self.buffer[self.buffer_offset..]);

        if data.len() < self.buffer.len() - self.buffer_offset {
            self.buffer_offset += data.len();
            return;
        }

        let (chunks, remain) = data[self.buffer_offset..].as_chunks_mut::<64>();
        for chunk in chunks {
            xor(chunk, &self.inner.next_key());
        }
        self.buffer = self.inner.next_key();

        xor(remain, &self.buffer);
        self.buffer_offset = remain.len();
    }
}
