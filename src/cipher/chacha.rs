use crate::utils::endian::{EndianConvertion, LittleEndian};

// "expand 32-byte k"
const INIT_VECTOR: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

pub(crate) struct ChaChaInner<const R: usize> {
    state: [u32; 16],
    buffer: [u8; 64],
    buffer_offset: usize,
}

impl<const R: usize> ChaChaInner<R> {
    pub(crate) fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        let mut state = [0; 16];

        state[0..4].copy_from_slice(&INIT_VECTOR);
        LittleEndian::from_bytes(&mut state[4..12], key);
        state[12] = 0;
        LittleEndian::from_bytes(&mut state[13..16], nonce);

        let mut context = Self {
            state,
            buffer: [0u8; 64],
            buffer_offset: 0,
        };
        let key = context.next_key();
        context.buffer.copy_from_slice(&key);
        context
    }

    fn round(&self) -> [u32; 16] {
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

        let mut state = self.state;
        for _ in 0..R / 2 {
            // column round
            quarter_round_idx!(state, 0x0, 0x4, 0x8, 0xC);
            quarter_round_idx!(state, 0x1, 0x5, 0x9, 0xD);
            quarter_round_idx!(state, 0x2, 0x6, 0xA, 0xE);
            quarter_round_idx!(state, 0x3, 0x7, 0xB, 0xF);

            // diagonal round
            quarter_round_idx!(state, 0x0, 0x5, 0xA, 0xF);
            quarter_round_idx!(state, 0x1, 0x6, 0xB, 0xC);
            quarter_round_idx!(state, 0x2, 0x7, 0x8, 0xD);
            quarter_round_idx!(state, 0x3, 0x4, 0x9, 0xE);
        }

        state
            .iter_mut()
            .zip(self.state)
            .for_each(|(o, i)| *o = o.wrapping_add(i));

        state
    }

    pub(crate) fn next_key(&mut self) -> [u8; 64] {
        let mut k = [0u8; 64];
        LittleEndian::to_bytes(&mut k, &self.round());
        self.state[12] = self.state[12].wrapping_add(1);
        k
    }
}

impl<const R: usize> Iterator for ChaChaInner<R> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buffer_offset == 64 {
            let next_key = self.next_key();
            self.buffer.copy_from_slice(&next_key);
            self.buffer_offset = 0;
        }
        let n = self.buffer_offset;
        self.buffer_offset += 1;
        Some(self.buffer[n])
    }
}

pub struct ChaCha20 {
    inner: ChaChaInner<20>,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        ChaCha20 {
            inner: ChaChaInner::new(key, nonce),
        }
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        data.iter_mut()
            .zip(self.inner.by_ref())
            .for_each(|(o, i)| *o ^= i);
    }
}
