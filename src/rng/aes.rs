use crate::{rng::Rng, symmetry::aes::Aes128};

#[derive(Debug)]
pub struct Aes128Rng {
    state: [u8; 16],
    cipher: Aes128,
}

impl Aes128Rng {
    #[cfg(feature = "system-random")]
    pub fn new_from_system() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        Self::new_from_seed(&seed)
    }

    fn next_key(&mut self) -> [u8; 16] {
        let counter: &mut [u8; 8] = &mut self.state[..8].try_into().unwrap();
        *counter = u64::from_ne_bytes(*counter).wrapping_add(1).to_ne_bytes();

        let mut r = self.state;
        self.cipher.encrypt(&mut r);
        r
    }
}

impl Rng for Aes128Rng {
    fn new_from_seed(seed: &[u8; 32]) -> Self {
        let state = seed[..16].try_into().unwrap();
        let cipher = Aes128::new(seed[16..].try_into().unwrap());
        Self { state, cipher }
    }
    fn fill_bytes(&mut self, data: &mut [u8]) {
        let (chunks, remain) = data.as_chunks_mut::<16>();
        chunks.iter_mut().for_each(|c| *c = self.next_key());
        remain.copy_from_slice(&self.next_key()[..remain.len()]);
    }
}
