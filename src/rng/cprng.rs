use crate::cipher::chacha::ChaChaInner;

use crate::rng::Rng;

pub struct FastRng(ChaChaInner<8>);

impl FastRng {
    #[cfg(feature = "system-random")]
    pub fn new_from_system() -> Self {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).unwrap();
        Self::new_from_seed(&seed)
    }
}

impl Rng for FastRng {
    // warning: build new rng after generate 4GiB data
    fn new_from_seed(seed: &[u8; 32]) -> Self {
        Self(ChaChaInner::new(seed, &seed[..12].try_into().unwrap()))
    }
    fn fill_bytes(&mut self, data: &mut [u8]) {
        let (chunks, remain) = data.as_chunks_mut::<64>();
        chunks.iter_mut().for_each(|c| *c = self.0.next_key());
        remain.copy_from_slice(&self.0.next_key()[..remain.len()]);
    }
}
