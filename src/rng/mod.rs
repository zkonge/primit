pub mod cprng;

pub trait Rng {
    fn new_from_seed(seed: &[u8; 32]) -> Self;
    fn fill_bytes(&mut self, data: &mut [u8]);
}
