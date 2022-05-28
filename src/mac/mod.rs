pub mod ghash;
pub mod poly1305;

pub trait Mac<const MAC_LEN: usize> {
    fn input(&mut self, data: &[u8]);

    fn reset(&mut self);

    fn result(&mut self) -> [u8; MAC_LEN];

    fn raw_result(&mut self, output: &mut [u8]);

    fn output_bytes(&self)->usize;
}
