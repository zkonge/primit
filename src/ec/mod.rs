use crate::{error::ECError, rng::Rng};

pub mod p256;

pub trait ECDH {
    const POINT_SIZE: usize;
    const INT_SIZE: usize;

    fn new(x: &[u8; Self::INT_SIZE]) -> Self;
    fn generate(rng: &mut impl Rng) -> Self;
    fn to_public(&self) -> [u8; Self::POINT_SIZE];
    fn exchange(&self, gy: &[u8; Self::POINT_SIZE]) -> Result<[u8; Self::INT_SIZE], ECError>;
}
