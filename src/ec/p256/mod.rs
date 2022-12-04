use self::{
    int256::Int256,
    point256::{NPoint256, Point256, G},
};
use super::ECDHE;
use crate::{error::ECError, rng::Rng};

mod int256;
mod point256;

#[derive(Debug)]
pub struct P256 {
    x: Int256,
}

impl ECDHE for P256 {
    const POINT_SIZE: usize = 65;
    const INT_SIZE: usize = 32;

    fn new(rng: &mut impl Rng) -> Self {
        let mut buf = [0u8; 32];
        loop {
            rng.fill_bytes(&mut buf);
            let x = Int256::from_bytes(&buf).unwrap();
            let xx = x.reduce_once(0);
            let x_is_okay = xx.not_equal(&x);
            if !x_is_okay {
                return Self { x };
            }
        }
    }

    fn to_public(&self) -> [u8; 65] {
        point256::G
            .mult_scalar(&self.x)
            .normalize()
            .to_uncompressed_bytes()
    }

    fn exchange(&self, gy: &[u8; 65]) -> Result<[u8; 32], ECError> {
        let gy = NPoint256::from_uncompressed_bytes(gy).ok_or(ECError::InvalidPublicKey)?;
        let gy = gy.to_point();
        let gxy = gy.mult_scalar(&self.x).normalize();
        Ok(gxy.x.to_bytes())
    }
}

// #[cfg(test)]
impl P256 {
    pub const G: Point256 = G;
    pub fn new_from_bytes(x: &[u8; 32]) -> Self {
        let x = Int256::from_bytes(x).unwrap();
        Self { x }
    }
}
