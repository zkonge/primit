#[cfg(not(feature = "aesni"))]
mod soft;
#[cfg(not(feature = "aesni"))]
pub use soft::*;

#[cfg(feature = "aesni")]
mod clmul;
#[cfg(feature = "aesni")]
pub use clmul::*;

use super::Mac;

// #[cfg(all(not(target_feature = "pclmulqdq"), feature = "aesni"))]
// compile_error!("Use `aesni` feature without target pclmulqdq support");

pub fn ghash(key: &[u8; 16], msg: &[[u8; 16]]) -> [u8; 16] {
    let mut h = GHash::new(key);
    for m in msg {
        h.update(m);
    }
    h.finalize(&[])
}
