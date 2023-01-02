#[cfg(not(feature = "aesni"))]
mod soft;
#[cfg(not(feature = "aesni"))]
pub use soft::*;

#[cfg(feature = "aesni")]
mod aesni;
#[cfg(feature = "aesni")]
pub use aesni::*;

// #[cfg(all(not(target_feature = "aes"), feature = "aesni"))]
// compile_error!("Use `aesni` feature without target aes support");
