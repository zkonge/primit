// #![no_std]
#![forbid(unsafe_code)]
#![feature(test)]
#![feature(inline_const)]
#![feature(exclusive_range_pattern)]
#![feature(associated_type_defaults)]
#![feature(slice_as_chunks)]
#![feature(portable_simd)]
#![feature(bigint_helper_methods)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

#[cfg(test)]
extern crate test;

pub mod cipher;
pub mod error;
pub mod hash;
pub mod mac;
pub mod rng;
pub mod utils;
