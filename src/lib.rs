#![no_std]
#![feature(inline_const)]
#![feature(exclusive_range_pattern)]
#![feature(slice_as_chunks)]
#![feature(associated_const_equality)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(associated_type_bounds)]

pub mod aead;
pub mod ec;
pub mod error;
pub mod hash;
pub mod mac;
pub mod rng;
pub mod symmetry;
pub mod utils;
