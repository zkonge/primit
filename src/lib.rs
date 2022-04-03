// #![no_std]
#![feature(test)]
#![feature(inline_const)]
#![feature(exclusive_range_pattern)]
#![feature(slice_as_chunks)]

#![allow(incomplete_features)]
#![feature(generic_const_exprs)]


#[cfg(test)]
extern crate test;

pub mod error;
pub mod hash;
pub mod cipher;
pub mod utils;
