#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::needless_range_loop)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(trait_alias)]
#![feature(decl_macro)]
#![feature(core_intrinsics)]

extern crate alloc;

pub mod builder;
pub mod composer;
pub mod ecc;
pub mod eth;
pub mod ethutils;
pub mod hash;
pub mod mapreduce;
pub mod num;
pub mod utils;
pub mod vars;
