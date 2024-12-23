// #![no_std]
// #[macro_use]
// extern crate alloc;

// pub use crate::{constants::*, error::*, api::*};

pub mod api;
pub mod constants;
pub mod error;
pub mod percent;

pub fn from_bool(flag: bool) -> usize {
  if flag {
    1
  } else {
    0
  }
}

pub fn to_bool(flag: usize) -> bool {
  flag != 0
}
