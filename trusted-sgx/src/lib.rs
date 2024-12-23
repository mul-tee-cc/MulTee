#![feature(core_intrinsics)]
extern crate sgx_trts;
extern crate sgx_types;

// https://github.com/apache/incubator-teaclave-sgx-sdk/issues/44
#[cfg(debug_assertions)]
#[no_mangle]
pub extern "C" fn __assert_fail(
  __assertion: *const u8, __file: *const u8, __line: u32, __function: *const u8,
) -> ! {
  core::intrinsics::abort()
}

pub mod api;
mod attestation;
mod mutex;

fn to_err(
  code: common::error::MulTeeErrCode, err: sgx_types::error::SgxStatus,
) -> common::error::MulTeeError {
  code.nested(
    err as i32,
    format!("{}{{{}}} - {}", err.as_str(), err, err.__description()),
  )
}
