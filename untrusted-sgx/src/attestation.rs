use crate::{DUMMY_SGX_QUOTE3_T, DUMMY_SGX_TARGET_INFO_T};

use sgx_types::error::Quote3Error;
use sgx_types::function::sgx_qe_get_target_info;
use sgx_types::types::uint32_t;
use sgx_types::types::uint8_t;
use sgx_types::types::Report;
use sgx_types::types::TargetInfo;

extern "C" {
  pub fn sgx_qe_get_quote_size(p_quote_size: *mut uint32_t) -> Quote3Error;
  pub fn sgx_qe_get_quote(
    p_app_report: *const Report, quote_size: uint32_t, p_quote: *mut uint8_t,
  ) -> Quote3Error;
}

#[no_mangle]
pub extern "C" fn ocall_qe_get_quote_size(p_quote_size: *mut uint32_t) -> Quote3Error {
  unsafe {
    let r = sgx_qe_get_quote_size(p_quote_size);
    if r == Quote3Error::InterfaceUnavailable {
      std::ptr::write_unaligned(p_quote_size, DUMMY_SGX_QUOTE3_T.len() as uint32_t);
      Quote3Error::Success
    } else {
      r
    }
  }
}
#[no_mangle]
pub extern "C" fn ocall_qe_get_target_info(p_qe_target_info: *mut TargetInfo) -> Quote3Error {
  unsafe {
    let r = sgx_qe_get_target_info(p_qe_target_info);
    if r == Quote3Error::InterfaceUnavailable {
      let target_info: TargetInfo = std::ptr::read_unaligned(DUMMY_SGX_TARGET_INFO_T.as_ptr() as _);
      std::ptr::write_unaligned(p_qe_target_info, target_info);
      Quote3Error::Success
    } else {
      r
    }
  }
}
#[no_mangle]
pub extern "C" fn ocall_qe_get_quote(
  p_app_report: *const Report, quote_size: uint32_t, p_quote: *mut uint8_t,
) -> Quote3Error {
  unsafe {
    let r = sgx_qe_get_quote(p_app_report, quote_size, p_quote);
    if r == Quote3Error::InterfaceUnavailable || r == Quote3Error::EnclaveLoadError {
      std::slice::from_raw_parts_mut(p_quote, DUMMY_SGX_QUOTE3_T.len())
        .copy_from_slice(DUMMY_SGX_QUOTE3_T);
      Quote3Error::Success
    } else {
      r
    }
  }
}
