mod api;
mod attestation;
mod util;
pub use api::Enclave;

const SIGNED_ENCLAVE_SIM: &[u8] = include_bytes!(env!("SIGNED_ENCLAVE_SIM_PATH"));
const SIGNED_ENCLAVE: &[u8] = include_bytes!(env!("SIGNED_ENCLAVE_PATH"));
const DUMMY_SGX_QUOTE3_T: &[u8] = include_bytes!("../resources/sgx_quote3_t");
const DUMMY_SGX_TARGET_INFO_T: &[u8] = include_bytes!("../resources/sgx_target_info_t");

fn to_err(
  code: common::error::MulTeeErrCode, err: sgx_types::error::SgxStatus,
) -> common::error::MulTeeError {
  code.nested(
    err as i32,
    format!("{}{{{}}} - {}", err.as_str(), err, err.__description()),
  )
}
