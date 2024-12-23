use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use multee_core::base64;
use multee_core::mtls::hash_sha256;
use multee_core::serde_json::json;
use multee_core::serde_json::Value;
use sgx_types::error::Quote3Error;
use sgx_types::error::SgxStatus;
use sgx_types::types::uint32_t;
use sgx_types::types::uint8_t;
use sgx_types::types::QlAuthData;
use sgx_types::types::QlCertificationData;
use sgx_types::types::QlEcdsaSigData;
use sgx_types::types::Quote3;
use sgx_types::types::Report;
use sgx_types::types::ReportData;
use sgx_types::types::TargetInfo;
use std::vec::Vec;

use sgx_tse::EnclaveReport;

// https://www.openssl.org/docs/man1.1.1/man1/x509.html
const PEM_FMT: &str = "CERTIFICATE-----";

extern "C" {
  pub fn ocall_qe_get_quote_size(ret_val: *mut Quote3Error, p_quote_size: *mut u32) -> SgxStatus;
  pub fn ocall_qe_get_target_info(
    ret_val: *mut Quote3Error, p_qe_target_info: *mut TargetInfo,
  ) -> SgxStatus;
  pub fn ocall_qe_get_quote(
    ret_val: *mut Quote3Error, p_app_report: *const Report, quote_size: uint32_t,
    p_quote: *mut uint8_t,
  ) -> SgxStatus;
}

pub(crate) fn mk_quote(payload: &[u8]) -> MulTeeResult<(String, String, String)> {
  let mut ret: Quote3Error = Quote3Error::Success;
  let mut q_size: u32 = 0;

  let ud_hash = unsafe { hash_sha256(payload)? };

  let mut report_data: ReportData = ReportData::default();
  report_data.d[..ud_hash.len()].copy_from_slice(ud_hash.as_slice());

  let mut target_info: TargetInfo = TargetInfo::default();
  let status = unsafe { ocall_qe_get_target_info(&mut ret, &mut target_info) };
  sgx_quote3_and_error_check(status, ret)?;

  let rep = Report::for_target(&target_info, &report_data)
    .map_err(|e| crate::to_err(MulTeeErrCode::SGX_REPORT, e))?;

  let status = unsafe { ocall_qe_get_quote_size(&mut ret, &mut q_size) };
  sgx_quote3_and_error_check(status, ret)?;

  let mut quote_vec: Vec<u8> = vec![0; q_size as usize];
  let status = unsafe { ocall_qe_get_quote(&mut ret, &rep, q_size, quote_vec.as_mut_ptr()) };
  sgx_quote3_and_error_check(status, ret)?;

  let quote_hdr_size = std::mem::size_of::<Quote3>();
  let ecdsa_hdr_size = std::mem::size_of::<QlEcdsaSigData>();

  let auth_offset = quote_hdr_size + ecdsa_hdr_size;

  let p_auth_data: *const QlAuthData = quote_vec[auth_offset..].as_ptr() as _;
  let auth_data_header: QlAuthData = unsafe { *p_auth_data };

  let auth_data_size = (auth_data_header.size + 2) as usize;

  let certs_offset = auth_offset + auth_data_size + std::mem::size_of::<QlCertificationData>();

  let certs = String::from_utf8_lossy(&quote_vec[certs_offset..]);

  let splits: Vec<&str> = certs.splitn(5, PEM_FMT).collect();
  let pck = format!("{}{}{}{}\n", splits[0], PEM_FMT, splits[1], PEM_FMT);
  let int = format!("{}{}{}{}\n", splits[2], PEM_FMT, splits[3], PEM_FMT);

  let quote = base64::encode(&quote_vec[..certs_offset]);

  Ok((quote, pck, int))
}

fn sgx_quote3_and_error_check(sgx: SgxStatus, q: Quote3Error) -> MulTeeResult<()> {
  if sgx != SgxStatus::Success {
    Err(crate::to_err(MulTeeErrCode::SGX_OCALL, sgx))
  } else if q != Quote3Error::Success {
    Err(crate::to_err(MulTeeErrCode::SGX_QE3, sgx))
  } else {
    Ok(())
  }
}

pub(crate) fn get_guote(payload: &[u8]) -> MulTeeResult<Value> {
  let (quote, pck, int) = mk_quote(payload)?;

  let json = json!({
    "kind": "DCAP",
    "value": {
      "quote": quote,
      "pck": pck,
      "intermediateCA": int,
    }
  });

  Ok(json)
}
