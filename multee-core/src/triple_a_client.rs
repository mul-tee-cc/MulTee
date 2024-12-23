use std::io::{Read, Write};
use std::string::ToString;
use std::vec::Vec;

use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use http::StatusCode;
use serde_json::{json, Value};

use crate::api::{CtxCTRDRBG, Tee};
use crate::http_util;

type ClientCert = (String, Vec<u8>);

pub(crate) fn attest_csr<T: Tee, I: Read + Write>(
  tls: &mut I, prefix: &str, cn: &str, rng: &CtxCTRDRBG,
) -> MulTeeResult<ClientCert> {
  let kind = T::attestation_kind();

  let init_path = format!("v1/attestation/{}/nonce", kind);

  let nonce = http_util::do_get(tls, prefix, init_path.as_str(), "")?;
  if nonce.status() != StatusCode::OK {
    return Err(MulTeeErrCode::TRIPLE_A_NOK.msg(format!(
      "Nonce request - Status: {}, Body: {}",
      nonce.status(),
      nonce.body()
    )));
  }

  let body = nonce.body();
  let json: Value = serde_json::from_str(body).map_err(|_| MulTeeErrCode::CORRUPT_JSON.no_msg())?;
  let nonce: String = json
    .get("nonce")
    .and_then(|v| v.as_str().map(|x| x.to_owned()))
    .ok_or(
      MulTeeErrCode::TRIPLE_A_PROTOCOL_VIOLATION.msg("Missing nonce in attestation response"),
    )?;

  let subject_name = format!("CN={}", cn);
  let (csr, key) = crate::csr::mk_csr::<T>(rng, subject_name.as_str(), false)?;
  let csr_str = String::from_utf8(csr).expect("Impossible");

  let att_payload_str = json!({
    "nonce": nonce.as_str(),
    "csr": csr_str,
  })
  .to_string();

  let tee_report = T::attestation(att_payload_str.as_bytes())?;

  let att_request = json!({
    "payload": {
      "kind": "CSR",
      "value": att_payload_str
    },
    "teeReport": tee_report,
    "opt": {
      "hostname": "hostname"
    }
  })
  .to_string();

  let quote_path = format!("v1/attestation/{}/grant", kind);

  let grant = http_util::do_post(
    tls,
    prefix,
    quote_path.as_str(),
    att_request.to_string().as_str(),
  )?;
  if grant.status() != StatusCode::OK {
    return Err(MulTeeErrCode::TRIPLE_A_NOK.msg(format!(
      "Attestation request - Status: {}, Body: {}",
      grant.status(),
      grant.body()
    )));
  }

  let body = grant.body();
  let json: Value = serde_json::from_str(body).map_err(|_| MulTeeErrCode::CORRUPT_JSON)?;

  let cert = json
    .get("cert")
    .and_then(|v| v.as_str())
    .ok_or(MulTeeErrCode::TRIPLE_A_PROTOCOL_VIOLATION)?
    .to_string();

  Ok((cert, key))
}
