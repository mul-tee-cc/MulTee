use core::ffi::c_void;
use std::ffi::CString;
use std::vec::Vec;

use paste::paste;

use common::constants::MAX_CSR_PEM_LEN;
use common::constants::MAX_KEY_LEN;
use common::constants::MULTEE_RSA_EXPONENT;
use common::constants::MULTEE_RSA_KEY_SIZE;
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;

use mbedtls_sys::{mbedtls_md_type_t::*, *};

use crate::api::{CtxCTRDRBG, Tee};
use crate::mtls::mbed_err_check;
use crate::mtls::CtxPK;

#[allow(non_camel_case_types)]
type size_t = usize;

// mbedtls_struct!(Pk, pk, mbedtls_pk_context);
mbedtls_struct!(CsrBuilder, x509write_csr, mbedtls_x509write_csr);

impl CsrBuilder {
  unsafe fn signature_hash(&mut self, md_alg: mbedtls_md_type_t) {
    mbedtls_x509write_csr_set_md_alg(self.as_mut_ptr(), md_alg)
  }
  unsafe fn key_usage(&mut self, usage: u32) -> MulTeeResult<()> {
    mbed_err_check(mbedtls_x509write_csr_set_key_usage(
      self.as_mut_ptr(),
      usage as u8,
    ))
  }
  unsafe fn set_ns_cert_type(&mut self, ns_cert_type: u32) -> MulTeeResult<()> {
    mbed_err_check(mbedtls_x509write_csr_set_ns_cert_type(
      self.as_mut_ptr(),
      ns_cert_type as u8,
    ))
  }
  unsafe fn set_subject_name(&mut self, subject_name: &str) -> MulTeeResult<()> {
    let subject_name = CString::new(subject_name)
      .map_err(|_| MulTeeErrCode::UNEXPECTED_OR_IMPOSSIBLE.msg("Zero byte in subject"))?;
    mbed_err_check(mbedtls_x509write_csr_set_subject_name(
      self.as_mut_ptr(),
      subject_name.as_ptr(),
    ))
  }
  unsafe fn set_key(&mut self, pk: &mut CtxPK) {
    mbedtls_x509write_csr_set_key(self.as_mut_ptr(), pk.as_mut_ptr())
  }
  unsafe fn write_csr_pem(
    &mut self, drbg: &CtxCTRDRBG, pem: &mut [u8],
    f_rng: Option<unsafe extern "C" fn(data: *mut c_void, output: *mut u8, len: size_t) -> i32>,
  ) -> MulTeeResult<()> {
    let p_rng = drbg.force_mut_ptr() as *mut libc::c_void;

    mbed_err_check(mbedtls_x509write_csr_pem(
      self.as_mut_ptr(),
      pem.as_mut_ptr(),
      pem.len(),
      f_rng,
      p_rng,
    ))
  }
}

pub(crate) fn mk_csr<T: Tee>(
  rnd: &CtxCTRDRBG, subject_name: &str, pinned: bool,
) -> MulTeeResult<(Vec<u8>, Vec<u8>)> {
  let mut key = CtxPK::new();
  let mut req = CsrBuilder::new();

  let mut key_pem = vec![0u8; MAX_KEY_LEN];
  let mut csr_pem = vec![0u8; MAX_CSR_PEM_LEN];
  unsafe {
    req.signature_hash(MBEDTLS_MD_SHA256);
    req.key_usage(
      MBEDTLS_X509_KU_DIGITAL_SIGNATURE
        | MBEDTLS_X509_KU_NON_REPUDIATION
        | MBEDTLS_X509_KU_KEY_ENCIPHERMENT
        | MBEDTLS_X509_KU_DATA_ENCIPHERMENT
        | MBEDTLS_X509_KU_KEY_AGREEMENT,
    )?;
    req.set_ns_cert_type(MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT)?;
    req.set_subject_name(subject_name)?;
    key.gen_rsa_key(rnd, MULTEE_RSA_KEY_SIZE as u32, MULTEE_RSA_EXPONENT as i32)?;
    req.set_key(&mut key);
    req.write_csr_pem(rnd, csr_pem.as_mut_slice(), Some(mbedtls_ctr_drbg_random))?;
    key.write_key_pem(key_pem.as_mut_slice())?;
  }

  let csr_null_range_end = csr_pem
    .iter()
    .position(|&c| c == 0)
    .unwrap_or(csr_pem.len());
  csr_pem.truncate(csr_null_range_end);
  let pkey_null_range_end = key_pem
    .iter()
    .position(|&c| c == 0)
    .unwrap_or(key_pem.len());
  key_pem.truncate(pkey_null_range_end);

  let pk_vec = if pinned {
    T::seal_data(key_pem.as_slice())?
  } else {
    key_pem
  };

  Ok((csr_pem, pk_vec))
}
