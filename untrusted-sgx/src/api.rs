use crate::util::is_hw_sgx;
use crate::{SIGNED_ENCLAVE, SIGNED_ENCLAVE_SIM};
use common::api::KMSEndPoint;
use common::api::KeyData;
use common::api::KeyUsageMask;
use common::api::MulTeeCore;
use common::api::RsaPadding;
use common::constants::MAX_CSR_PEM_LEN;
use common::constants::MAX_KEY_LEN;
use common::constants::MAX_KEY_NAME_LEN;
use common::constants::MULTEE_HMAC256_BYTES;
use common::constants::MULTEE_SIG_LEN_MAX;
use common::error::MulTeeErrCode;
use common::error::MulTeeErrorBuf;
use common::error::MulTeeResult;
use common::from_bool;
use either::{Either, Left, Right};
use kmip::constants::FromU32;
use kmip::enumerations::CryptographicAlgorithm;
use kmip::enumerations::HashingAlgorithm;
use log::error;
use sgx_types::error::SgxStatus;
use sgx_types::types::c_char;
use sgx_types::types::c_void;
use sgx_urts::enclave::ExtFeatures;
use sgx_urts::enclave::SgxEnclave;
use std::cell::RefCell;
use std::env;

#[allow(improper_ctypes)]
extern "C" {
  fn ecall_mk_csr(
    eid: u64, sn: *const c_char, sn_len: usize, pinned: u8, csr: *mut u8, csr_len: *mut usize,
    pkey: *mut u8, pkey_len: *mut usize, err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_seal_pk(
    eid: u64, pem: *const u8, in_len: usize, sealed: *mut u8, out_len: *mut usize,
    err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;

  fn ecall_import_keys(
    eid: u64, kms_ref_buf_ptr: *const u8, kms_ref_buf_len: usize, key_literal: *const u8,
    key_literal_len: usize, rust_log_env: *const c_char, rust_log_env_len: usize,
    err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;

  fn ecall_crypt_cbc(
    eid: u64, key_index: usize, encrypt: usize, explicit_iv: usize, iv: *mut u8,
    crypto_buf: *mut u8, input_len: usize, err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_crypt_gcm(
    eid: u64, key_index: usize, encrypt: usize, iv: *mut u8, aad: *mut u8, aad_len: usize,
    in_buf: *const u8, out_buf: *mut u8, input_len: usize, tag: *mut u8,
    err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_hmac_sha256(
    eid: u64, key_index: usize, input: *const u8, input_len: usize, output: *mut u8,
    err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_sign(
    eid: u64, key_index: usize, plaintext: *const u8, plaintext_len: usize, padding: *const c_void,
    md_type: u32, signature: *mut u8, signature_len: *mut usize, err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_get_public_key(
    eid: u64, key_index: usize, public_key: *mut u8, public_key_len: *mut usize,
    err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_meta_key_len(
    eid: u64, key_index: usize, key_len: *mut u64, err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_meta_key_type(
    eid: u64, key_index: usize, key_type: *mut u32, err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_meta_key_usage(
    eid: u64, key_index: usize, key_usage: *mut u32, err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_meta_key_name(
    eid: u64, key_index: usize, key_name: *mut u8, key_name_len: *mut usize,
    err_buf: *mut MulTeeErrorBuf,
  ) -> SgxStatus;
  fn ecall_meta_key_count(eid: u64, key_count: *mut u64, err_buf: *mut MulTeeErrorBuf)
    -> SgxStatus;
}

#[no_mangle]
pub fn load_sgx(
  want_sim: bool, key_ref: Either<&KMSEndPoint, &Vec<KeyData>>,
) -> MulTeeResult<*mut dyn MulTeeCore> {
  let e = Enclave::new(want_sim).and_then(|e| {
    e.load_keys(key_ref)?;
    Ok(e)
  })?;
  Ok(Box::into_raw(Box::new(e)))
}

thread_local!(static ERR_BUF: RefCell<MulTeeErrorBuf> = RefCell::new(MulTeeErrorBuf::new()));

pub struct Enclave {
  _enclave: SgxEnclave,
  eid: u64,
}

impl Enclave {
  pub fn new(want_sim: bool) -> MulTeeResult<Self> {
    env_logger::init();

    let hw_sgx = !want_sim && is_hw_sgx();

    let enclave_bytes = if hw_sgx {
      SIGNED_ENCLAVE
    } else {
      SIGNED_ENCLAVE_SIM
    };

    let sgx_debug = !(hw_sgx && cfg!(feature = "prod-signing"));

    // TODO: why create_from_buffer doesn't work?
    let enclave = if true {
      let (dir, enclave_file) = crate::util::extract_enclave(enclave_bytes).map_err(|e| {
        MulTeeErrCode::ENCLAVE_ARTIFACT_IO.msg(format!("Unable to extract enclave {}", e))
      })?;
      let enclave_file_name = enclave_file.to_str().expect("Path - is always unicode");
      let res = SgxEnclave::create(enclave_file_name, sgx_debug);
      if env::var("MULTEE_KEEP_EXTRACTED").is_err() {
        if std::fs::remove_dir_all(dir.as_path()).is_err() {
          eprintln!("Unable to remove MulTee directory")
        }
      }
      res
    } else {
      let features = ExtFeatures::new();
      // features.set_switchless(config);
      // features.set_kss(config);
      SgxEnclave::create_from_buffer(enclave_bytes, sgx_debug, features)
    };

    match enclave {
      Ok(enclave) => {
        let eid = enclave.eid();
        Ok(Enclave {
          _enclave: enclave,
          eid: eid,
        })
      }
      Err(e) => Err(crate::to_err(MulTeeErrCode::SGX_INIT, e)),
    }
  }

  fn do_ecall<F: FnMut(*mut MulTeeErrorBuf) -> SgxStatus>(&self, mut func: F) -> MulTeeResult<()> {
    ERR_BUF.with(|ebuff| {
      let err_buf = &mut ebuff.borrow_mut();
      err_buf.reset();

      match func(ebuff.as_ptr()) {
        SgxStatus::Success => err_buf.to_result(),
        err => {
          let err = crate::to_err(MulTeeErrCode::SGX_ECALL, err);
          error!("ecall failed: {}", err);
          Err(err)
        }
      }
    })
  }

  fn load_keys(&self, key_ref: Either<&KMSEndPoint, &Vec<KeyData>>) -> MulTeeResult<()> {
    let env = env::var("RUST_LOG").unwrap_or("".to_string());
    match key_ref {
      Left(kms_info) => {
        let buf = postcard::to_allocvec(kms_info).expect("TODO: impossible?");
        self.do_ecall(|err_buf| unsafe {
          ecall_import_keys(
            self.eid,
            buf.as_ptr(),
            buf.len(),
            std::ptr::null(),
            0,
            env.as_ptr() as *const c_char,
            env.len(),
            err_buf,
          )
        })
      }
      Right(literal) => {
        let buf = postcard::to_allocvec(literal).expect("TODO: impossible?");
        self.do_ecall(|err_buf| unsafe {
          ecall_import_keys(
            self.eid,
            std::ptr::null(),
            0,
            buf.as_ptr(),
            buf.len(),
            env.as_ptr() as *const c_char,
            env.len(),
            err_buf,
          )
        })
      }
    }
  }
}

impl MulTeeCore for Enclave {
  fn crypt_cbc(
    &self, key_index: usize, encrypt: bool, explicit_iv: bool, iv: &mut [u8],
    crypto_buf: &mut [u8], input_len: usize,
  ) -> MulTeeResult<()> {
    self.do_ecall(|err_buf| unsafe {
      ecall_crypt_cbc(
        self.eid,
        key_index,
        from_bool(encrypt),
        from_bool(explicit_iv),
        iv.as_mut_ptr(),
        crypto_buf.as_mut_ptr(),
        input_len,
        err_buf,
      )
    })
  }

  fn crypt_gcm(
    &self, key_index: usize, encrypt: bool, iv: &mut [u8], aad: Option<&[u8]>, in_buf: &[u8],
    out_buf: &mut [u8], tag: &mut [u8],
  ) -> MulTeeResult<()> {
    let aad_ptr = aad.map(|s| s.as_ptr()).unwrap_or(std::ptr::null()) as *mut u8;
    let aad_len = aad.map(|s| s.len()).unwrap_or(0);

    self.do_ecall(|err_buf| unsafe {
      ecall_crypt_gcm(
        self.eid,
        key_index,
        from_bool(encrypt),
        iv.as_mut_ptr(),
        aad_ptr,
        aad_len,
        in_buf.as_ptr(),
        out_buf.as_mut_ptr(),
        in_buf.len(),
        tag.as_mut_ptr(),
        err_buf,
      )
    })
  }

  fn sign<'a>(
    &self, key_index: usize, padding: Option<RsaPadding>, md_type: HashingAlgorithm,
    plaintext: &[u8],
  ) -> MulTeeResult<Vec<u8>> {
    let mut sig_len: usize = 0;

    let padding_ptr: *const RsaPadding = if let Some(padding) = padding {
      &padding
    } else {
      std::ptr::null()
    };

    let mut signature = vec![0u8; MULTEE_SIG_LEN_MAX];

    self.do_ecall(|err_buf| unsafe {
      ecall_sign(
        self.eid,
        key_index,
        plaintext.as_ptr(),
        plaintext.len(),
        padding_ptr as *const c_void,
        md_type as u32,
        signature.as_mut_ptr(),
        &mut sig_len,
        err_buf,
      )
    })?;

    signature.truncate(sig_len as usize);
    Ok(signature)
  }

  fn hmac_sha256(&self, key_index: usize, input: &[u8]) -> MulTeeResult<Vec<u8>> {
    let mut hash = vec![0u8; MULTEE_HMAC256_BYTES];

    self.do_ecall(|err_buf| unsafe {
      ecall_hmac_sha256(
        self.eid,
        key_index,
        input.as_ptr(),
        input.len(),
        hash.as_mut_ptr(),
        err_buf,
      )
    })?;
    Ok(hash)
  }

  fn meta_key_type(&self, key_index: usize) -> MulTeeResult<CryptographicAlgorithm> {
    let mut key_type: u32 = 0;

    self.do_ecall(|err_buf| unsafe {
      ecall_meta_key_type(self.eid, key_index, &mut key_type, err_buf)
    })?;

    Ok(
      CryptographicAlgorithm::fromu32(key_type)
        .expect("Impossible: trusted can only return specific key types"),
    )
  }

  fn meta_key_len(&self, key_index: usize) -> MulTeeResult<u64> {
    let mut key_len: u64 = 0;

    self.do_ecall(|err_buf| unsafe {
      ecall_meta_key_len(self.eid, key_index, &mut key_len, err_buf)
    })?;
    Ok(key_len)
  }

  fn meta_key_usage_mask(&self, key_index: usize) -> MulTeeResult<KeyUsageMask> {
    let mut key_usage: u32 = 0;
    self.do_ecall(|err_buf| unsafe {
      ecall_meta_key_usage(self.eid, key_index, &mut key_usage, err_buf)
    })?;
    Ok(key_usage)
  }

  fn mk_csr(&self, subject_name: &str, pinned: bool) -> MulTeeResult<(Vec<u8>, Vec<u8>)> {
    let pinned = if pinned { 1 } else { 0 };

    let mut key = vec![0u8; MAX_KEY_LEN];
    let mut csr_pem = vec![0u8; MAX_CSR_PEM_LEN];

    let mut csr_len = 0;
    let mut key_len = 0;
    self.do_ecall(|err_buf| unsafe {
      ecall_mk_csr(
        self.eid,
        subject_name.as_ptr() as *const c_char,
        subject_name.len(),
        pinned,
        csr_pem.as_mut_ptr(),
        &mut csr_len,
        key.as_mut_ptr(),
        &mut key_len,
        err_buf,
      )
    })?;

    csr_pem.truncate(csr_len as usize);
    key.truncate(key_len as usize);

    Ok((csr_pem, key))
  }

  fn seal_pk(&self, private_key: &[u8]) -> MulTeeResult<Vec<u8>> {
    let mut sealed_private_key = vec![0u8; MAX_KEY_LEN as usize];
    let mut size = 0;

    self.do_ecall(|err_buf| unsafe {
      ecall_seal_pk(
        self.eid,
        private_key.as_ptr(),
        private_key.len(),
        sealed_private_key.as_mut_ptr(),
        &mut size,
        err_buf,
      )
    })?;

    sealed_private_key.truncate(size as usize);
    Ok(sealed_private_key)
  }

  fn get_public_key(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    let mut public_key = vec![0u8; MAX_KEY_LEN as usize];
    let mut size = 0;

    self.do_ecall(|err_buf| unsafe {
      ecall_get_public_key(
        self.eid,
        key_index,
        public_key.as_mut_ptr(),
        &mut size,
        err_buf,
      )
    })?;

    public_key.truncate(size as usize);
    Ok(public_key)
  }

  fn meta_key_count(&self) -> MulTeeResult<u64> {
    let mut key_count: u64 = 0;

    self.do_ecall(|err_buf| unsafe { ecall_meta_key_count(self.eid, &mut key_count, err_buf) })?;
    Ok(key_count)
  }

  fn meta_key_name(&self, key_index: usize) -> MulTeeResult<String> {
    let mut key_name = vec![0u8; MAX_KEY_NAME_LEN as usize];
    let mut size = 0;

    self.do_ecall(|err_buf| unsafe {
      ecall_meta_key_name(
        self.eid,
        key_index,
        key_name.as_mut_ptr(),
        &mut size,
        err_buf,
      )
    })?;

    key_name.truncate(size as usize);
    Ok(String::from_utf8(key_name)?)
  }
}
