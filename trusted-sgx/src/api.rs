use common::api::RsaPadding;
use common::api::{KMSEndPoint, KeyData, MulTeeCore};
use common::constants::MAX_CSR_PEM_LEN;
use common::constants::MAX_CSR_SN_LEN;
use common::constants::MAX_KEY_LEN;
use common::constants::MAX_KEY_NAME_LEN;
use common::constants::MULTEE_BLOCK_SIZE;
use common::constants::MULTEE_GCM_IV_BYTES;
use common::constants::MULTEE_GCM_TAG_BYTES;
use common::constants::MULTEE_HMAC256_BYTES;
use common::constants::MULTEE_SIG_LEN_MAX;
use common::error::MulTeeErrorBuf;
use common::error::MulTeeResult;
use common::error::{MulTeeErrCode, MulTeeError};
use common::to_bool;
use core::mem::size_of;
use either::{Either, Left, Right};
use kmip::constants::FromU32;
use lazycell::AtomicLazyCell;
use log::trace;
use multee_core::api::*;
use multee_core::serde_json::Value;
use sgx_trts::fence::lfence;
use sgx_trts::trts::is_within_enclave;
use sgx_tseal::seal::SealedData;
use sgx_tseal::seal::UnsealedData;
use sgx_types::types::c_char;
use sgx_types::types::c_void;
use std::io::Write;
use std::slice;
use std::sync::Mutex;
use std::sync::Once;
use std::vec::Vec;

static STATIC_INSTANCE: AtomicLazyCell<MtlsImpl<SGXCore>> = AtomicLazyCell::NONE;
static INIT: Once = Once::new();

fn init_once(rust_log_env: String) {
  INIT.call_once(|| {
    crate::mutex::MbetlstMutex::set_alt();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(rust_log_env))
      .format(|buf, record| {
        writeln!(
          buf,
          "[ENCLAVE_TIME {}\t{}] {}",
          record.level(),
          record.metadata().target(),
          record.args()
        )
      })
      .init();
    trace!("Initialized enclave log")
  });
}

#[no_mangle]
pub extern "C" fn ecall_import_keys(
  end_point_ptr: *const u8, end_point_len: usize, key_literal_ptr: *const u8,
  key_literal_len: usize, rust_log_env: *mut u8, rust_log_env_len: usize,
  err_buf: *mut MulTeeErrorBuf,
) {
  load_keys(
    end_point_ptr,
    end_point_len,
    key_literal_ptr,
    key_literal_len,
    rust_log_env,
    rust_log_env_len,
  )
  .and_then(|i| {
    STATIC_INSTANCE
      .fill(i)
      .map_err(|_| MulTeeErrCode::LAZY_CELL_FILLED.no_msg())
  })
  .unwrap_or_else(|e| encode(err_buf, e))
}

fn load_keys(
  end_point_ptr: *const u8, end_point_len: usize, key_literal_ptr: *const u8,
  key_literal_len: usize, rust_log_env: *mut u8, rust_log_env_len: usize,
) -> MulTeeResult<MtlsImpl<SGXCore>> {
  assert!(!is_within_enclave(
    rust_log_env as *const u8,
    rust_log_env_len
  ));
  lfence();
  let rust_log_env =
    String::from_utf8_lossy(unsafe { slice::from_raw_parts(rust_log_env, rust_log_env_len) })
      .to_string();
  // let rust_log_env = "info".to_string();

  init_once(rust_log_env);

  let args: MulTeeResult<Either<KMSEndPoint, Vec<KeyData>>> =
    if end_point_ptr != std::ptr::null() && key_literal_ptr == std::ptr::null() {
      Mutex::new(())
        .lock()
        .map_err(|_| MulTeeErrCode::UNEXPECTED_OR_IMPOSSIBLE.no_msg())
        .and_then(|_guard| {
          assert!(!is_within_enclave(
            end_point_ptr as *const u8,
            end_point_len
          ));
          lfence();

          let buf = unsafe { slice::from_raw_parts(end_point_ptr, end_point_len).to_vec() };

          postcard::from_bytes(buf.as_slice())
            .map_err(|_| MulTeeErrCode::KEY_IMPORT.no_msg())
            .map(Left)
        })
    } else if end_point_ptr == std::ptr::null() && key_literal_ptr != std::ptr::null() {
      assert!(!is_within_enclave(
        key_literal_ptr as *const u8,
        key_literal_len
      ));
      lfence();

      let buf = unsafe { slice::from_raw_parts(key_literal_ptr, key_literal_len).to_vec() };

      postcard::from_bytes(buf.as_slice())
        .map_err(|_| MulTeeErrCode::KEY_IMPORT.no_msg())
        .map(Right)
    } else {
      Err(MulTeeErrCode::KEY_IMPORT.no_msg())
    };

  SGXCore.import_keys(args?.as_ref())
}

#[no_mangle]
pub extern "C" fn ecall_mk_csr(
  sn: *const c_char, sn_len: usize, pinned: u8, csr: *mut u8, csr_len: *mut usize, pkey: *mut u8,
  pkey_len: *mut usize, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(sn_len < MAX_CSR_SN_LEN as usize);
  assert!(!is_within_enclave(sn as *const u8, sn_len as usize));
  assert!(!is_within_enclave(csr, MAX_CSR_PEM_LEN));
  assert!(!is_within_enclave(pkey, MAX_KEY_LEN));
  assert!(!is_within_enclave(csr_len as *const u8, size_of::<u32>()));
  assert!(!is_within_enclave(pkey_len as *const u8, size_of::<u32>()));
  lfence();

  let sn_bytes = unsafe { slice::from_raw_parts(sn as *const u8, sn_len) };
  let sn = String::from_utf8_lossy(sn_bytes);

  let pinned = pinned != 0;

  match instance().and_then(|e| e.mk_csr(&sn, pinned)) {
    Ok((csr_out, pkey_out)) => unsafe {
      *csr_len = csr_out.len();
      *pkey_len = pkey_out.len();
      slice::from_raw_parts_mut(pkey, pkey_out.len()).copy_from_slice(pkey_out.as_slice());
      slice::from_raw_parts_mut(csr, csr_out.len()).copy_from_slice(csr_out.as_slice());
    },
    Err(e) => encode(err_buf, e),
  };
}

#[inline]
fn instance() -> MulTeeResult<&'static MtlsImpl<SGXCore>> {
  STATIC_INSTANCE
    .borrow()
    .ok_or(MulTeeErrCode::KEY_IMPORT.no_msg())
}

#[no_mangle]
pub extern "C" fn ecall_get_public_key(
  key_index: usize, public_key: *mut u8, public_key_len: *mut usize, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(public_key, MAX_KEY_LEN));
  assert!(!is_within_enclave(
    public_key_len as *const u8,
    size_of::<u32>()
  ));
  lfence();

  match instance().and_then(|e| e.get_public_key(key_index)) {
    Ok(pk) => unsafe {
      *public_key_len = pk.len();
      slice::from_raw_parts_mut(public_key, pk.len()).copy_from_slice(pk.as_slice());
    },
    Err(err) => encode(err_buf, err),
  };
}

#[no_mangle]
pub extern "C" fn ecall_hmac_sha256(
  key_index: usize, input: *const u8, input_len: usize, output: *mut u8,
  err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(input, input_len));
  assert!(!is_within_enclave(output, MULTEE_HMAC256_BYTES));
  lfence();

  let input = unsafe { slice::from_raw_parts(input, input_len) };

  match instance().and_then(|e| e.hmac_sha256(key_index, input)) {
    Ok(hash) => unsafe {
      slice::from_raw_parts_mut(output, hash.len()).copy_from_slice(hash.as_slice());
    },
    Err(err) => encode(err_buf, err),
  };
}

#[inline]
fn encode(err_buf: *mut MulTeeErrorBuf, err: MulTeeError) {
  assert!(!is_within_enclave(
    err_buf as *const u8,
    size_of::<MulTeeErrorBuf>()
  ));
  let err_buf = unsafe { &mut *err_buf };
  err_buf.encode(err);
}

#[no_mangle]
pub extern "C" fn ecall_meta_key_usage(
  key_index: usize, key_usage: *mut u32, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(key_usage as *const u8, size_of::<u32>()));
  lfence();

  match instance().and_then(|e| e.meta_key_usage_mask(key_index)) {
    Ok(typ) => unsafe {
      *key_usage = typ as u32;
    },
    Err(err) => encode(err_buf, err),
  };
}

#[no_mangle]
pub extern "C" fn ecall_meta_key_type(
  key_index: usize, key_type: *mut u32, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(key_type as *const u8, size_of::<u32>()));
  lfence();

  match instance().and_then(|e| e.meta_key_type(key_index)) {
    Ok(typ) => unsafe {
      *key_type = typ as u32;
    },
    Err(err) => encode(err_buf, err),
  };
}

#[no_mangle]
pub extern "C" fn ecall_meta_key_len(
  key_index: usize, key_len: *mut u64, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(key_len as *const u8, size_of::<u64>()));
  lfence();

  match instance().and_then(|e| e.meta_key_len(key_index)) {
    Ok(len) => unsafe {
      *key_len = len;
    },
    Err(err) => encode(err_buf, err),
  };
}

#[no_mangle]
pub extern "C" fn ecall_meta_key_name(
  key_index: usize, key_name: *mut u8, key_name_len: *mut usize, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(key_name, MAX_KEY_NAME_LEN));
  assert!(!is_within_enclave(
    key_name_len as *const u8,
    size_of::<u32>()
  ));
  lfence();

  match instance().and_then(|e| e.meta_key_name(key_index)) {
    Ok(name) => unsafe {
      *key_name_len = name.len();
      slice::from_raw_parts_mut(key_name, name.len()).copy_from_slice(name.as_bytes());
    },
    Err(err) => encode(err_buf, err),
  };
}

#[no_mangle]
pub extern "C" fn ecall_meta_key_count(key_count: *mut u64, err_buf: *mut MulTeeErrorBuf) {
  assert!(!is_within_enclave(key_count as *const u8, size_of::<u64>()));
  lfence();

  match instance().and_then(|e| e.meta_key_count()) {
    Ok(len) => unsafe {
      *key_count = len;
    },
    Err(err) => encode(err_buf, err),
  };
}

#[no_mangle]
pub extern "C" fn ecall_crypt_cbc(
  key_index: usize, encrypt: usize, explicit_iv: usize, iv: *mut u8, crypto_buf: *mut u8,
  input_len: usize, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(crypto_buf, input_len));
  assert!(!is_within_enclave(iv, MULTEE_BLOCK_SIZE));
  assert_eq!(input_len % MULTEE_BLOCK_SIZE, 0);

  lfence();

  let crypto_buf = unsafe { slice::from_raw_parts_mut(crypto_buf, input_len) };
  let iv = unsafe { slice::from_raw_parts_mut(iv, MULTEE_BLOCK_SIZE) };

  instance()
    .and_then(|e| {
      e.crypt_cbc(
        key_index,
        to_bool(encrypt),
        to_bool(explicit_iv),
        iv,
        crypto_buf,
        input_len,
      )
    })
    .unwrap_or_else(|err| encode(err_buf, err));
}

#[no_mangle]
pub extern "C" fn ecall_crypt_gcm(
  key_index: usize, encrypt: bool, iv: *const u8, aad: *const u8, aad_len: usize,
  in_buf: *const u8, out_buf: *mut u8, input_len: usize, tag: *mut u8,
  err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(iv, MULTEE_GCM_IV_BYTES));
  assert!(!is_within_enclave(aad, aad_len));
  assert!(!is_within_enclave(in_buf, input_len));
  assert!(!is_within_enclave(out_buf, input_len));

  if aad != std::ptr::null() {
    assert!(!is_within_enclave(aad, aad_len));
  }
  lfence();

  let in_buf = unsafe { slice::from_raw_parts(in_buf, input_len) };
  let out_buf = unsafe { slice::from_raw_parts_mut(out_buf, input_len) };
  let iv = unsafe { slice::from_raw_parts_mut(iv as *mut u8, MULTEE_GCM_IV_BYTES) };
  let tag = unsafe { slice::from_raw_parts_mut(tag as *mut u8, MULTEE_GCM_TAG_BYTES) };

  let aad = if aad != std::ptr::null() {
    unsafe { Some(slice::from_raw_parts(aad, aad_len)) }
  } else {
    None
  };

  instance()
    .and_then(|e| e.crypt_gcm(key_index, encrypt, iv, aad, in_buf, out_buf, tag))
    .unwrap_or_else(|err| encode(err_buf, err));
}

#[no_mangle]
pub extern "C" fn ecall_sign(
  key_index: usize, plaintext: *const u8, plaintext_len: usize, padding: *const c_void,
  md_type: u32, signature: *mut u8, signature_len: *mut usize, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(plaintext, plaintext_len));
  assert!(!is_within_enclave(signature, MULTEE_SIG_LEN_MAX));
  if padding != std::ptr::null() {
    assert!(!is_within_enclave(
      padding as *const u8,
      size_of::<RsaPadding>()
    ));
  }
  lfence();

  let plaintext = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };

  let padding = if padding != std::ptr::null() {
    let ptr = padding as *const RsaPadding;
    unsafe { Some(((*ptr).0, (*ptr).1)) }
  } else {
    None
  };

  // let md_type: mbedtls_md_type_t = unsafe { ::std::mem::transmute(md_type) };
  let hashing_alg = kmip::enumerations::HashingAlgorithm::fromu32(md_type).unwrap();

  match instance().and_then(|e| e.sign(key_index, padding, hashing_alg, plaintext)) {
    Ok(sig_out) => unsafe {
      *signature_len = sig_out.len();
      slice::from_raw_parts_mut(signature, sig_out.len()).copy_from_slice(sig_out.as_slice());
    },
    Err(err) => encode(err_buf, err),
  }
}

#[no_mangle]
pub extern "C" fn ecall_seal_pk(
  pem: *const u8, in_len: usize, sealed: *mut u8, out_len: *mut usize, err_buf: *mut MulTeeErrorBuf,
) {
  assert!(!is_within_enclave(pem, MAX_KEY_LEN as usize));
  assert!(!is_within_enclave(sealed, MAX_KEY_LEN as usize));
  assert!(!is_within_enclave(out_len as *const u8, size_of::<u32>()));
  lfence();

  let input = unsafe { slice::from_raw_parts(pem, in_len as usize) }.to_vec();
  assert!(input.len() < MAX_KEY_LEN as usize - 768);

  match SGXCore::seal_data(input.as_slice()) {
    Ok(sealed_data) => unsafe {
      *out_len = sealed_data.len();
      slice::from_raw_parts_mut(sealed, sealed_data.len()).copy_from_slice(sealed_data.as_slice());
    },
    Err(err) => encode(err_buf, err),
  };
}

static AADD: &str = "MulTee-Sealed";

#[derive(Copy, Clone)]
struct SGXCore;

impl Tee for SGXCore {
  fn seal_data(input: &[u8]) -> MulTeeResult<Vec<u8>> {
    let data: SealedData<[u8]> =
      SealedData::seal(input, Some(AADD.as_bytes())).map_err(|e| MulTeeErrCode::SGX_SEAL.msg(e))?;

    data
      .into_bytes()
      .map_err(|e| crate::to_err(MulTeeErrCode::SGX_SEAL, e))
  }
  fn unseal_data(sealed_data: &[u8]) -> MulTeeResult<Vec<u8>> {
    UnsealedData::<[u8]>::unseal_from_slice(sealed_data)
      .map_err(|e| crate::to_err(MulTeeErrCode::SGX_SEAL, e))
      .map(|x| x.to_plaintext().to_vec())
  }
  fn unseal_pk(pk_bytes: &[u8]) -> MulTeeResult<Vec<u8>> {
    let is_unencrypted = pk_bytes
      .windows(UNENCRYPTED_HEADER.len())
      .any(|w| w == UNENCRYPTED_HEADER);

    if is_unencrypted {
      Ok(pk_bytes.to_vec())
    } else {
      Self::unseal_data(pk_bytes)
    }
  }
  fn attestation(payload: &[u8]) -> MulTeeResult<Value> {
    crate::attestation::get_guote(payload)
  }
  fn attestation_kind() -> String {
    "dcap".to_string()
  }
}
