use core::convert::Into;
use std::{
  boxed::Box,
  ffi::{CStr, CString},
  os::raw::c_char,
  slice,
};

use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use common::from_bool;
use common::to_bool;
use kmip::enumerations::CryptographicAlgorithm;

use common::constants::MAX_CIPHERTEXT_EXPANSION;
use common::constants::MULTEE_BLOCK_SIZE;
use common::constants::MULTEE_GCM_IV_BYTES;
use common::constants::MULTEE_GCM_TAG_BYTES;
use multee_core::api::{DEFAULT_SIG_HASH, DEFAULT_SIG_PADDING};

use multee_lib::api::EnclaveSession;

#[repr(C)]
pub struct CGoUnit {
  status: i32,
  sub: i32,
  err: *const c_char,
}

#[repr(C)]
pub struct CGoLong {
  val: usize,
  status: i32,
  sub: i32,
  err: *const c_char,
}
#[repr(C)]
pub struct CGoBool {
  val: usize,
  status: i32,
  sub: i32,
  err: *const c_char,
}

// #[repr(C)]
// pub(crate) struct CGotStr {
//   val: *const c_char,
//   err: *const c_char,
// }

trait IntoRust<T: ?Sized> {
  fn into_rust(self) -> &'static T;
}

trait IntoRustMut<T: ?Sized> {
  fn into_rust(self) -> &'static mut T;
}

impl IntoRust<str> for *const c_char {
  fn into_rust(self) -> &'static str {
    unsafe { CStr::from_ptr(self) }
      .to_str()
      .expect("Received corrupt UTF8 from Go")
  }
}

impl<T> IntoRust<[T]> for (*const T, usize) {
  fn into_rust(self) -> &'static [T] {
    unsafe { slice::from_raw_parts(self.0, self.1) }
  }
}

impl<T> IntoRustMut<[T]> for (*mut T, usize) {
  fn into_rust(self) -> &'static mut [T] {
    unsafe { slice::from_raw_parts_mut(self.0, self.1) }
  }
}

impl From<MulTeeResult<usize>> for CGoLong {
  fn from(result: MulTeeResult<usize>) -> Self {
    match result {
      Ok(val) => CGoLong {
        val,
        status: MulTeeErrCode::SUCCESS as i32,
        sub: 0,
        err: std::ptr::null(),
      },
      Err(err) => CGoLong {
        val: 0,
        status: err.tag as i32,
        sub: err.sub,
        err: opt_string_to_ptr(err.message),
      },
    }
  }
}

impl From<MulTeeResult<bool>> for CGoBool {
  fn from(result: MulTeeResult<bool>) -> Self {
    match result {
      Ok(val) => CGoBool {
        val: from_bool(val),
        status: MulTeeErrCode::SUCCESS as i32,
        sub: 0,
        err: std::ptr::null(),
      },
      Err(err) => CGoBool {
        val: 0,
        status: err.tag as i32,
        sub: err.sub,
        err: opt_string_to_ptr(err.message),
      },
    }
  }
}

impl From<MulTeeResult<()>> for CGoUnit {
  fn from(result: MulTeeResult<()>) -> Self {
    match result {
      Ok(_) => CGoUnit {
        status: MulTeeErrCode::SUCCESS as i32,
        sub: 0,
        err: std::ptr::null(),
      },
      Err(err) => CGoUnit {
        status: err.tag as i32,
        sub: err.sub,
        err: opt_string_to_ptr(err.message),
      },
    }
  }
}

// impl<T: Into<String>> From<MulTeeResult<T>> for CGotStr {
//   fn from(result: MulTeeResult<T>) -> Self {
//     match result {
//       Ok(val) => {
//         let ret_val = CString::new(val.into()).unwrap();
//         CGotStr { val: ret_val.into_raw(), err: std::ptr::null() }
//       }
//       Err(err) => {
//         let err_msg = CString::new(format!("{:?}", err)).unwrap();
//         CGotStr { val: std::ptr::null(), err: err_msg.into_raw() }
//       }
//     }
//   }
// }

fn opt_string_to_ptr(opt_s: Option<String>) -> *const c_char {
  match opt_s {
    None => std::ptr::null(),
    Some(s) => CString::new(s)
      .expect("Impossible - zero inside utf8 string")
      .into_raw(),
  }
}

#[no_mangle]
pub extern "C" fn multee_free_rust_str(r_str: *const c_char) {
  if !r_str.is_null() {
    unsafe {
      drop(CString::from_raw(r_str as *mut c_char));
    }
  }
}

#[no_mangle]
pub extern "C" fn multee_destroy(enc_sess: usize) {
  unsafe {
    let _ = Box::from_raw(enc_sess as *mut EnclaveSession);
  };
}

#[no_mangle]
pub extern "C" fn multee_load_keys(
  uri: *const c_char, key_names: *const *const c_char, num_keys: usize, creds_path: *const c_char,
) -> CGoLong {
  let uri = uri.into_rust();
  let key_names: Vec<String> = (key_names, num_keys)
    .into_rust()
    .iter()
    .map(|c_key_name| c_key_name.into_rust().to_string())
    .collect();
  let creds_path = creds_path.into_rust();

  EnclaveSession::load_keys(creds_path, uri, key_names, None)
    .map(|enc_sess| Box::into_raw(Box::new(enc_sess)) as usize)
    .into()
}

#[no_mangle]
pub extern "C" fn multee_crypt_cbc(
  enc_sess: usize, key_index: usize, encrypt: usize, explicit_iv: usize, iv: *mut u8,
  crypto_buf: *mut u8, input_len: usize,
) -> CGoLong {
  let crypto_buf_len = input_len + MAX_CIPHERTEXT_EXPANSION;

  let enc_sess: &EnclaveSession = unsafe { &*(enc_sess as *const EnclaveSession) };

  // let padding = true; // TODO: decide whether is needed
  let iv: &mut [u8] = unsafe { slice::from_raw_parts_mut(iv, MULTEE_BLOCK_SIZE) };

  let crypto_buf = (crypto_buf, crypto_buf_len).into_rust();

  if to_bool(encrypt) {
    enc_sess
      .encrypt_cbc(key_index, to_bool(explicit_iv), iv, crypto_buf, input_len)
      .into()
  } else {
    enc_sess
      .decrypt_cbc(key_index, to_bool(explicit_iv), iv, crypto_buf, input_len)
      .into()
  }
}

#[no_mangle]
pub extern "system" fn multee_key_length(enc_sess: usize, key_index: usize) -> CGoLong {
  let enc_sess: &EnclaveSession = unsafe { &*(enc_sess as *const EnclaveSession) };

  let key_index = key_index as usize;

  enc_sess.key_len(key_index).map(|v| v as usize).into()
}

#[no_mangle]
pub extern "C" fn multee_crypt_gcm(
  enc_sess: usize, key_index: usize, encrypt: usize, aad: *const u8, aad_len: usize,
  crypto_buf: *mut u8, input_len: usize, iv: *mut u8, tag: *mut u8,
) -> CGoUnit {
  let enc_sess: &EnclaveSession = unsafe { &*(enc_sess as *const EnclaveSession) };

  let buf = (crypto_buf, input_len).into_rust();

  let aad = match aad_len {
    0 => None,
    _ => Some((aad, aad_len).into_rust()),
  };

  let result = if to_bool(encrypt) {
    enc_sess
      .encrypt_gcm(key_index, aad, buf)
      .map(|(out, iv_vec, tag_vec)| {
        (crypto_buf, input_len)
          .into_rust()
          .copy_from_slice(out.as_slice());
        (iv, MULTEE_GCM_IV_BYTES)
          .into_rust()
          .copy_from_slice(iv_vec.as_slice());
        (tag, MULTEE_GCM_TAG_BYTES)
          .into_rust()
          .copy_from_slice(tag_vec.as_slice());
      })
  } else {
    let iv = (iv, MULTEE_GCM_IV_BYTES).into_rust();
    let tag = (tag, MULTEE_GCM_TAG_BYTES).into_rust();

    enc_sess
      .decrypt_gcm(key_index, aad, buf, iv, tag)
      .map(|out| {
        (crypto_buf, input_len)
          .into_rust()
          .copy_from_slice(out.as_slice())
      })
  };

  result.into()
}

#[no_mangle]
pub extern "C" fn multee_hmac_sha256(
  enc_sess: usize, key_index: usize, input: *const u8, input_len: usize, output: *mut u8,
) -> CGoUnit {
  let enc_sess: &EnclaveSession = unsafe { &*(enc_sess as *const EnclaveSession) };

  let input = (input, input_len).into_rust();
  enc_sess
    .hmac_sha256(key_index, input)
    .map(|out| {
      (output, out.len())
        .into_rust()
        .copy_from_slice(out.as_slice())
    })
    .into()
}

#[no_mangle]
pub extern "C" fn multee_sign(
  enc_sess: usize, key_index: usize, input: *const u8, input_len: usize, output: *mut u8,
  output_len: *mut usize,
) -> CGoUnit {
  let enc_sess: &EnclaveSession = unsafe { &*(enc_sess as *const EnclaveSession) };

  let input = (input, input_len).into_rust();

  enc_sess
    .sign(
      key_index,
      Some(DEFAULT_SIG_PADDING),
      DEFAULT_SIG_HASH,
      input,
    )
    .map(|out| {
      (output, out.len())
        .into_rust()
        .copy_from_slice(out.as_slice());
      unsafe { *output_len = out.len() };
    })
    .into()
}

#[no_mangle]
pub extern "C" fn multee_verify(
  enc_sess: usize, key_index: usize, message: *const u8, message_len: usize, signature: *const u8,
  signature_len: usize,
) -> CGoBool {
  let enc_sess: &EnclaveSession = unsafe { &*(enc_sess as *const EnclaveSession) };

  let msg = (message, message_len).into_rust();
  let sig = (signature, signature_len).into_rust();

  let is_rsa = matches!(
    enc_sess.get_key_type(key_index),
    Ok(CryptographicAlgorithm::RSA)
  );

  let padding = if is_rsa {
    Some(DEFAULT_SIG_PADDING)
  } else {
    None
  };

  enc_sess
    .verify(key_index, padding, DEFAULT_SIG_HASH, msg, sig)
    .into()
}
