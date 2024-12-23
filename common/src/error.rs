#![allow(non_camel_case_types)]

use core::fmt::{self, Display};
use core::str::{from_utf8, Utf8Error};
use std::string::FromUtf8Error;
use strum_macros::EnumIter;
use strum_macros::FromRepr;
use strum_macros::IntoStaticStr;

pub type MulTeeResult<T> = Result<T, MulTeeError>;

#[derive(Debug)]
pub struct MulTeeError {
  pub tag: MulTeeErrCode,
  pub sub: i32,
  pub message: Option<String>,
}

impl Display for MulTeeError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      MulTeeError {
        tag,
        sub: 0,
        message: None,
      } => write!(f, "{:?}", tag),
      MulTeeError {
        tag,
        sub: 0,
        message: Some(msg),
      } => write!(f, "{:?} ({})", tag, msg),
      MulTeeError {
        tag,
        sub,
        message: None,
      } => write!(f, "{:?}[{}]", tag, sub),
      MulTeeError {
        tag,
        sub,
        message: Some(msg),
      } => write!(f, "{:?}[{}] ({})", tag, sub, msg),
    }
  }
}

impl std::error::Error for MulTeeError {}

#[derive(Copy, Clone, Debug, Eq, PartialEq, FromRepr, EnumIter, IntoStaticStr)]
#[repr(u32)]
pub enum MulTeeErrCode {
  SUCCESS = 0,
  CORRUPT_UTF8 = 1,
  CORRUPT_JSON = 2,
  CORRUPT_YAML = 3,
  CORRUPT_URI = 4,
  CORRUPT_BASE64 = 5,
  CORRUPT_HEX = 6,
  JSON_KEY_NOT_FOUND = 7,

  KMIP = 10,

  SGX_INIT = 20,
  SGX_ECALL = 21,
  SGX_SEAL = 22,
  SGX_KEY_DERIVATION = 23,
  SGX_QE3 = 24,
  SGX_OCALL = 25,
  SGX_REPORT = 26,

  CREDENTIALS = 31,
  CREDENTIALS_PINNING = 32,
  CREDENTIALS_IO = 33,
  ENCLAVE_ARTIFACT_IO = 34,
  UNSUPPORTED_PLATFORM = 35,
  API_MISUSE = 36,

  LOG_IO = 40,

  RUSTLS_IO = 50,

  KEY_IMPORT = 60,
  TRIPLE_A_NOK = 61,
  TRIPLE_A_PROTOCOL_VIOLATION = 62,

  CRYPTO_UNSUPPORTED_SCHEME_FOR_KEY_IMPORT = 100,
  CRYPTO_UNSUPPORTED_CIPHER_MODE = 101,
  CRYPTO_KEYS_ALREADY_IMPORTED = 102,
  CRYPTO_UNEXPECTED_ALG_OR_LEN = 104,
  CRYPTO_ALG_MISMATCH = 105,
  CRYPTO_UNSUPPORTED_HASH = 106,
  CRYPTO_PROHIBITED_USAGE = 107,
  CRYPTO_AUTH_TAG_VERIFY_FAILED = 108,
  CRYPTO_AUTH_TAG_LEN_MISMATCH = 109,
  CRYPTO_MAC_LEN_MISMATCH = 110,
  CRYPTO_CIPHERTEXT_LEN_MISMATCH = 111,
  CRYPTO_BAD_PADDING = 112,
  CRYPTO_BUFFER_TOO_SMALL = 113,
  CRYPTO_INVALID_IV_LENGTH = 114,
  CRYPTO_INVALID_KEY_INDEX = 115,
  CRYPTO_INVALID_KEY_NAME = 116,
  CRYPTO_INVALID_ARGUMENTS = 117,

  CRYPTO_MBED = 200,
  // CRYPTO_MBED2(u32)  = 201,
  // CRYPTO_MBED3{ other: i64}  = 202,
  A3_ERROR = 300,
  A3_WARNING = 301,

  HTTP_MALFORMATTED_RESPONSE = 70,
  // VAULT_LOGIN_NOK = 71,
  // VAULT_GET_NOK = 72,
  MACHINE_INFO_NOT_FOUND = 73,

  OBFUSCATION_FAILED = 74,

  LAZY_CELL_FILLED = 75,
  LAZY_CELL_EMPTY = 76,

  PKCS11_PROTOCOL_VIOLATION = 80,

  UNEXPECTED_OR_IMPOSSIBLE = 90,

  SEVSNP_REPORT = 150,
}

impl MulTeeErrCode {
  pub fn nested<M: Display>(self, sub_err_code: i32, msg: M) -> MulTeeError {
    MulTeeError {
      tag: self,
      sub: sub_err_code,
      message: Some(msg.to_string()),
    }
  }
  pub fn msg<M: Display>(self, tag_msg: M) -> MulTeeError {
    MulTeeError {
      tag: self,
      sub: 0,
      message: Some(tag_msg.to_string()),
    }
  }
  pub const fn no_msg(self) -> MulTeeError {
    MulTeeError {
      tag: self,
      sub: 0,
      message: None,
    }
  }
}

// pub const MAX_ERR_MESSAGE_LENGTH: usize = 4096;

pub struct MulTeeErrorBuf {
  tag: u32,
  sub: i32,
  message_len: usize,
  message: [u8; MulTeeErrorBuf::MAX_ERR_MESSAGE_LENGTH],
}

impl MulTeeErrorBuf {
  pub const MAX_ERR_MESSAGE_LENGTH: usize = 4096;

  pub const fn new() -> Self {
    MulTeeErrorBuf {
      tag: MulTeeErrCode::SUCCESS as u32,
      message_len: 0,
      sub: 0,
      message: [0u8; 4096],
    }
  }
  pub fn reset(&mut self) {
    self.tag = MulTeeErrCode::SUCCESS as u32;
    self.sub = 0;
  }
  pub fn encode(&mut self, error: MulTeeError) {
    self.tag = error.tag as u32;
    self.sub = error.sub;

    if let Some(ref err_msg) = error.message {
      self.message_len = MulTeeErrorBuf::truncate_str(err_msg);
      (&mut self.message[..self.message_len]).copy_from_slice(err_msg.as_bytes());
    } else {
      self.message_len = 0;
    }
  }
  pub fn to_result(&self) -> MulTeeResult<()> {
    if self.tag == MulTeeErrCode::SUCCESS as u32 {
      Ok(())
    } else {
      let tag = MulTeeErrCode::from_repr(self.tag).expect("impossible - all tags come from Enum");
      let message = if self.message_len > 0 {
        Some(String::from(
          from_utf8(&self.message[..self.message_len])
            .expect("impossible - all messages are utf8 in Enum"),
        ))
      } else {
        None
      };
      Err(MulTeeError {
        tag,
        sub: self.sub,
        message,
      })
    }
  }
  fn truncate_str(input: &str) -> usize {
    if input.len() <= MulTeeErrorBuf::MAX_ERR_MESSAGE_LENGTH {
      input.len()
    } else {
      let mut idx = MulTeeErrorBuf::MAX_ERR_MESSAGE_LENGTH;
      while !input.is_char_boundary(idx) {
        idx -= 1;
      }
      idx
    }
  }
}
impl From<MulTeeErrCode> for MulTeeError {
  fn from(tag: MulTeeErrCode) -> Self {
    tag.no_msg()
  }
}
impl From<Utf8Error> for MulTeeError {
  fn from(_utf8_err: Utf8Error) -> Self {
    MulTeeErrCode::CORRUPT_UTF8.into()
  }
}
impl From<FromUtf8Error> for MulTeeError {
  fn from(_utf8_err: FromUtf8Error) -> Self {
    MulTeeErrCode::CORRUPT_UTF8.no_msg()
  }
}
impl From<kmip::error::KmipError> for MulTeeError {
  fn from(kmip_err: kmip::error::KmipError) -> Self {
    MulTeeError {
      tag: MulTeeErrCode::KMIP,
      sub: 0,
      message: Some(format!("{:?}", kmip_err)),
    }
  }
}
impl From<kmip::ttlv::TtlvError> for MulTeeError {
  fn from(ttlv_err: kmip::ttlv::TtlvError) -> Self {
    let kmip_err: kmip::error::KmipError = ttlv_err.into();
    kmip_err.into()
  }
}

// impl From<(MulTeeErrCode, &str)> for MulTeeError {
//   fn from(tag_msg: (MulTeeErrCode, &str)) -> Self {
//     tag_msg.0.opt_msg(Some(tag_msg.1))
//     // MulTeeError { tag: tag_msg.0, sub: 0, message: Some(format!("{}", tag_msg.1)) }
//   }
// }
// impl From<(MulTeeErrCode, i32, String)> for MulTeeError {
//   fn from(tag_msg: (MulTeeErrCode, i32, String)) -> Self {
//     // println!("From {}",tag_msg.1);
//     MulTeeError { tag: tag_msg.0, sub: tag_msg.1, message: Some(tag_msg.2) }
//   }
// }
// impl From<Utf8Error> for Error {
//   fn from(_: Utf8Error) -> Self {
//     Error::CorruptUtf8
//   }
// }
