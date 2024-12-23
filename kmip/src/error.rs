use crate::constants::enumerations::ResultReason;
use crate::ttlv::TtlvError;
use core::fmt::Display;
use std::fmt;

#[derive(Debug)]
pub enum KmipError {
  Ttlv(TtlvError),
  RequestFailed(ResultReason, String),
  UnsupportedAlgorithm,
  UnsupportedPaddingMethod,
  UnsupportedHashingAlgorithm,
  UnsupportedBlockCipherMode,
  UnsupportedOperation,
  UnsupportedObjectType,
  UnsupportedUsage,
  UnsupportedBatchCount,
  CorruptStructure,
}

impl From<TtlvError> for KmipError {
  fn from(e: TtlvError) -> Self {
    Self::Ttlv(e)
  }
}

impl Display for KmipError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}
impl std::error::Error for KmipError {}
