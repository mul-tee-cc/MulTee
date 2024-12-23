use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

pub trait FromU32: FromPrimitive {
  #[inline]
  fn fromu32(val: u32) -> Option<Self> {
    Self::from_u32(val)
  }
}

#[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
#[repr(u16)]
pub enum Tag {
  Attribute = 0x0008,
  AttributeIndex = 0x0009,
  AttributeName = 0x000A,
  AttributeValue = 0x000B,
  Authentication = 0x000C,
  BatchCount = 0x000D,
  BatchItem = 0x000F,
  BlockCipherMode = 0x0011,
  Credential = 0x0023,
  CredentialType = 0x0024,
  CredentialValue = 0x0025,
  CryptographicAlgorithm = 0x0028,
  CryptographicLength = 0x002A,
  CryptographicParameters = 0x002B,
  HashingAlgorithm = 0x0038,
  IvCounterNonce = 0x003D,
  KeyBlock = 0x0040,
  KeyCompressionType = 0x0041,
  KeyFormatType = 0x0042,
  KeyMaterial = 0x0043,
  KeyPartIdentifier = 0x0044,
  KeyValue = 0x0045,
  Name = 0x0053,
  NameType = 0x0054,
  NameValue = 0x0055,
  ObjectType = 0x0057,
  Operation = 0x005C,
  PaddingMethod = 0x005F,
  PrivateKey = 0x0064,
  ProtocolVersion = 0x0069,
  PublicKey = 0x006D,
  ProtocolVersionMajor = 0x006A,
  ProtocolVersionMinor = 0x006B,
  RequestHeader = 0x0077,
  RequestMessage = 0x0078,
  RequestPayload = 0x0079,
  ResponseHeader = 0x007A,
  ResponseMessage = 0x007B,
  ResponsePayload = 0x007C,
  ResultMessage = 0x007D,
  ResultReason = 0x007E,
  ResultStatus = 0x007F,
  SymmetricKey = 0x008F,
  TimeStamp = 0x0092,
  UniqueBatchItemId = 0x0093,
  UniqueIdentifier = 0x0094,
  Username = 0x0099,
  Password = 0x00A1,
  DigitalSignatureAlgorithm = 0x00AE,
  Data = 0x00C2,
  SignatureData = 0x00C3,
  DataLength = 0x00C4,
  RandomIV = 0x00C5,
  MacData = 0x00C6,
  IvLength = 0x00CD,
  TagLength = 0x00CE,
  AuthenticatedEncryptionAdditionalData = 0x00FE,
  AuthenticatedEncryptionTag = 0x00FF,
  DigestedData = 0x0107,
}

// http://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html#_Toc490660920
pub mod enumerations {
  use num_derive::FromPrimitive;
  use serde::{Deserialize, Serialize};
  // use num_traits::FromPrimitive;
  use crate::constants::FromU32;
  // use num_traits::FromPrimitive;

  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum CredentialType {
    UsernamePassword = 0x0000_0001,
    Device = 0x0000_0002,
    Attestation = 0x0000_0003,
  }
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive, Serialize, Deserialize)]
  #[repr(u32)]
  pub enum ObjectType {
    Certificate = 0x0000_0001,
    SymmetricKey = 0x0000_0002,
    PublicKey = 0x0000_0003,
    PrivateKey = 0x0000_0004,
  }
  impl FromU32 for ObjectType {}
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive, Serialize, Deserialize)]
  #[repr(u32)]
  pub enum CryptographicAlgorithm {
    AES = 0x0000_0003,
    RSA = 0x0000_0004,
    ECDSA = 0x0000_0006,
    #[allow(non_camel_case_types)]
    HMAC_SHA256 = 0x0000_0009,
    // ECDH = 0x0000_000E,
    // EC = 0x0000_001A,
    SM4 = 0x0000_002D,
  }
  impl FromU32 for CryptographicAlgorithm {}
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive, Serialize, Deserialize)]
  #[repr(u32)]
  pub enum DigitalSignatureAlgorithm {
    // #[allow(non_camel_case_types)]
    // SHA256_WITH_RSA = 0x0000_0005,
    #[allow(non_camel_case_types)]
    RSASSA_PSS = 0x0000_0008,
    #[allow(non_camel_case_types)]
    ECDSA_WITH_SHA256 = 0x0000_000E,
  }
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum CryptographicUsageMask {
    Sign = 0x0000_0001,
    Verify = 0x0000_0002,
    Encrypt = 0x0000_0004,
    Decrypt = 0x0000_0008,
    MACGenerate = 0x0000_0080,
  }
  impl FromU32 for CryptographicUsageMask {}
  // impl CryptographicUsageMask {
  //   #[inline]
  //   pub fn from(val: u32) -> Option<Self> {
  //     Self::from_u32(val)
  //   }
  // }
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum BlockCipherMode {
    CBC = 0x0000_0001,
    ECB = 0x0000_0002,
    GCM = 0x0000_0009,
  }
  impl FromU32 for BlockCipherMode {}
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum PaddingMethod {
    None = 0x0000_0001,
    OAEP = 0x0000_0002,
    PKCS5 = 0x0000_0003,
    #[allow(non_camel_case_types)]
    PKCS1_V1_5 = 0x0000_0008,
    PSS = 0x0000_000A,
  }
  impl FromU32 for PaddingMethod {}
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum HashingAlgorithm {
    SHA256 = 0x0000_0006,
    SHA384 = 0x0000_0007,
    SHA512 = 0x0000_0008,
  }
  impl FromU32 for HashingAlgorithm {}
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum Operation {
    Locate = 0x0000_0008,
    Get = 0x0000_000A,
    GetAttributes = 0x0000_000B,
    Activate = 0x0000_0012,
    Encrypt = 0x0000_001F,
    Decrypt = 0x0000_0020,
    Sign = 0x0000_0021,
    Mac = 0x0000_0023,
    // Export = 0x0000_002B,
  }
  impl FromU32 for Operation {}
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum Name {
    UninterpretedTextString = 0x0000_0001,
    Uri = 0x0000_0002,
  }
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum ResultStatus {
    Success = 0x0000_0000,
    Failed = 0x0000_0001,
    Pending = 0x0000_0002,
    Undone = 0x0000_0003,
  }
  #[derive(Copy, Clone, Eq, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum ResultReason {
    ItemNotFound = 0x0000_0001,
    ResponseTooLarge,
    AuthenticationNotSuccessful,
    InvalidMessage,
    OperationNotSupported,
    MissingData,
    InvalidField,
    FeatureNotSupported,
    OperationCanceled,
    CryptographicFailure,
    IllegalOperation,
    PermissionDenied,
    ObjectArchived,
    IndexOutOfBounds,
    NamespaceNotSupported,
    KeyFormatTypeNotSupported,
    KeyCompressionTypeNotSupported,
    EncodingOptionError,
    KeyValueNotPresent,
    AttestationRequired,
    AttestationFailed,
    Sensitive,
    NotExtractable,
    ObjectAlreadyExists,
    GeneralFailure = 0x0000_0100,
  }
  impl FromU32 for ResultReason {}
  #[derive(Copy, Clone, PartialEq, Debug, FromPrimitive)]
  #[repr(u32)]
  pub enum QueryFunction {
    QueryOperations = 0x0000_0001,
    QueryObjects,
    QueryServerInformation,
  }
}
