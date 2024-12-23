use crate::constants::enumerations::CryptographicAlgorithm;
use crate::constants::enumerations::CryptographicUsageMask;
use crate::constants::FromU32;
use crate::constants::Tag;
use crate::enumerations::HashingAlgorithm;
use crate::enumerations::{BlockCipherMode, PaddingMethod};
use crate::error::KmipError;
use crate::ttlv::Ttlv;

pub const KMIP_PROTOCOL_VERSION: (i32, i32) = (1, 4);

const SUPPORTED_USAGES: u32 = CryptographicUsageMask::Encrypt as u32
  | CryptographicUsageMask::Decrypt as u32
  | CryptographicUsageMask::Sign as u32
  | CryptographicUsageMask::MACGenerate as u32
  | CryptographicUsageMask::Verify as u32;

#[derive(Clone, Debug)]
pub struct KmipRequest {
  pub protocol_version_major: i32,
  pub protocol_version_minor: i32,
  pub maximum_response_size: Option<i32>,
  pub authentication: Option<Auth>,
  pub requests: Vec<KmipOp>,
}

#[derive(Clone, Debug)]
pub struct Auth {
  pub username: String,
  pub password: String,
}

#[derive(Clone, Debug)]
pub enum KmipOp {
  Locate(String),
  GetAttrs(String),
  Get(String),
  MAC(String, CryptographicAlgorithm, Vec<u8>),
  Sign(
    String,
    Option<(PaddingMethod, HashingAlgorithm)>,
    HashingAlgorithm,
    Vec<u8>,
  ),

  EncryptGCM(
    String,
    CryptographicAlgorithm,
    Vec<u8>,
    Option<Vec<u8>>,
    (usize, usize),
  ),
  DecryptGCM(
    String,
    CryptographicAlgorithm,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    Vec<u8>,
  ),
  EncryptCBC(String, CryptographicAlgorithm, Vec<u8>, Option<Vec<u8>>),
  DecryptCBC(String, CryptographicAlgorithm, Vec<u8>, Vec<u8>),
}

pub mod request {
  use super::{KmipOp, KMIP_PROTOCOL_VERSION};
  use crate::constants::{enumerations::*, FromU32, Tag};
  use crate::error::KmipError;
  pub use crate::hmac::request;
  use crate::ttlv::{Ttlv, Value::*};
  use crate::{hmac, parse_algo, parse_data, parse_mode, sign};

  pub fn build<'a>(
    credentials: &'a Option<(String, String)>, (operation, payload): (Operation, Ttlv<'a>),
  ) -> Ttlv<'a> {
    let mut request_header = vec![
      Ttlv::new(
        Tag::ProtocolVersion,
        Structure(vec![
          Ttlv::new(
            Tag::ProtocolVersionMajor,
            Integer(crate::kmip::KMIP_PROTOCOL_VERSION.0),
          ),
          Ttlv::new(Tag::ProtocolVersionMinor, Integer(KMIP_PROTOCOL_VERSION.1)),
        ]),
      ),
      Ttlv::new(Tag::BatchCount, Integer(1)),
    ];

    // TODO: get rid of Vec
    if let Some((username, password)) = credentials {
      request_header.push(Ttlv::new(
        Tag::Authentication,
        Structure(vec![Ttlv::new(
          Tag::Credential,
          Structure(vec![
            Ttlv::new(
              Tag::CredentialType,
              Enumeration(CredentialType::UsernamePassword as u32),
            ),
            Ttlv::new(
              Tag::CredentialValue,
              Structure(vec![
                Ttlv::new(Tag::Username, TextString(username)),
                Ttlv::new(Tag::Password, TextString(password)),
              ]),
            ),
          ]),
        )]),
      ));
    }

    Ttlv::new(
      Tag::RequestMessage,
      Structure(vec![
        Ttlv::new(Tag::RequestHeader, Structure(request_header)),
        Ttlv::new(
          Tag::BatchItem,
          Structure(vec![
            Ttlv::new(Tag::Operation, Enumeration(operation as u32)),
            payload,
          ]),
        ),
      ]),
    )
  }

  pub fn locate_key(key_name: &str) -> (Operation, Ttlv) {
    let payload = Ttlv::new(
      Tag::RequestPayload,
      Structure(vec![Ttlv::new(
        Tag::Attribute,
        Structure(vec![
          Ttlv::new(Tag::AttributeName, TextString("Name")),
          Ttlv::new(
            Tag::AttributeValue,
            Structure(vec![
              Ttlv::new(Tag::NameValue, TextString(key_name)),
              Ttlv::new(
                Tag::NameType,
                Enumeration(Name::UninterpretedTextString as u32),
              ),
            ]),
          ),
        ]),
      )]),
    );
    (Operation::Locate, payload)
  }

  pub fn get_key(uuid: &str) -> (Operation, Ttlv) {
    let payload = Ttlv::new(
      Tag::RequestPayload,
      Structure(vec![Ttlv::new(Tag::UniqueIdentifier, TextString(uuid))]),
    );
    (Operation::Get, payload)
  }

  pub fn get_attributes(uuid: &str) -> (Operation, Ttlv) {
    let payload = Ttlv::new(
      Tag::RequestPayload,
      Structure(vec![Ttlv::new(Tag::UniqueIdentifier, TextString(uuid))]),
    );
    (Operation::GetAttributes, payload)
  }

  pub fn parse(payload: &Ttlv) -> Result<KmipOp, KmipError> {
    if payload.tag != Tag::RequestMessage {
      return Err(KmipError::CorruptStructure);
    }

    let batch_count: i32 = payload
      .path(&[Tag::RequestHeader, Tag::BatchCount])?
      .unbox()?;
    if batch_count != 1 {
      return Err(KmipError::UnsupportedBatchCount);
    }

    let batch_item: &Ttlv = payload.path(&[Tag::BatchItem])?;
    let op: u32 = batch_item.path(&[Tag::Operation])?.unbox()?;
    let op_tag = Operation::fromu32(op).ok_or(KmipError::UnsupportedOperation)?;

    Ok(match op_tag {
      Operation::Locate => KmipOp::Locate(parse_locate(batch_item)?),
      Operation::GetAttributes => KmipOp::GetAttrs(parse_uuid(batch_item)?),
      Operation::Get => KmipOp::Get(parse_uuid(batch_item)?),
      Operation::Mac => {
        let (algo, data) = hmac::parse_request(batch_item)?;
        KmipOp::MAC(parse_uuid(batch_item)?, algo, data)
      }
      Operation::Sign => {
        let (padding, md_type, data) = sign::parse_request(batch_item)?;
        KmipOp::Sign(parse_uuid(batch_item)?, padding, md_type, data)
      }
      Operation::Encrypt => match parse_mode(batch_item)? {
        BlockCipherMode::GCM => KmipOp::EncryptGCM(
          parse_uuid(batch_item)?,
          parse_algo(batch_item)?,
          parse_data(batch_item)?,
          crate::gcm::parse_aad(batch_item)?,
          crate::gcm::parse_iv_tag_len(batch_item)?,
        ),
        BlockCipherMode::CBC => KmipOp::EncryptCBC(
          parse_uuid(batch_item)?,
          parse_algo(batch_item)?,
          parse_data(batch_item)?,
          crate::cbc::parse_iv(batch_item)?,
        ),
        _ => return Err(KmipError::UnsupportedBlockCipherMode),
      },
      Operation::Decrypt => match parse_mode(batch_item)? {
        BlockCipherMode::GCM => KmipOp::DecryptGCM(
          parse_uuid(batch_item)?,
          parse_algo(batch_item)?,
          parse_data(batch_item)?,
          crate::gcm::parse_aad(batch_item)?,
          crate::parse_iv(batch_item)?,
          crate::gcm::parse_tag(batch_item)?,
        ),
        BlockCipherMode::CBC => KmipOp::DecryptCBC(
          parse_uuid(batch_item)?,
          parse_algo(batch_item)?,
          parse_data(batch_item)?,
          crate::parse_iv(batch_item)?,
        ),
        _ => return Err(KmipError::UnsupportedBlockCipherMode),
      },
      _ => return Err(KmipError::UnsupportedOperation),
    })
  }

  fn parse_locate(payload: &Ttlv) -> Result<String, KmipError> {
    if payload
      .path(&[Tag::RequestPayload, Tag::Attribute, Tag::AttributeName])?
      .unbox::<&str>()?
      == "Name"
    {
      payload
        .path(&[
          Tag::RequestPayload,
          Tag::Attribute,
          Tag::AttributeValue,
          Tag::NameValue,
        ])
        .and_then(|r| r.unbox::<&str>())
        .map_err(|_| KmipError::CorruptStructure)
        .map(str::to_string)
    } else {
      Err(KmipError::UnsupportedOperation)
    }
  }

  fn parse_uuid(payload: &Ttlv) -> Result<String, KmipError> {
    payload
      .path(&[Tag::RequestPayload, Tag::UniqueIdentifier])
      .and_then(|r| r.unbox::<&str>())
      .map_err(|_| KmipError::CorruptStructure)
      .map(str::to_string)
  }
}

pub mod response {
  use super::KMIP_PROTOCOL_VERSION;
  use crate::constants::{enumerations::*, FromU32, Tag};
  use crate::error::KmipError;
  use crate::ttlv::{Ttlv, Value::*};

  pub fn from(timestamp: i64, operation: Operation, payload: Ttlv) -> Ttlv {
    Ttlv::new(
      Tag::ResponseMessage,
      Structure(vec![
        Ttlv::new(
          Tag::ResponseHeader,
          Structure(vec![
            Ttlv::new(
              Tag::ProtocolVersion,
              Structure(vec![
                Ttlv::new(Tag::ProtocolVersionMajor, Integer(KMIP_PROTOCOL_VERSION.0)),
                Ttlv::new(Tag::ProtocolVersionMinor, Integer(KMIP_PROTOCOL_VERSION.1)),
              ]),
            ),
            Ttlv::new(Tag::TimeStamp, DateTime(timestamp)),
            Ttlv::new(Tag::BatchCount, Integer(1)),
          ]),
        ),
        Ttlv::new(
          Tag::BatchItem,
          Structure(vec![
            Ttlv::new(Tag::Operation, Enumeration(operation as u32)),
            Ttlv::new(Tag::ResultStatus, Enumeration(ResultStatus::Success as u32)),
            Ttlv::new(Tag::ResponsePayload, Structure(vec![payload])),
          ]),
        ),
      ]),
    )
  }

  pub fn from_vec(timestamp: i64, operation: Operation, payload: Vec<Ttlv>) -> Ttlv {
    let mut p = vec![Ttlv::new(Tag::Operation, Enumeration(operation as u32))];
    p.extend(payload);

    Ttlv::new(
      Tag::ResponseMessage,
      Structure(vec![
        Ttlv::new(
          Tag::ResponseHeader,
          Structure(vec![
            Ttlv::new(
              Tag::ProtocolVersion,
              Structure(vec![
                Ttlv::new(Tag::ProtocolVersionMajor, Integer(KMIP_PROTOCOL_VERSION.0)),
                Ttlv::new(Tag::ProtocolVersionMinor, Integer(KMIP_PROTOCOL_VERSION.1)),
              ]),
            ),
            Ttlv::new(Tag::TimeStamp, DateTime(timestamp)),
            Ttlv::new(Tag::BatchCount, Integer(1)),
          ]),
        ),
        Ttlv::new(
          Tag::BatchItem,
          Structure(vec![
            Ttlv::new(Tag::Operation, Enumeration(operation as u32)),
            Ttlv::new(Tag::ResultStatus, Enumeration(ResultStatus::Success as u32)),
            Ttlv::new(Tag::ResponsePayload, Structure(p)),
          ]),
        ),
      ]),
    )
  }

  pub fn parse_batch_item<'a>(response: &'a Ttlv) -> Result<&'a Ttlv<'a>, KmipError> {
    if response.tag != Tag::ResponseMessage {
      return Err(KmipError::CorruptStructure);
    }

    let batch_item = response.path(&[Tag::BatchItem])?;
    let status: u32 = batch_item.path(&[Tag::ResultStatus])?.unbox()?;

    if status == ResultStatus::Success as u32 {
      let payload = batch_item.path(&[Tag::ResponsePayload])?;
      Ok(payload)
    } else {
      let reason: u32 = batch_item.path(&[Tag::ResultReason])?.unbox()?;
      let reason = ResultReason::fromu32(reason).unwrap_or(ResultReason::GeneralFailure);
      // let reason = ResultReason::try_from(reason).map_err(|_|ResultReason::GeneralFailure);
      let message: &str = match batch_item.path(&[Tag::ResultMessage]) {
        Ok(message) => message.unbox()?,
        Err(_) => "No Message",
      };
      Err(KmipError::RequestFailed(reason, String::from(message)))
    }
  }

  pub fn parse_attrs<'a>(
    payload: &'a Ttlv,
  ) -> Result<(CryptographicAlgorithm, ObjectType, u32, usize), KmipError> {
    let ttlv_attrs: Vec<&Ttlv> = payload.paths(&[Tag::Attribute])?;

    let attr_list_: Result<Vec<(&str, &Ttlv)>, KmipError> = ttlv_attrs
      .into_iter()
      .map(|entry| {
        let name: &'a str = entry.path(&[Tag::AttributeName])?.unbox()?;
        let value: &'a Ttlv = entry.path(&[Tag::AttributeValue])?;
        Ok((name, value))
      })
      .collect();
    let attr_list = attr_list_?;

    let alg: u32 = filter_attr(&attr_list, "Cryptographic Algorithm")?.unbox()?;
    let alg = CryptographicAlgorithm::fromu32(alg).ok_or(KmipError::UnsupportedAlgorithm)?;

    let len: i32 = filter_attr(&attr_list, "Cryptographic Length")?.unbox()?;

    let usage_mask_: i32 = filter_attr(&attr_list, "Cryptographic Usage Mask")?.unbox()?;
    let usage_mask = usage_mask_ as u32;

    let obj_type: u32 = filter_attr(&attr_list, "Object Type")?.unbox()?;
    let obj_type = ObjectType::fromu32(obj_type).ok_or(KmipError::UnsupportedObjectType)?;

    if (usage_mask as u32) & !crate::kmip::SUPPORTED_USAGES != 0 {
      Err(KmipError::UnsupportedUsage)
    } else {
      Ok((alg, obj_type, usage_mask, len as usize))
    }
  }

  pub fn parse_uuids<'a>(payload: &Ttlv) -> Result<Vec<String>, KmipError> {
    payload
      .paths(&[Tag::UniqueIdentifier])?
      .into_iter()
      .map(|s| {
        s.unbox::<&str>()
          .map(str::to_string)
          .map_err(KmipError::Ttlv)
      })
      .collect()
  }

  pub fn parse_key_material<'a>(payload: &'a Ttlv, key_kind: Tag) -> Result<Vec<u8>, KmipError> {
    let key = payload.path(&[key_kind, Tag::KeyBlock])?;
    let key_material: &[u8] = key.path(&[Tag::KeyValue, Tag::KeyMaterial])?.unbox()?;
    Ok(Vec::from(key_material))
  }

  fn filter_attr<'a>(
    entries: &Vec<(&str, &'a Ttlv)>, name: &str,
  ) -> Result<&'a Ttlv<'a>, KmipError> {
    match entries.iter().find(|e| e.0 == name) {
      None => Err(KmipError::CorruptStructure),
      Some(ttlv) => Ok(ttlv.1),
    }
  }
}

pub mod hmac {
  use crate::constants::{enumerations::*, Tag};
  use crate::error::KmipError;
  use crate::ttlv::{Ttlv, Value::*};

  pub fn request<'a>(uuid: &'a str, bytes: &'a [u8]) -> (Operation, Ttlv<'a>) {
    let payload = Ttlv::new(
      Tag::RequestPayload,
      Structure(vec![
        Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
        Ttlv::new(
          Tag::CryptographicParameters,
          Structure(vec![Ttlv::new(
            Tag::CryptographicAlgorithm,
            Enumeration(CryptographicAlgorithm::HMAC_SHA256 as u32),
          )]),
        ),
        Ttlv::new(Tag::Data, ByteString(bytes)),
      ]),
    );
    (Operation::Mac, payload)
  }

  pub(crate) fn parse_request(
    payload: &Ttlv,
  ) -> Result<(CryptographicAlgorithm, Vec<u8>), KmipError> {
    if let Ok(CryptographicAlgorithm::HMAC_SHA256) = super::parse_algo(payload) {
      Ok((
        CryptographicAlgorithm::HMAC_SHA256,
        super::parse_data(payload)?,
      ))
    } else {
      Err(KmipError::CorruptStructure)
    }
  }

  pub fn parse_mac_response(payload: &Ttlv) -> Result<Vec<u8>, KmipError> {
    let data: &[u8] = payload.path(&[Tag::MacData])?.unbox()?;
    Ok(data.to_vec())
  }
}

pub mod sign {
  use crate::constants::FromU32;
  use crate::constants::{enumerations::*, Tag};
  use crate::error::KmipError;
  use crate::ttlv::{Ttlv, Value::*};

  pub fn request<'a>(
    uuid: &'a str, algo: CryptographicAlgorithm,
    padding: &Option<(PaddingMethod, HashingAlgorithm)>, bytes: &'a [u8],
  ) -> (Operation, Ttlv<'a>) {
    let params = if let Some((padding, hashing)) = padding {
      vec![
        Ttlv::new(Tag::PaddingMethod, Enumeration(*padding as u32)),
        Ttlv::new(Tag::HashingAlgorithm, Enumeration(*hashing as u32)),
        Ttlv::new(Tag::CryptographicAlgorithm, Enumeration(algo as u32)),
      ]
    } else {
      vec![
        Ttlv::new(
          Tag::DigitalSignatureAlgorithm,
          Enumeration(DigitalSignatureAlgorithm::ECDSA_WITH_SHA256 as u32),
        ),
        Ttlv::new(Tag::CryptographicAlgorithm, Enumeration(algo as u32)),
      ]
    };

    let payload = Ttlv::new(
      Tag::RequestPayload,
      Structure(vec![
        Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
        Ttlv::new(Tag::CryptographicParameters, Structure(params)),
        Ttlv::new(Tag::DigestedData, ByteString(bytes)),
      ]),
    );
    (Operation::Sign, payload)
  }

  pub fn parse_sign_response(payload: &Ttlv) -> Result<Vec<u8>, KmipError> {
    let data: &[u8] = payload.path(&[Tag::SignatureData])?.unbox()?;
    Ok(data.to_vec())
  }

  pub fn parse_request(
    payload: &Ttlv,
  ) -> Result<
    (
      Option<(PaddingMethod, HashingAlgorithm)>,
      HashingAlgorithm,
      Vec<u8>,
    ),
    KmipError,
  > {
    let algo = super::parse_algo(payload)?;
    let hash = payload
      .path(&[Tag::RequestPayload, Tag::DigestedData])
      .and_then(|r| r.unbox::<&[u8]>())
      .map_err(|_| KmipError::CorruptStructure)?;

    match algo {
      CryptographicAlgorithm::RSA => {
        let padding_ = payload
          .path(&[
            Tag::RequestPayload,
            Tag::CryptographicParameters,
            Tag::PaddingMethod,
          ])
          .and_then(|r| r.unbox::<u32>())
          .map_err(|_| KmipError::UnsupportedPaddingMethod)?;
        let padding =
          PaddingMethod::fromu32(padding_).ok_or(KmipError::UnsupportedPaddingMethod)?;

        let hashing_ = payload
          .path(&[
            Tag::RequestPayload,
            Tag::CryptographicParameters,
            Tag::HashingAlgorithm,
          ])
          .and_then(|r| r.unbox::<u32>())
          .map_err(|_| KmipError::UnsupportedHashingAlgorithm)?;
        let hashing =
          HashingAlgorithm::fromu32(hashing_).ok_or(KmipError::UnsupportedHashingAlgorithm)?;

        Ok((
          Some((padding, hashing)),
          HashingAlgorithm::SHA256,
          hash.to_vec(),
        ))
      }
      CryptographicAlgorithm::ECDSA => Ok((None, HashingAlgorithm::SHA256, hash.to_vec())),
      _ => Err(KmipError::UnsupportedAlgorithm),
    }
  }
}

pub mod gcm {
  use crate::constants::{enumerations::*, Tag};
  use crate::error::KmipError;
  use crate::ttlv::{Ttlv, Value::*};

  pub fn encrypt_request<'a>(
    uuid: &'a str, algo: CryptographicAlgorithm, tag_len: i32, iv_len: i32, data: &'a [u8],
    aad: Option<&'a [u8]>,
  ) -> (Operation, Ttlv<'a>) {
    let mut payload = vec![
      Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
      Ttlv::new(
        Tag::CryptographicParameters,
        Structure(vec![
          Ttlv::new(
            Tag::BlockCipherMode,
            Enumeration(BlockCipherMode::GCM as u32),
          ),
          Ttlv::new(Tag::PaddingMethod, Enumeration(PaddingMethod::None as u32)),
          Ttlv::new(Tag::CryptographicAlgorithm, Enumeration(algo as u32)),
          Ttlv::new(Tag::RandomIV, Boolean(true)),
          Ttlv::new(Tag::IvLength, Integer(iv_len)),
          Ttlv::new(Tag::TagLength, Integer(tag_len)),
        ]),
      ),
      Ttlv::new(Tag::Data, ByteString(data)),
    ];
    if let Some(aad) = aad {
      payload.push(Ttlv::new(
        Tag::AuthenticatedEncryptionAdditionalData,
        ByteString(aad),
      ))
    }

    let payload = Ttlv::new(Tag::RequestPayload, Structure(payload));
    (Operation::Encrypt, payload)
  }

  pub fn parse_iv_tag_len(payload: &Ttlv) -> Result<(usize, usize), KmipError> {
    let iv_len = payload
      .path(&[
        Tag::RequestPayload,
        Tag::CryptographicParameters,
        Tag::IvLength,
      ])
      .and_then(|r| r.unbox::<i32>())
      .map_err(|_| KmipError::CorruptStructure)? as usize;
    let tag_len = payload
      .path(&[
        Tag::RequestPayload,
        Tag::CryptographicParameters,
        Tag::TagLength,
      ])
      .and_then(|r| r.unbox::<i32>())
      .map_err(|_| KmipError::CorruptStructure)? as usize;

    Ok((iv_len, tag_len))
  }

  pub fn decrypt_request<'a>(
    uuid: &'a str, algo: CryptographicAlgorithm, data: &'a [u8], iv: &'a [u8], tag: &'a [u8],
    aad: Option<&'a [u8]>,
  ) -> (Operation, Ttlv<'a>) {
    let mut payload = vec![
      Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
      Ttlv::new(
        Tag::CryptographicParameters,
        Structure(vec![
          Ttlv::new(
            Tag::BlockCipherMode,
            Enumeration(BlockCipherMode::GCM as u32),
          ),
          Ttlv::new(Tag::PaddingMethod, Enumeration(PaddingMethod::None as u32)),
          Ttlv::new(Tag::CryptographicAlgorithm, Enumeration(algo as u32)),
        ]),
      ),
      Ttlv::new(Tag::Data, ByteString(data)),
      Ttlv::new(Tag::IvCounterNonce, ByteString(iv)),
      Ttlv::new(Tag::AuthenticatedEncryptionTag, ByteString(tag)),
    ];
    if let Some(aad) = aad {
      payload.push(Ttlv::new(
        Tag::AuthenticatedEncryptionAdditionalData,
        ByteString(aad),
      ));
    }

    let payload = Ttlv::new(Tag::RequestPayload, Structure(payload));
    (Operation::Decrypt, payload)
  }

  pub fn parse_encrypt_response(payload: &Ttlv) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), KmipError> {
    let data: &[u8] = payload.path(&[Tag::Data])?.unbox()?;
    let iv: &[u8] = payload.path(&[Tag::IvCounterNonce])?.unbox()?;
    let tag: &[u8] = payload.path(&[Tag::AuthenticatedEncryptionTag])?.unbox()?;
    Ok((data.to_vec(), tag.to_vec(), iv.to_vec()))
  }

  pub fn parse_decrypt_response(payload: &Ttlv) -> Result<Vec<u8>, KmipError> {
    let data: &[u8] = payload.path(&[Tag::Data])?.unbox()?;
    Ok(data.to_vec())
  }

  pub(crate) fn parse_aad(payload: &Ttlv) -> Result<Option<Vec<u8>>, KmipError> {
    let box_opt = payload
      .path(&[
        Tag::RequestPayload,
        Tag::AuthenticatedEncryptionAdditionalData,
      ])
      .ok();
    if let Some(node) = box_opt {
      Ok(Some(
        node
          .unbox::<&[u8]>()
          .map_err(|_| KmipError::CorruptStructure)?
          .to_vec(),
      ))
    } else {
      Ok(None)
    }
  }

  pub(crate) fn parse_tag(payload: &Ttlv) -> Result<Vec<u8>, KmipError> {
    let data = payload
      .path(&[Tag::RequestPayload, Tag::AuthenticatedEncryptionTag])
      .and_then(|r| r.unbox::<&[u8]>())
      .map_err(|_| KmipError::CorruptStructure)?;
    Ok(data.to_vec())
  }
}

pub mod cbc {
  use crate::constants::{enumerations::*, Tag};
  use crate::error::KmipError;
  use crate::ttlv::{Ttlv, Value::*};

  pub fn encrypt_request<'a>(
    uuid: &'a str, algo: CryptographicAlgorithm, data: &'a [u8], iv: Option<&'a [u8]>,
  ) -> (Operation, Ttlv<'a>) {
    let mut payload = vec![
      Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
      Ttlv::new(
        Tag::CryptographicParameters,
        Structure(vec![
          Ttlv::new(
            Tag::BlockCipherMode,
            Enumeration(BlockCipherMode::CBC as u32),
          ),
          Ttlv::new(Tag::PaddingMethod, Enumeration(PaddingMethod::PKCS5 as u32)),
          Ttlv::new(Tag::CryptographicAlgorithm, Enumeration(algo as u32)),
          Ttlv::new(Tag::RandomIV, Boolean(iv.is_none())),
        ]),
      ),
      Ttlv::new(Tag::Data, ByteString(data)),
    ];
    if let Some(iv) = iv {
      payload.push(Ttlv::new(Tag::IvCounterNonce, ByteString(iv)))
    }

    let payload = Ttlv::new(Tag::RequestPayload, Structure(payload));
    (Operation::Encrypt, payload)
  }

  pub fn decrypt_request<'a>(
    uuid: &'a str, algo: CryptographicAlgorithm, data: &'a [u8], iv: &'a [u8],
  ) -> (Operation, Ttlv<'a>) {
    let payload = Ttlv::new(
      Tag::RequestPayload,
      Structure(vec![
        Ttlv::new(Tag::UniqueIdentifier, TextString(uuid)),
        Ttlv::new(
          Tag::CryptographicParameters,
          Structure(vec![
            Ttlv::new(
              Tag::BlockCipherMode,
              Enumeration(BlockCipherMode::CBC as u32),
            ),
            Ttlv::new(Tag::PaddingMethod, Enumeration(PaddingMethod::PKCS5 as u32)),
            Ttlv::new(Tag::CryptographicAlgorithm, Enumeration(algo as u32)),
          ]),
        ),
        Ttlv::new(Tag::Data, ByteString(data)),
        Ttlv::new(Tag::IvCounterNonce, ByteString(iv)),
      ]),
    );
    (Operation::Decrypt, payload)
  }

  pub fn parse_encrypt_response_with_iv(payload: &Ttlv) -> Result<(Vec<u8>, Vec<u8>), KmipError> {
    let data: &[u8] = payload.path(&[Tag::Data])?.unbox()?;
    let iv: &[u8] = payload.path(&[Tag::IvCounterNonce])?.unbox()?;
    Ok((data.to_vec(), iv.to_vec()))
  }

  pub fn parse_encrypt_response_without_iv(payload: &Ttlv) -> Result<Vec<u8>, KmipError> {
    let data: &[u8] = payload.path(&[Tag::Data])?.unbox()?;
    Ok(data.to_vec())
  }

  pub(crate) fn parse_iv(payload: &Ttlv) -> Result<Option<Vec<u8>>, KmipError> {
    let random_iv = payload
      .path(&[
        Tag::RequestPayload,
        Tag::CryptographicParameters,
        Tag::RandomIV,
      ])?
      .unbox::<bool>()?;
    let box_opt = payload
      .path(&[Tag::RequestPayload, Tag::IvCounterNonce])
      .ok();
    if random_iv == box_opt.is_some() {
      Err(KmipError::CorruptStructure)
    } else if let Some(node) = box_opt {
      Ok(Some(
        node
          .unbox::<&[u8]>()
          .map_err(|_| KmipError::CorruptStructure)?
          .to_vec(),
      ))
    } else {
      Ok(None)
    }
  }

  pub use super::gcm::parse_decrypt_response;
}

pub fn parse_uuid<'a>(payload: &'a Ttlv) -> Result<&'a str, KmipError> {
  let uuid: &str = payload.path(&[Tag::UniqueIdentifier])?.unbox()?;
  Ok(uuid)
}

pub fn parse_data(payload: &Ttlv) -> Result<Vec<u8>, KmipError> {
  let data = payload
    .path(&[Tag::RequestPayload, Tag::Data])
    .and_then(|r| r.unbox::<&[u8]>())
    .map_err(|_| KmipError::CorruptStructure)?;
  Ok(data.to_vec())
}

pub(crate) fn parse_iv(payload: &Ttlv) -> Result<Vec<u8>, KmipError> {
  let data = payload
    .path(&[Tag::RequestPayload, Tag::IvCounterNonce])
    .and_then(|r| r.unbox::<&[u8]>())
    .map_err(|_| KmipError::CorruptStructure)?;
  Ok(data.to_vec())
}

pub(crate) fn parse_algo(payload: &Ttlv) -> Result<CryptographicAlgorithm, KmipError> {
  let algo_ = payload
    .path(&[
      Tag::RequestPayload,
      Tag::CryptographicParameters,
      Tag::CryptographicAlgorithm,
    ])
    .and_then(|r| r.unbox::<u32>())
    .map_err(|_| KmipError::CorruptStructure)?;
  CryptographicAlgorithm::fromu32(algo_).ok_or(KmipError::UnsupportedAlgorithm)
}

pub(crate) fn parse_mode(payload: &Ttlv) -> Result<BlockCipherMode, KmipError> {
  let algo_ = payload
    .path(&[
      Tag::RequestPayload,
      Tag::CryptographicParameters,
      Tag::BlockCipherMode,
    ])
    .and_then(|r| r.unbox::<u32>())
    .map_err(|_| KmipError::CorruptStructure)?;
  BlockCipherMode::fromu32(algo_).ok_or(KmipError::UnsupportedBlockCipherMode)
}
