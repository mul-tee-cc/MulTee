use crate::error::MulTeeResult;
use kmip::enumerations::CryptographicAlgorithm;
use kmip::enumerations::HashingAlgorithm;
use kmip::enumerations::ObjectType;
use kmip::enumerations::PaddingMethod;
use serde::{Deserialize, Serialize};

pub type RsaPadding = (PaddingMethod, HashingAlgorithm);

pub trait MulTeeCore {
  fn meta_key_type(&self, key_index: usize) -> MulTeeResult<CryptographicAlgorithm>;
  fn meta_key_usage_mask(&self, key_index: usize) -> MulTeeResult<KeyUsageMask>;
  fn meta_key_len(&self, key_index: usize) -> MulTeeResult<u64>;
  fn meta_key_count(&self) -> MulTeeResult<u64>;
  fn meta_key_name(&self, key_index: usize) -> MulTeeResult<String>;

  fn crypt_cbc(
    &self, key_index: usize, encrypt: bool, explicit_iv: bool, iv: &mut [u8],
    crypto_buf: &mut [u8], input_len: usize,
  ) -> MulTeeResult<()>;

  fn crypt_gcm(
    &self, key_index: usize, encrypt: bool, iv: &mut [u8], aad: Option<&[u8]>, in_buf: &[u8],
    out_buf: &mut [u8], tag: &mut [u8],
  ) -> MulTeeResult<()>;

  fn get_public_key(&self, key_index: usize) -> MulTeeResult<Vec<u8>>;

  fn sign(
    &self, key_index: usize, padding: Option<RsaPadding>, md_type: HashingAlgorithm, hash: &[u8],
  ) -> MulTeeResult<Vec<u8>>;

  fn hmac_sha256(&self, key_index: usize, input: &[u8]) -> MulTeeResult<Vec<u8>>;

  fn mk_csr(&self, subject_name: &str, pinned: bool) -> MulTeeResult<(Vec<u8>, Vec<u8>)>;

  fn seal_pk(&self, input: &[u8]) -> MulTeeResult<Vec<u8>>;
}

pub type KeyUsageMask = u32; // kmip::enumerations::CryptographicUsageMask
pub type KeyLength = usize;
pub type KeyMaterial = Vec<u8>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyData {
  pub name: String,
  pub key_type: CryptographicAlgorithm,
  pub object_type: ObjectType,
  pub usage_mask: KeyUsageMask,
  pub key_length: KeyLength,
  pub key_material: KeyMaterial,
  pub key_kmip_uuid: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KMSEndPoint {
  pub kms_url: String,
  pub key_names: Vec<String>,
  pub trusted_ca: String,
  pub id_cred_pub: String,
  pub id_cred_secret: Vec<u8>,
  pub conn_timeout_sec: u64,
}
