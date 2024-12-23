use crate::mtls::mbed_err_check;
use crate::mtls::CtxPK;
use common::api::KMSEndPoint;
use common::api::KeyData;
use common::api::KeyLength;
use common::api::KeyMaterial;
use common::api::KeyUsageMask;
use common::api::MulTeeCore;
use common::api::RsaPadding;
use common::constants::MULTEE_HMAC256_BYTES;
use common::constants::MULTEE_SIG_LEN_MAX;
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use either::{Either, Left, Right};
use kmip::constants::FromU32;
use kmip::enumerations::CryptographicAlgorithm;
use kmip::enumerations::CryptographicUsageMask;
use kmip::enumerations::ObjectType;
use kmip::enumerations::{HashingAlgorithm, PaddingMethod};
use log::trace;
pub use mbedtls_sys::mbedtls_md_type_t;
use mbedtls_sys::{mbedtls_md_type_t::*, *};
use num_traits::ToPrimitive;
use paste::paste;
use serde_json::Value;
use std::vec::Vec;

mbedtls_struct!(CtxEntropy, entropy, mbedtls_entropy_context);
mbedtls_struct!(CtxCTRDRBG, ctr_drbg, mbedtls_ctr_drbg_context);
// mbedtls_struct!(CtxPK, pk, mbedtls_pk_context);
mbedtls_struct_plus2!(
  CtxRSA,
  rsa,
  mbedtls_rsa_context,
  padding,
  libc::c_int,
  hash_id,
  libc::c_int
);
mbedtls_struct!(CtxAES, aes, mbedtls_aes_context);

pub const UNENCRYPTED_HEADER: &[u8] = b"-----BEGIN";

pub(crate) const SUPPORTED_KEY_TYPES: [CryptographicAlgorithm; 3] = [
  CryptographicAlgorithm::AES,
  CryptographicAlgorithm::ECDSA,
  CryptographicAlgorithm::RSA,
];
pub(crate) const SUPPORTED_OBJECT_TYPES: [ObjectType; 2] =
  [ObjectType::PrivateKey, ObjectType::SymmetricKey];

pub fn key_meta_new(
  name: &str, key_material: &[u8], key_type: u32, object_type: u32, usage_mask: u32,
  key_length: usize,
) -> MulTeeResult<KeyData> {
  Ok(KeyData {
    name: name.to_owned(),
    key_type: CryptographicAlgorithm::fromu32(key_type)
      .filter(|e| SUPPORTED_KEY_TYPES.contains(e))
      .ok_or(MulTeeErrCode::CREDENTIALS.msg("Unsuppofted key type"))?, // TODO
    object_type: ObjectType::fromu32(object_type)
      .filter(|e| SUPPORTED_OBJECT_TYPES.contains(e))
      .ok_or(MulTeeErrCode::CREDENTIALS.msg("Unsuppofted object type"))?,
    usage_mask: usage_mask as KeyUsageMask,
    key_length: key_length as KeyLength,
    key_material: key_material.to_vec(),
    key_kmip_uuid: String::new(),
  })
}

//todo split AES and HMAC
pub enum MtlsKey {
  AES(CtxAES, CtxAES, KeyMaterial),
  SM4(CtxAES, CtxAES, KeyMaterial),
  RSA(CtxPK, KeyLength, KeyUsageMask),
  ECC(CtxPK, KeyLength, KeyUsageMask),
}

impl MtlsKey {
  pub(crate) fn new(key: &KeyData) -> MulTeeResult<Self> {
    match key.key_type {
      CryptographicAlgorithm::AES => {
        let mut enc_ctx = CtxAES::new();
        let mut dec_ctx = CtxAES::new();
        unsafe {
          mbed_err_check(mbedtls_aes_setkey_enc(
            enc_ctx.as_mut_ptr(),
            key.key_material.as_ptr(),
            key.key_length as u32,
          ))?;
          mbed_err_check(mbedtls_aes_setkey_dec(
            dec_ctx.as_mut_ptr(),
            key.key_material.as_ptr(),
            key.key_length as u32,
          ))?;
        }
        Ok(MtlsKey::AES(enc_ctx, dec_ctx, key.key_material.clone()))
      }
      CryptographicAlgorithm::RSA => {
        let mut sig_ctx_pk = CtxPK::new();

        unsafe {
          mbed_err_check(mbedtls_pk_parse_key(
            sig_ctx_pk.as_mut_ptr(),
            key.key_material.as_ptr(),
            key.key_material.len(),
            std::ptr::null(),
            0,
          ))?;
        }

        Ok(MtlsKey::RSA(sig_ctx_pk, key.key_length, key.usage_mask))
      }
      CryptographicAlgorithm::ECDSA => {
        let mut sig_ctx_pk = CtxPK::new();

        unsafe {
          mbed_err_check(mbedtls_pk_parse_key(
            sig_ctx_pk.as_mut_ptr(),
            key.key_material.as_ptr(),
            key.key_material.len(),
            std::ptr::null(),
            0,
          ))?;
        }

        Ok(MtlsKey::ECC(sig_ctx_pk, key.key_length, key.usage_mask))
      }
      _ => todo!(),
    }
  }
}

pub const DEFAULT_SIG_HASH: HashingAlgorithm = HashingAlgorithm::SHA256;
pub const DEFAULT_SIG_PADDING: RsaPadding = (PaddingMethod::PSS, HashingAlgorithm::SHA256);

pub trait Tee: Sized {
  fn import_keys(
    self, key_ref: Either<&KMSEndPoint, &Vec<KeyData>>,
  ) -> MulTeeResult<MtlsImpl<Self>> {
    trace!("MulTeeCore::import_keys in {}", file!());

    let (entropy, drbg) = crate::mtls::prep_rnd()?;

    let key_meta = match key_ref {
      Left(kms_info) => crate::import_keys::import_keys_from_end_point::<Self>(kms_info, &drbg)?,
      Right(literal) => literal.clone(),
    };

    let mtls_keys: MulTeeResult<Vec<MtlsKey>> = key_meta.iter().map(MtlsKey::new).collect();
    let mtls_keys = mtls_keys?;

    Ok(MtlsImpl {
      _inner: self,
      key_meta,
      mtls_keys,
      _entropy: entropy,
      drbg,
    })
  }

  fn seal_data(input: &[u8]) -> MulTeeResult<Vec<u8>>;
  fn unseal_data(sealed_data: &[u8]) -> MulTeeResult<Vec<u8>>;
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
  fn attestation(payload: &[u8]) -> MulTeeResult<Value>;
  fn attestation_kind() -> String;
}

pub struct MtlsImpl<T: Tee> {
  _inner: T,
  key_meta: Vec<KeyData>,
  mtls_keys: Vec<MtlsKey>,
  _entropy: CtxEntropy,
  drbg: CtxCTRDRBG,
}

impl<'a, T: Tee> MtlsImpl<T> {
  #[inline]
  fn get_key(&'a self, key_index: usize) -> MulTeeResult<&'a MtlsKey> {
    self
      .mtls_keys
      .get(key_index)
      .ok_or(MulTeeErrCode::CRYPTO_INVALID_KEY_INDEX.msg(key_index))
  }
  fn get_key_meta(&'a self, key_index: usize) -> MulTeeResult<&'a KeyData> {
    self
      .key_meta
      .get(key_index)
      .ok_or(MulTeeErrCode::CRYPTO_INVALID_KEY_INDEX.msg(key_index))
  }
}

impl<T: Tee> MulTeeCore for MtlsImpl<T>
where
  T: Tee,
{
  fn crypt_cbc(
    &self, key_index: usize, encrypt: bool, explicit_iv: bool, iv: &mut [u8],
    crypto_buf: &mut [u8], input_len: usize,
  ) -> MulTeeResult<()> {
    let input: *const u8 = crypto_buf.as_ptr();
    let output: *mut u8 = crypto_buf.as_mut_ptr();

    unsafe {
      match self.get_key(key_index)? {
        MtlsKey::AES(enc_ctx, dec_ctx, _) => {
          if !explicit_iv && encrypt {
            crate::mtls::get_random(iv, &self.drbg)?;
          }

          let mut iv = Vec::from(iv);

          let ctx = if encrypt {
            enc_ctx.force_mut_ptr()
          } else {
            dec_ctx.force_mut_ptr()
          };
          mbed_err_check(mbedtls_aes_crypt_cbc(
            ctx,
            encrypt as i32,
            input_len,
            iv.as_mut_ptr(),
            input,
            output,
          ))
        }
        MtlsKey::RSA(..) | MtlsKey::ECC(..) => Err(
          MulTeeErrCode::CRYPTO_ALG_MISMATCH.msg("Can not symmetric crypto using asymmetric keys"),
        ),
        MtlsKey::SM4(..) => {
          todo!()
        }
      }
    }
  }

  fn crypt_gcm(
    &self, key_index: usize, encrypt: bool, iv: &mut [u8], aad: Option<&[u8]>, in_buf: &[u8],
    out_buf: &mut [u8], tag: &mut [u8],
  ) -> MulTeeResult<()> {
    match self.get_key(key_index)? {
      MtlsKey::AES(.., key_material) => crate::mtls::crypt_gcm(
        &self.drbg,
        key_material.as_slice(),
        encrypt,
        iv,
        aad,
        in_buf,
        out_buf,
        tag,
      ),

      MtlsKey::RSA(..) | MtlsKey::ECC(..) => Err(
        MulTeeErrCode::CRYPTO_ALG_MISMATCH.msg("Can not symmetric crypto using asymmetric keys"),
      ),
      MtlsKey::SM4(..) => todo!(),
    }
  }

  fn get_public_key(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    match self.get_key(key_index)? {
      MtlsKey::RSA(ctx, ..) | MtlsKey::ECC(ctx, ..) => ctx.get_public_key(),
      _ => Err(MulTeeErrCode::CRYPTO_ALG_MISMATCH.msg("Can not do using symmetric keys")),
    }
  }

  fn sign(
    &self, key_index: usize, padding: Option<RsaPadding>, md_type: HashingAlgorithm, hash: &[u8],
  ) -> MulTeeResult<Vec<u8>> {
    match self.get_key(key_index)? {
      MtlsKey::RSA(ctx, _len, usage_mask) => unsafe {
        if usage_mask & CryptographicUsageMask::Sign as u32 == 0 {
          return Err(
            MulTeeErrCode::CRYPTO_PROHIBITED_USAGE.msg("Signing with this key isn't permitted"),
          );
        }

        let mut sig_len: usize = 0;

        let mut signature = vec![0u8; MULTEE_SIG_LEN_MAX];

        let p_rng = self.drbg.force_mut_ptr() as *mut libc::c_void;

        let mut copy = crate::mtls::RSACopy::new(ctx)?;

        if let Some(padding) = padding {
          let (sig_padding, sig_md) = crate::mtls::kmip_to_mbedtls_padding_params(padding)?;

          // TODO: research/make generic
          // I.e. for RSA - capture desired algorithm (with RSA_PKCS_PSS being default) and pass as a parameter (which would be ignored for EC?)
          // mbedtls_rsa_set_padding(ctx.ctx.pk_ctx as * mut mbedtls_rsa_context, sig_padding, sig_md);
          mbedtls_rsa_set_padding(
            copy.rsa.as_mut_ptr(),
            sig_padding.to_i32().unwrap(),
            sig_md as libc::c_int,
          );
        }

        mbed_err_check(mbedtls_pk_sign(
          copy.pk.force_mut_ptr(),
          crate::mtls::kmip_to_mbedtls_digest(md_type)?,
          // mbedtls_pk_sign(ctx.force_mut_ptr(), md_type,
          hash.as_ptr(),
          hash.len(),
          signature.as_mut_ptr(),
          &mut sig_len,
          Some(mbedtls_ctr_drbg_random),
          p_rng,
        ))?;
        signature.truncate(sig_len);
        Ok(signature)
      },
      MtlsKey::ECC(ctx, _len, usage_mask) => unsafe {
        if usage_mask & CryptographicUsageMask::Sign as u32 == 0 {
          return Err(
            MulTeeErrCode::CRYPTO_PROHIBITED_USAGE.msg("Signing with this key isn't permitted"),
          );
        }

        let mut sig_len: usize = 0;

        let mut signature = vec![0u8; MULTEE_SIG_LEN_MAX];

        let p_rng = self.drbg.as_ptr() as *mut libc::c_void;

        // let copy = crate::crate::mtls::ECPCopy::new(ctx)?;

        mbed_err_check(mbedtls_pk_sign(
          ctx.force_mut_ptr(),
          crate::mtls::kmip_to_mbedtls_digest(md_type)?,
          hash.as_ptr(),
          hash.len(),
          signature.as_mut_ptr(),
          &mut sig_len,
          Some(mbedtls_ctr_drbg_random),
          p_rng,
        ))?;
        signature.truncate(sig_len);
        Ok(signature)
      },
      _ => Err(MulTeeErrCode::CRYPTO_ALG_MISMATCH.msg("Can not sign using symmetric keys")),
    }
  }

  fn mk_csr(&self, subject_name: &str, pinned: bool) -> MulTeeResult<(Vec<u8>, Vec<u8>)> {
    crate::csr::mk_csr::<T>(&self.drbg, subject_name, pinned)
  }

  fn hmac_sha256(&self, key_index: usize, input: &[u8]) -> MulTeeResult<Vec<u8>> {
    let mut hash = vec![0u8; MULTEE_HMAC256_BYTES];

    let key_material = match self.get_key(key_index)? {
      MtlsKey::AES(_, _, bytes) => bytes,
      MtlsKey::SM4(_, _, bytes) => bytes,
      _ => {
        return Err(
          MulTeeErrCode::CRYPTO_ALG_MISMATCH.msg("Can only perform HMAC using symmetric keys"),
        )
      }
    };

    mbed_err_check(unsafe {
      mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        key_material.as_ptr(),
        key_material.len(),
        input.as_ptr(),
        input.len(),
        hash.as_mut_ptr(),
      )
    })?;
    Ok(hash)
  }

  fn meta_key_type(&self, key_index: usize) -> MulTeeResult<CryptographicAlgorithm> {
    self.get_key_meta(key_index).map(|k| k.key_type)
  }

  fn meta_key_usage_mask(&self, _key_index: usize) -> MulTeeResult<KeyUsageMask> {
    todo!()
  }

  fn meta_key_len(&self, key_index: usize) -> MulTeeResult<u64> {
    Ok(match self.get_key(key_index)? {
      MtlsKey::AES(.., bytes) => 8 * bytes.len() as u64,
      MtlsKey::RSA(_, len, _) => *len as u64,
      MtlsKey::ECC(_, len, _) => *len as u64,
      MtlsKey::SM4(.., bytes) => 8 * bytes.len() as u64,
    })
  }

  fn meta_key_count(&self) -> MulTeeResult<u64> {
    Ok(self.mtls_keys.len() as u64)
  }

  fn meta_key_name(&self, key_index: usize) -> MulTeeResult<String> {
    self.get_key_meta(key_index).map(|x| x.name.clone())
  }

  fn seal_pk(&self, input: &[u8]) -> MulTeeResult<Vec<u8>> {
    T::seal_data(input)
  }
}
