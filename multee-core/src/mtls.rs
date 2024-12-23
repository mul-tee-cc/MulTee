use common::constants::MAX_KEY_LEN;
use common::constants::MULTEE_GCM_IV_BYTES;
use common::constants::MULTEE_RSA_EXPONENT;
use common::constants::MULTEE_RSA_KEY_SIZE;
use common::error::MulTeeErrCode;
use common::error::MulTeeErrorBuf;
use common::error::MulTeeResult;
use kmip::enumerations::HashingAlgorithm;
use kmip::enumerations::PaddingMethod;
use mbedtls_sys::mbedtls_pk_type_t::*;
use mbedtls_sys::*;
use paste::paste;
use std::vec::Vec;

#[cfg(any(feature = "multee_sgx", feature = "multee_devm"))]
static DUMMY_SEED: &str =
  const_format::formatcp!("$Revision: MulTee Enclave {} $", env!("CARGO_PKG_VERSION"));
#[cfg(not(any(feature = "multee_sgx", feature = "multee_devm")))]
static DUMMY_SEED: &str =
  const_format::formatcp!("$Revision: MulTee Exclave {} $", env!("CARGO_PKG_VERSION"));

mbedtls_struct!(CtxPK, pk, mbedtls_pk_context);
mbedtls_struct_plus2!(
  CtxRSA,
  rsa,
  mbedtls_rsa_context,
  padding,
  libc::c_int,
  hash_id,
  libc::c_int
);
mbedtls_struct!(CtxGCM, gcm, mbedtls_gcm_context);
mbedtls_struct!(CtxMPI, mpi, mbedtls_mpi);

use crate::api::{CtxCTRDRBG, CtxEntropy};
use common::api::RsaPadding;

type DrbgFunc = unsafe extern "C" fn(*mut libc::c_void, *mut libc::c_uchar, usize) -> libc::c_int;
pub(crate) const DRBG_FUNC: Option<DrbgFunc> = Some(mbedtls_ctr_drbg_random);

impl CtxPK {
  pub unsafe fn gen_rsa_key(
    &mut self, drbg: &CtxCTRDRBG, nbits: u32, exponent: i32,
  ) -> MulTeeResult<()> {
    mbed_err_check(mbedtls_pk_setup(
      self.as_mut_ptr(),
      mbedtls_pk_info_from_type(MBEDTLS_PK_RSA),
    ))?;
    let rsa_ctx = self.ctx.pk_ctx as *mut mbedtls_rsa_context;
    mbedtls_rsa_init(rsa_ctx, MBEDTLS_RSA_PKCS_V15 as i32, 0);

    let p_rng = drbg.force_mut_ptr() as *mut libc::c_void;

    mbed_err_check(mbedtls_rsa_gen_key(
      rsa_ctx, DRBG_FUNC, p_rng, nbits, exponent,
    ))
  }

  pub unsafe fn write_key_pem(&mut self, pem: &mut [u8]) -> MulTeeResult<()> {
    mbed_err_check(mbedtls_pk_write_key_pem(
      self.as_mut_ptr(),
      pem.as_mut_ptr(),
      pem.len(),
    ))
  }

  pub fn get_public_key(&self) -> MulTeeResult<Vec<u8>> {
    let mut buf = vec![0u8; MAX_KEY_LEN];

    let pk_ctx: *mut mbedtls_pk_context = self.ctx.as_ref() as *const mbedtls_pk_context as _;

    let written = unsafe { mbedtls_pk_write_pubkey_der(pk_ctx, buf.as_mut_ptr(), buf.len()) };

    let pk = buf.split_off(buf.len() - written as usize);
    Ok(pk)
  }

  pub fn mk_rsa(drbg: &CtxCTRDRBG) -> MulTeeResult<CtxPK> {
    let mut key = CtxPK::new();

    unsafe { key.gen_rsa_key(drbg, MULTEE_RSA_KEY_SIZE as u32, MULTEE_RSA_EXPONENT as i32)? };

    Ok(key)
  }
}

pub(crate) fn get_random(buf: &mut [u8], drbg: &CtxCTRDRBG) -> MulTeeResult<()> {
  unsafe {
    let p_rng = drbg.force_mut_ptr() as *mut libc::c_void;

    mbed_err_check(mbedtls_ctr_drbg_random(p_rng, buf.as_mut_ptr(), buf.len()))?;
  }

  Ok(())
}

pub fn crypt_gcm(
  drbg: &CtxCTRDRBG, key_material: &[u8], encrypt: bool, iv: &mut [u8], aad: Option<&[u8]>,
  in_buf: &[u8], out_buf: &mut [u8], tag: &mut [u8],
) -> MulTeeResult<()> {
  let aad_ptr = aad.map(|s| s.as_ptr()).unwrap_or(std::ptr::null()) as *mut u8;
  let aad_len = aad.map(|s| s.len()).unwrap_or(0);

  let mut gcm = CtxGCM::new();

  mbed_err_check(unsafe {
    mbedtls_gcm_setkey(
      gcm.as_mut_ptr(),
      mbedtls_cipher_id_t::MBEDTLS_CIPHER_ID_AES,
      key_material.as_ptr(),
      key_material.len() as u32 * 8,
    )
  })?;

  let mbed_err_code = unsafe {
    if encrypt {
      let mut gen_iv = [0u8; MULTEE_GCM_IV_BYTES];
      get_random(gen_iv.as_mut_slice(), drbg)?;
      iv.copy_from_slice(gen_iv.as_slice());

      mbedtls_gcm_crypt_and_tag(
        gcm.as_mut_ptr(),
        MBEDTLS_GCM_ENCRYPT as i32,
        in_buf.len(),
        gen_iv.as_ptr(),
        gen_iv.len(),
        aad_ptr,
        aad_len,
        in_buf.as_ptr(),
        out_buf.as_mut_ptr(),
        tag.len(),
        tag.as_mut_ptr(),
      )
    } else {
      mbedtls_gcm_auth_decrypt(
        gcm.as_mut_ptr(),
        in_buf.len(),
        iv.as_ptr(),
        iv.len(),
        aad_ptr,
        aad_len,
        tag.as_ptr(),
        tag.len(),
        in_buf.as_ptr(),
        out_buf.as_mut_ptr(),
      )
    }
  };

  mbed_err_check(mbed_err_code)
}

pub fn verify_sig2(
  pub_key: Vec<u8>, padding: Option<RsaPadding>, md_type: HashingAlgorithm, hash: &[u8], sig: &[u8],
) -> MulTeeResult<bool> {
  let md_type = kmip_to_mbedtls_digest(md_type)?;
  if let Some(p) = padding {
    let padding = kmip_to_mbedtls_padding_params(p)?;
    verify_sig(pub_key, Some(padding), md_type, hash, sig)
  } else {
    verify_sig(pub_key, None, md_type, hash, sig)
  }
}
fn verify_sig(
  pub_key: Vec<u8>, padding: Option<(mbedtls_cipher_padding_t, mbedtls_md_type_t)>,
  md_type: mbedtls_md_type_t, hash: &[u8], sig: &[u8],
) -> MulTeeResult<bool> {
  let mut ctx_pk = CtxPK::new();

  unsafe {
    mbed_err_check(mbedtls_pk_parse_public_key(
      ctx_pk.as_mut_ptr(),
      pub_key.as_ptr(),
      pub_key.len(),
    ))?;

    match padding {
      None => mbed_sig_err_check(
        MBEDTLS_ERR_ECP_VERIFY_FAILED,
        mbedtls_pk_verify(
          ctx_pk.as_mut_ptr(),
          md_type,
          hash.as_ptr(),
          hash.len(),
          sig.as_ptr(),
          sig.len(),
        ),
      ),
      Some((_, mgf1_hash_id)) => {
        let options = mbedtls_pk_rsassa_pss_options {
          mgf1_hash_id,
          expected_salt_len: MBEDTLS_RSA_SALT_LEN_ANY,
        };
        let opt_ptr = &options as *const mbedtls_pk_rsassa_pss_options as *const libc::c_void;
        mbed_sig_err_check(
          MBEDTLS_ERR_RSA_VERIFY_FAILED,
          mbedtls_pk_verify_ext(
            mbedtls_pk_type_t::MBEDTLS_PK_RSASSA_PSS,
            opt_ptr,
            ctx_pk.as_mut_ptr(),
            md_type,
            hash.as_ptr(),
            hash.len(),
            sig.as_ptr(),
            sig.len(),
          ),
        )
      }
    }
  }
}

// Needed for OPENSSL
pub unsafe fn pkcss_ecdsa_sig(sig: Vec<u8>, key_length: usize) -> MulTeeResult<Vec<u8>> {
  let mut p = sig.as_ptr() as *mut u8;
  let end = p.add(sig.len());
  let mut len: usize = 0;

  mbed_sig_err_check(
    MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
    mbedtls_asn1_get_tag(
      &mut p,
      end,
      &mut len,
      (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) as libc::c_int,
    ),
  )?;

  if p.add(len) != end {
    return Err(MulTeeErrCode::CRYPTO_MBED.nested(
      MBEDTLS_ERR_ECP_BAD_INPUT_DATA + MBEDTLS_ERR_ASN1_LENGTH_MISMATCH,
      "ASN1/DER ECDSA signature corrupted",
    ));
  }

  let mut r = CtxMPI::new();
  let mut s = CtxMPI::new();

  mbed_sig_err_check(
    MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
    mbedtls_asn1_get_mpi(&mut p, end, r.as_mut_ptr()),
  )?;
  mbed_sig_err_check(
    MBEDTLS_ERR_ECP_BAD_INPUT_DATA,
    mbedtls_asn1_get_mpi(&mut p, end, s.as_mut_ptr()),
  )?;

  let size = (key_length + 7) / 8;

  let mut r = mpi_to_bytes_sized(r.as_ptr(), size)?;
  let mut s = mpi_to_bytes_sized(s.as_ptr(), size)?;

  r.append(&mut s);
  Ok(r)
}

unsafe fn parse_pubkey(pub_key: &[u8]) -> MulTeeResult<CtxPK> {
  let ctx = CtxPK::new();
  let mut start = pub_key.as_ptr() as *mut libc::c_uchar;
  let end = start.add(pub_key.len());

  mbed_err_check(mbedtls_pk_parse_subpubkey(
    &mut start,
    end,
    ctx.force_mut_ptr(),
  ))?;

  Ok(ctx)
}

pub(crate) unsafe fn mpi_to_bytes(mpi: *const mbedtls_mpi) -> MulTeeResult<Vec<u8>> {
  let size = mbedtls_mpi_size(mpi);

  mpi_to_bytes_sized(mpi, size)
}

unsafe fn mpi_to_bytes_sized(mpi: *const mbedtls_mpi, size: usize) -> MulTeeResult<Vec<u8>> {
  let mut res = vec![0u8; size];

  mbed_err_check(mbedtls_mpi_write_binary(mpi, res.as_mut_ptr(), res.len()))?;
  Ok(res)
}

pub unsafe fn get_exponent(pub_key: &[u8]) -> MulTeeResult<Vec<u8>> {
  let pubkey = parse_pubkey(pub_key)?;
  let rsa = pubkey.ctx.pk_ctx as *mut mbedtls_rsa_context;

  mpi_to_bytes(&(*rsa).E)
}

pub unsafe fn get_modulus(pub_key: &[u8]) -> MulTeeResult<Vec<u8>> {
  let pubkey = parse_pubkey(pub_key)?;
  let rsa = pubkey.ctx.pk_ctx as *mut mbedtls_rsa_context;

  mpi_to_bytes(&(*rsa).N)
}

pub unsafe fn get_ec_params(pub_key: &[u8]) -> MulTeeResult<Vec<u8>> {
  // for n in prime256v1 secp521r1 secp384r1 secp256k1; do echo -n $n; openssl ecparam -name $n -outform der|xxd -i; done

  let pubkey = parse_pubkey(pub_key)?;
  let ec = pubkey.ctx.pk_ctx as *mut mbedtls_ecp_keypair;
  let ec = *ec;

  let mut oid: *const i8 = std::ptr::null();
  let mut oid_len: usize = 0;
  let mut buf = vec![0u8; 64];

  mbed_err_check(mbedtls_oid_get_oid_by_ec_grp(
    ec.grp.id,
    &mut oid,
    &mut oid_len,
  ))?;
  let mut p = buf.as_mut_ptr().add(buf.len());
  let len = mbedtls_asn1_write_oid(&mut p, buf.as_mut_ptr(), oid, oid_len) as usize;
  Ok(Vec::from(&buf.as_slice()[buf.len() - len..]))
}

pub unsafe fn get_ec_point(pub_key: &[u8]) -> MulTeeResult<Vec<u8>> {
  let pubkey = parse_pubkey(pub_key)?;
  let ec = pubkey.ctx.pk_ctx as *mut mbedtls_ecp_keypair;
  let ec = *ec;

  let mut buf = vec![0u8; MBEDTLS_ECP_MAX_PT_LEN as usize];
  let mut len: usize = 0;

  mbed_err_check(mbedtls_ecp_point_write_binary(
    &ec.grp,
    &ec.Q,
    MBEDTLS_ECP_PF_UNCOMPRESSED as libc::c_int,
    &mut len,
    buf.as_mut_ptr(),
    buf.len(),
  ))?;

  buf.truncate(len);

  Ok(buf)
}

pub unsafe fn hash2(alg: HashingAlgorithm, data: &[u8]) -> MulTeeResult<Vec<u8>> {
  hash(kmip_to_mbedtls_digest(alg)?, data)
}

pub unsafe fn hash(md_type: mbedtls_md_type_t, data: &[u8]) -> MulTeeResult<Vec<u8>> {
  let md_info = mbedtls_md_info_from_type(md_type);
  let size = mbedtls_md_get_size(md_info);

  let mut hash = vec![0u8; size as usize];

  mbed_err_check(mbedtls_md(
    md_info,
    data.as_ptr(),
    data.len(),
    hash.as_mut_ptr(),
  ))?;

  Ok(hash)
}

pub unsafe fn hash_sha256(data: &[u8]) -> MulTeeResult<Vec<u8>> {
  hash(mbedtls_sys::mbedtls_md_type_t::MBEDTLS_MD_SHA256, data)
}

pub fn kmip_to_mbedtls_padding_params(
  padding: RsaPadding,
) -> MulTeeResult<(mbedtls_cipher_padding_t, mbedtls_md_type_t)> {
  Ok((
    kmip_to_mbedtls_padding(padding.0)?,
    kmip_to_mbedtls_digest(padding.1)?,
  ))
}
pub fn kmip_to_mbedtls_padding(method: PaddingMethod) -> MulTeeResult<mbedtls_cipher_padding_t> {
  match method {
    PaddingMethod::PSS => Ok(MBEDTLS_RSA_PKCS_V21),
    PaddingMethod::PKCS1_V1_5 => Ok(MBEDTLS_RSA_PKCS_V15),
    PaddingMethod::None => todo!(),
    PaddingMethod::OAEP => todo!(),
    PaddingMethod::PKCS5 => todo!(),
  }
}
pub fn kmip_to_mbedtls_digest(alg: HashingAlgorithm) -> MulTeeResult<mbedtls_md_type_t> {
  match alg {
    HashingAlgorithm::SHA256 => Ok(mbedtls_md_type_t::MBEDTLS_MD_SHA256),
    _ => todo!(),
  }
}

pub(crate) struct RSACopy {
  pub pk: CtxPK,
  pub rsa: CtxRSA,
}

impl RSACopy {
  pub unsafe fn new(original: &CtxPK) -> MulTeeResult<RSACopy> {
    let mut rsa_copy = CtxRSA::new(0, 0);
    mbed_err_check(mbedtls_rsa_copy(
      rsa_copy.as_mut_ptr(),
      original.ctx.pk_ctx as *mut mbedtls_rsa_context,
    ))?;

    let mut pk_copy = CtxPK::new();
    pk_copy.ctx.pk_info = original.ctx.pk_info;
    pk_copy.ctx.pk_ctx = rsa_copy.as_mut_ptr() as *mut libc::c_void;

    Ok(RSACopy {
      pk: pk_copy,
      rsa: rsa_copy,
    })
  }
}

impl Drop for RSACopy {
  fn drop(&mut self) {
    self.pk.ctx.pk_info = std::ptr::null();
  }
}

pub(crate) fn prep_rnd() -> MulTeeResult<(CtxEntropy, CtxCTRDRBG)> {
  unsafe {
    let entropy_ctx = CtxEntropy::new();
    let ctr_drbg_ctx = CtxCTRDRBG::new();

    mbed_err_check(mbedtls_ctr_drbg_seed(
      ctr_drbg_ctx.force_mut_ptr(),
      Some(mbedtls_entropy_func),
      entropy_ctx.force_mut_ptr() as *mut libc::c_void,
      DUMMY_SEED.as_ptr(),
      DUMMY_SEED.len(),
    ))?;
    Ok((entropy_ctx, ctr_drbg_ctx))
  }
}

// pub(crate) struct ECPCopy {
//   pub pk: CtxPK,
//   _ecp: CtxECP
// }
//
// impl ECPCopy {
//   pub unsafe fn new(original: &CtxPK) -> MulTeeResult<ECPCopy> {
//     let mut ecp_copy = CtxECP::new();
//
//
//     mbed_err_check(
//     mbedtls_mpi_copy(&mut ecp_copy.ctx.d, &(*(original.ctx.pk_ctx as *const mbedtls_ecp_keypair)).d)
//     )?;
//     mbed_err_check(
//       mbedtls_ecp_copy(&mut ecp_copy.ctx.Q, &(*(original.ctx.pk_ctx as *const mbedtls_ecp_keypair)).Q)
//     )?;
//     ecp_copy.ctx.grp = (*(original.ctx.pk_ctx as *const mbedtls_ecp_keypair)).grp;
//
//     let mut pk_copy = CtxPK::new();
//     pk_copy.ctx.pk_info = original.ctx.pk_info;
//     pk_copy.ctx.pk_ctx = ecp_copy.as_mut_ptr() as *mut libc::c_void;
//
//     Ok(ECPCopy {
//       pk: pk_copy,
//       _ecp: ecp_copy
//     })
//   }
// }
//
// impl Drop for ECPCopy {
//   fn drop(&mut self) {
//     self.pk.ctx.pk_info = std::ptr::null();
//   }
// }

pub(crate) fn mbed_err_check(ret: i32) -> MulTeeResult<()> {
  match ret {
    0 => Ok(()),
    err => mbed_err(err),
  }
}

pub(crate) fn mbed_sig_err_check(fail: i32, ret: i32) -> MulTeeResult<bool> {
  match ret {
    0 => Ok(true),
    x if x == fail => Ok(false),
    err => mbed_err(err),
  }
}

fn mbed_err<T>(ret: i32) -> MulTeeResult<T> {
  unsafe {
    let mut buf = vec![0u8; MulTeeErrorBuf::MAX_ERR_MESSAGE_LENGTH];
    mbedtls_strerror(
      ret,
      buf.as_mut_ptr() as *mut i8,
      MulTeeErrorBuf::MAX_ERR_MESSAGE_LENGTH,
    );

    let nul_range_end = buf.iter().position(|&c| c == b'\0').unwrap_or(buf.len()); // default to length if no `\0` present
    let msg = ::std::str::from_utf8(&buf[0..nul_range_end])
      .unwrap_or("mbedtls provided inconsistent error message")
      .to_string();

    Err(MulTeeErrCode::CRYPTO_MBED.nested(ret, msg))
  }
}
