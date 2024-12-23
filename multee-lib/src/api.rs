use chrono::Utc;
use core::todo;
use dlopen_derive::WrapperApi;
use either::{Either, Left, Right};
use env_logger;
use http::uri;
use log::{debug, error, info};
use std::collections::HashMap;
use std::io::Write;
use std::sync::{Arc, Once};
use std::{env, mem};

#[cfg(feature = "with-sevsnp")]
use sev::firmware::guest::*;
// use sev_snp_utilities::{AttestationReport, Requester};

use common::api::KMSEndPoint;
use common::api::RsaPadding;
use common::api::{KeyData, MulTeeCore};
use common::constants::MULTEE_BLOCK_SIZE;
use common::constants::MULTEE_GCM_IV_BYTES;
use common::constants::MULTEE_GCM_TAG_BYTES;
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;

use multee_core::api::Tee;

use kmip::enumerations::CryptographicAlgorithm;
use kmip::enumerations::HashingAlgorithm;

use multee_core::mtls::get_ec_params;
use multee_core::mtls::get_ec_point;
use multee_core::mtls::get_exponent;
use multee_core::mtls::get_modulus;
use multee_core::mtls::hash2;
use multee_core::mtls::verify_sig2;

use crate::util::delete_tmp_dir;
use crate::util::extract_files;
use crate::util::has_sev;
use crate::util::has_tdx;
use crate::util::is_intel;
use crate::util::want_sim;

use crate::credentials::pin_credentials;
use dlopen::wrapper::{Container, WrapperApi};
use multee_core::serde_json::Value;
// use crate::err::map_known_err;
use crate::remote_kmip::RemoteKMIP;

#[derive(WrapperApi)]
struct PluginApi {
  #[allow(improper_ctypes_definitions)]
  load_sgx: extern "C" fn(
    want_sim: bool,
    key_ref: Either<&KMSEndPoint, &Vec<KeyData>>,
  ) -> MulTeeResult<*mut dyn MulTeeCore>,
}

static LOGGER: Once = Once::new();

fn overridden() -> bool {
  env::var("MULTEE_LITE").is_ok()
}

#[derive(Clone)]
pub struct EnclaveSession {
  dynamic: Arc<dyn MulTeeCore>,
  key_name_to_index: HashMap<String, usize>,
}
unsafe impl Send for EnclaveSession {}

impl EnclaveSession {
  pub fn configure_logging(logger_pipe: Option<Box<dyn Write + Send + 'static>>) {
    LOGGER.call_once(|| {
      if let Some(pipe) = logger_pipe {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
          .format(|buf, record| {
            writeln!(
              buf,
              "{}:{} {} [{}] - {}",
              record.file().unwrap_or("unknown"),
              record.line().unwrap_or(0),
              Utc::now().format("%Y-%m-%dT%H:%M:%S%.3f"),
              record.level(),
              record.args()
            )
          })
          .target(env_logger::Target::Pipe(pipe))
          .init();
      } else {
        let _ignore = env_logger::try_init();
      }
    });
  }

  pub fn load_keys(
    id_creds_file: &str, url: &str, key_names: Vec<String>,
    logger_pipe: Option<Box<dyn Write + Send + 'static>>,
  ) -> MulTeeResult<Self> {
    Self::configure_logging(logger_pipe);

    let uri = url
      .parse::<uri::Uri>()
      .map_err(|_| MulTeeErrCode::CORRUPT_URI.msg("Unable to parse URI"))?;
    let scheme = uri
      .scheme_str()
      .ok_or(MulTeeErrCode::CORRUPT_URI.msg("Unable to extract scheme from URI"))?;

    let key_name_to_index: HashMap<String, usize> = key_names
      .iter()
      .enumerate()
      .map(|x| (x.1.clone(), x.0))
      .collect();

    let (import_params, creds_pinned) = if key_names.is_empty() {
      (Right(Vec::new()), true)
    } else {
      let uri = url
        .parse::<uri::Uri>()
        .map_err(|_| MulTeeErrCode::CORRUPT_URI.msg("Unable to parse URI"))?;
      let scheme = uri
        .scheme_str()
        .ok_or(MulTeeErrCode::CORRUPT_URI.msg("Unable to extract scheme from URI"))?;

      if scheme == "file" {
        (
          Right(crate::literal::read_literal(
            id_creds_file,
            "unpinned",
            key_names,
          )?),
          true,
        )
      } else {
        let (ca_chain, id_cred_pub, id_cred_secret, pinned) =
          crate::credentials::get_credentials_from_zip(id_creds_file)?;
        let trusted_ca =
          String::from_utf8(ca_chain).map_err(|_| MulTeeErrCode::CORRUPT_UTF8.no_msg())?;
        let id_cred_pub =
          String::from_utf8(id_cred_pub).map_err(|_| MulTeeErrCode::CORRUPT_UTF8.no_msg())?;

        info!("importing keys, url: {}, key names: {:?}", url, key_names);

        let kms = KMSEndPoint {
          kms_url: url.to_string(),
          key_names,
          trusted_ca,
          id_cred_pub,
          id_cred_secret,
          conn_timeout_sec: 5,
        };
        (Left(kms), pinned)
      }
    };

    let session = if scheme == "remote" {
      info!("Running in Remote mode");
      EnclaveSession {
        dynamic: Arc::new(RemoteKMIP::load_keys(import_params.as_ref())?),
        key_name_to_index: key_name_to_index,
      }
    } else if cfg!(feature = "with-intel-tdx") && is_intel() && has_tdx() && !overridden() {
      debug!("Running in Intel TDX mode");
      EnclaveSession {
        dynamic: Arc::new(TdxCvm {}.import_keys(import_params.as_ref())?),
        key_name_to_index: key_name_to_index,
      }
    } else if cfg!(feature = "with-sevsnp")
      && (env::var("MULTEE_FORCE_SNP").is_ok() || has_sev() && !overridden())
    {
      debug!("Running in SEV-SNP mode");
      EnclaveSession {
        dynamic: Arc::new(SevSnpCvm {}.import_keys(import_params.as_ref())?),
        key_name_to_index: key_name_to_index,
      }
    } else if cfg!(feature = "with-dcap") && is_intel() && !overridden() {
      debug!("Running in SGX mode");

      let (dir, file) = extract_files().map_err(|e| {
        MulTeeErrCode::ENCLAVE_ARTIFACT_IO.msg(format!("Unable to extract untrusted: {}", e))
      })?;

      debug!("Loading SGX untrusted module {}", file);
      let plugin_api_wrapper: Container<PluginApi> =
        unsafe { Container::load(file) }.map_err(|e| {
          MulTeeErrCode::ENCLAVE_ARTIFACT_IO.msg(format!("Unable to load untrusted: {}", e))
        })?;

      let multee_ptr: *mut dyn MulTeeCore =
        plugin_api_wrapper.load_sgx(want_sim(), import_params.as_ref())?;
      let multee: Box<dyn MulTeeCore> = unsafe { Box::from_raw(multee_ptr) };
      let multee: Arc<dyn MulTeeCore> = Arc::from(multee);
      // Prevent library from unloading. Untrusted RTS registers signal handlers, etc
      let _ = Box::into_raw(Box::new(plugin_api_wrapper));

      if env::var("MULTEE_KEEP_EXTRACTED").is_err() && delete_tmp_dir(dir).is_err() {
        error!("Unable to delete MulTee dir");
      }

      debug!("SGX untrusted module loaded");
      EnclaveSession {
        dynamic: multee,
        key_name_to_index: key_name_to_index,
      }
    } else {
      info!("Running in MulTee-Lite mode");

      EnclaveSession {
        dynamic: Arc::new(MulTeeLite {}.import_keys(import_params.as_ref())?),
        key_name_to_index: key_name_to_index,
      }
    };

    if env::var("MULTEE_PIN_CREDENTIALS").is_ok() && !creds_pinned {
      pin_credentials(session.dynamic.as_ref(), id_creds_file)?;
    }

    Ok(session)
  }

  pub fn encrypt_cbc(
    &self, key_index: usize, explicit_iv: bool, iv: &mut [u8], crypto_buf: &mut [u8],
    input_len: usize,
  ) -> MulTeeResult<usize> {
    let padded_input_len = crate::util::pkcs5_pad(crypto_buf, input_len);

    self.dynamic.crypt_cbc(
      key_index,
      true,
      explicit_iv,
      iv,
      crypto_buf,
      padded_input_len,
    )?;

    Ok(padded_input_len)
  }

  pub fn decrypt_cbc(
    &self, key_index: usize, explicit_iv: bool, iv: &mut [u8], crypto_buf: &mut [u8],
    input_len: usize,
  ) -> MulTeeResult<usize> {
    self
      .dynamic
      .crypt_cbc(key_index, false, explicit_iv, iv, crypto_buf, input_len)?;

    // get number of padding bytes
    let pad_bytes = crypto_buf[input_len - 1] as usize;
    if pad_bytes < 1 || pad_bytes > MULTEE_BLOCK_SIZE {
      return Err(MulTeeErrCode::CRYPTO_BAD_PADDING.no_msg());
    }
    // remove padding
    let output_len = input_len - pad_bytes;
    for i in 0..pad_bytes {
      if (pad_bytes as u8) != crypto_buf[output_len + i] {
        return Err(MulTeeErrCode::CRYPTO_BAD_PADDING.no_msg());
      }
    }

    Ok(output_len)
  }

  pub fn encrypt_gcm(
    &self, key_index: usize, aad: Option<&[u8]>, in_buf: &[u8],
  ) -> MulTeeResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let mut iv = vec![0u8; MULTEE_GCM_IV_BYTES];
    let mut tag = vec![0u8; MULTEE_GCM_TAG_BYTES];
    let mut out = vec![0u8; in_buf.len()];

    self.dynamic.crypt_gcm(
      key_index,
      true,
      iv.as_mut_slice(),
      aad,
      in_buf,
      out.as_mut_slice(),
      tag.as_mut_slice(),
    )?;

    Ok((out, iv, tag))
  }

  pub fn decrypt_gcm(
    &self, key_index: usize, aad: Option<&[u8]>, in_buf: &[u8], iv: &[u8], tag: &[u8],
  ) -> MulTeeResult<Vec<u8>> {
    let tag = unsafe { std::slice::from_raw_parts_mut(tag.as_ptr() as *mut u8, tag.len()) };
    let iv = unsafe { std::slice::from_raw_parts_mut(iv.as_ptr() as *mut u8, iv.len()) };
    let mut out = vec![0u8; in_buf.len()];

    self
      .dynamic
      .crypt_gcm(key_index, false, iv, aad, in_buf, out.as_mut_slice(), tag)
      .map(|_| out)
      .map_err(crate::err::map_known_err)
  }

  pub fn hmac_sha256(&self, key_index: usize, input: &[u8]) -> MulTeeResult<Vec<u8>> {
    self.dynamic.hmac_sha256(key_index, input)
  }

  pub fn sign(
    &self, key_index: usize, padding: Option<RsaPadding>, md_type: HashingAlgorithm, input: &[u8],
  ) -> MulTeeResult<Vec<u8>> {
    let hash = unsafe { hash2(md_type, input)? };

    self.sign_hash(key_index, padding, md_type, hash.as_slice())
  }

  pub fn sign_hash(
    &self, key_index: usize, padding: Option<RsaPadding>, md_type: HashingAlgorithm, hash: &[u8],
  ) -> MulTeeResult<Vec<u8>> {
    self.dynamic.sign(key_index, padding, md_type, hash)
  }

  pub fn verify(
    &self, key_index: usize, padding: Option<RsaPadding>, md_type: HashingAlgorithm, msg: &[u8],
    sig: &[u8],
  ) -> MulTeeResult<bool> {
    let hash = unsafe { hash2(md_type, msg)? };
    self.verify_hash(key_index, padding, md_type, hash.as_slice(), sig)
  }

  pub fn verify_hash(
    &self, key_index: usize, padding: Option<RsaPadding>, md_type: HashingAlgorithm, hash: &[u8],
    sig: &[u8],
  ) -> MulTeeResult<bool> {
    let pub_key = self.get_public_key(key_index)?;
    verify_sig2(pub_key, padding, md_type, hash, sig)
  }

  pub fn get_public_key(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    self.dynamic.get_public_key(key_index)
  }

  pub fn get_key_type(&self, key_index: usize) -> MulTeeResult<CryptographicAlgorithm> {
    self.dynamic.meta_key_type(key_index)
  }

  pub fn get_modulus(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    let pk = self.get_public_key(key_index)?;

    unsafe { get_modulus(pk.as_slice()) }
  }

  pub fn get_exponent(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    let pk = self.get_public_key(key_index)?;

    unsafe { get_exponent(pk.as_slice()) }
  }

  pub fn get_ec_params(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    let pk = self.get_public_key(key_index)?;

    unsafe { get_ec_params(pk.as_slice()) }
  }

  pub fn get_ec_point(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    let pk = self.get_public_key(key_index)?;

    unsafe { get_ec_point(pk.as_slice()) }
  }

  pub fn key_count(&self) -> MulTeeResult<usize> {
    Ok(self.dynamic.meta_key_count()? as usize)
  }

  pub fn key_index_map(&self) -> HashMap<String, usize> {
    self.key_name_to_index.clone()
  }

  pub fn key_name(&self, key_index: usize) -> MulTeeResult<String> {
    self.dynamic.meta_key_name(key_index)
  }

  pub fn key_len(&self, key_index: usize) -> MulTeeResult<u64> {
    self.dynamic.meta_key_len(key_index)
  }

  // pub(crate) fn key_len_internal(&self, _key_index: usize) -> usize {
  //   todo!()
  //   // self.key_handles.borrow().map(|v| v[key_index].length).expect("Impossible: key_len_internal - internal use only")
  // }

  pub fn mk_csr_zip(&self, filename: &str, sn: &str) -> MulTeeResult<()> {
    crate::credentials::multee_mk_csr_zip(self.dynamic.as_ref(), filename, sn, true)
  }

  #[allow(dead_code)]
  fn seal_pk(&self, input: &[u8]) -> MulTeeResult<Vec<u8>> {
    self.dynamic.seal_pk(input)
  }
}

struct MulTeeLite {}
impl MulTeeLite {
  fn todo() {
    eprintln!("TODO: obfuscation");
  }
}

impl Tee for MulTeeLite {
  fn seal_data(input: &[u8]) -> MulTeeResult<Vec<u8>> {
    Self::todo();
    Ok(input.to_vec())
  }
  fn unseal_data(sealed_data: &[u8]) -> MulTeeResult<Vec<u8>> {
    Self::todo();
    Ok(sealed_data.to_vec())
  }
  fn attestation(_grant_request: &[u8]) -> MulTeeResult<Value> {
    Self::todo();
    todo!();
  }
  fn attestation_kind() -> String {
    "lite".to_string()
  }
}

struct SevSnpCvm {}
impl SevSnpCvm {
  fn todo() {
    eprintln!("TODO: SEV-SNP key derivation");
  }
  fn map_err<T: ToString>(e: T) -> common::error::MulTeeError {
    MulTeeErrCode::SEVSNP_REPORT.msg(e.to_string())
  }
}

impl Tee for SevSnpCvm {
  fn seal_data(input: &[u8]) -> MulTeeResult<Vec<u8>> {
    Self::todo();
    Ok(input.to_vec())
  }
  fn unseal_data(sealed_data: &[u8]) -> MulTeeResult<Vec<u8>> {
    Self::todo();
    Ok(sealed_data.to_vec())
  }
  fn attestation_kind() -> String {
    "sev-snp".to_string()
  }
  #[cfg(feature = "with-sevsnp")]
  fn attestation(payload: &[u8]) -> MulTeeResult<Value> {
    let mut grant_request = [0u8; 64];
    let hash = unsafe { hash2(HashingAlgorithm::SHA256, payload).expect("Impossible") };
    grant_request[..hash.len()].copy_from_slice(hash.as_slice());

    let rep = Firmware::open().map_err(Self::map_err).and_then(|mut f| {
      f.get_report(None, Some(grant_request), None)
        .map_err(Self::map_err)
    });

    match rep {
      Ok(report) => {
        let bytes: [u8; mem::size_of::<AttestationReport>()] =
          unsafe { mem::transmute_copy(&report) };
        Ok(multee_core::serde_json::json!({
          "kind": "SEVSNP",
          "value": {
            "report": multee_core::base64::encode(&bytes),
            "vekCert": "TODO: VLEK OR VCEK",
            "intermediateCA": "TODO",}
        }))
      }
      Err(_) if env::var("MULTEE_FORCE_SNP").is_ok() => Ok(multee_core::serde_json::json!({
        "kind": "SEVSNP",
        "value": {
            "report": multee_core::base64::encode(crate::sevsnp_test_blobs::DUMMY_SNP_REPORT),
            "vekCert": multee_core::base64::encode(crate::sevsnp_test_blobs::DUMMY_SNP_VCEK_MILAN),
            "intermediateCA": crate::sevsnp_test_blobs::DUMMY_SNP_INT_MILAN,
        }
      })),
      Err(e) => Err(MulTeeErrCode::SEVSNP_REPORT.msg(e.to_string())),
    }
  }
  #[cfg(not(feature = "with-sevsnp"))]
  fn attestation(_grant_request: &[u8]) -> MulTeeResult<Value> {
    unreachable!()
  }
}

struct TdxCvm {}
impl TdxCvm {
  fn todo() {
    eprintln!("TODO: Intel TDX key derivation");
  }
}
impl Tee for TdxCvm {
  fn seal_data(input: &[u8]) -> MulTeeResult<Vec<u8>> {
    Self::todo();
    Ok(input.to_vec())
  }
  fn unseal_data(sealed_data: &[u8]) -> MulTeeResult<Vec<u8>> {
    Self::todo();
    Ok(sealed_data.to_vec())
  }
  fn attestation(_grant_request: &[u8]) -> MulTeeResult<Value> {
    todo!()
  }
  fn attestation_kind() -> String {
    "tdx".to_string()
  }
}

// TODO: ARM CCA
