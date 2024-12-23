use std::io::{Read, Write};
use std::string::String;
use std::vec::Vec;

use common::constants::MAX_KMIP_KEY_LEN;
use kmip::constants::Tag;
use kmip::enumerations::{CryptographicAlgorithm, ObjectType};
use kmip::ttlv::{parse_ttlv_len, Ttlv};

use crate::import_keys::KeyImporter;
use crate::tls::format_rustls_io_err;
use common::api::KeyData;
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use kmip::error::KmipError;
use log::{debug, warn};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum KeyExportMode {
  MetaDataOnly,
  Full,
  PublicKeyOnly,
}

pub struct KMIPKeyImporter {
  passwd_auth: Option<(String, String)>,
}

impl<'a> KMIPKeyImporter {
  pub fn new(passwd_auth: Option<(String, String)>) -> KMIPKeyImporter {
    KMIPKeyImporter { passwd_auth }
  }
}

impl<T: Read + Write> KeyImporter<T> for KMIPKeyImporter {
  fn import_keys(&self, tls: &mut T, key_names: &Vec<String>) -> MulTeeResult<Vec<KeyData>> {
    debug!("KMIPKeyImporter:import_keys");
    let mut key_vec = Vec::new();

    for key_name in key_names {
      let key_data = read_key_data(
        tls,
        &self.passwd_auth,
        key_name.as_str(),
        KeyExportMode::Full,
      )?;
      key_vec.push(key_data);
    }

    Ok(key_vec)
  }
}

pub fn read_key_data<T: Read + Write>(
  tls: &mut T, passwd: &Option<(String, String)>, key_name: &str, export: KeyExportMode,
) -> MulTeeResult<KeyData> {
  let mut buf = vec![0u8; MAX_KMIP_KEY_LEN];

  let locate_request = kmip::request::build(passwd, kmip::request::locate_key(key_name));

  let uuids: Vec<String> = send_request(
    tls,
    buf.as_mut_slice(),
    &locate_request,
    kmip::response::parse_uuids,
  )
  .map_err(|e| {
    MulTeeErrCode::KEY_IMPORT.msg(format!("unable to locate key {}: {:?}", key_name, e))
  })?;

  let mut key_data: Vec<KeyData> = uuids
    .into_iter()
    .map(|uuid| {
      fetch_key(
        tls,
        passwd,
        buf.as_mut_slice(),
        key_name,
        uuid.as_str(),
        export,
      )
    })
    .filter_map(flatten_fetch_filter)
    .collect::<MulTeeResult<Vec<KeyData>>>()?;

  match key_data.len() {
    1 => Ok(key_data.pop().expect("impossible")),
    0 => Err(MulTeeErrCode::KEY_IMPORT.msg("Unsupported key type (read_key_data)")),
    _ => Err(MulTeeErrCode::KEY_IMPORT.msg("Ambiguous key name")),
  }
}

fn fetch_key<T: Read + Write>(
  tls: &mut T, passwd: &Option<(String, String)>, buf: &mut [u8], name: &str, uuid: &str,
  export: KeyExportMode,
) -> MulTeeResult<Option<KeyData>> {
  let get_attr_request = kmip::request::build(passwd, kmip::request::get_attributes(uuid));

  let (algo, obj_type, usage_mask, len) =
    send_request(tls, buf, &get_attr_request, kmip::response::parse_attrs)?;

  let key_tag = match (export, algo, obj_type) {
    (_, CryptographicAlgorithm::AES, _) => Tag::SymmetricKey,
    (
      KeyExportMode::MetaDataOnly | KeyExportMode::Full,
      CryptographicAlgorithm::RSA | CryptographicAlgorithm::ECDSA,
      ObjectType::PrivateKey,
    ) => Tag::PrivateKey,
    (
      KeyExportMode::PublicKeyOnly,
      CryptographicAlgorithm::RSA | CryptographicAlgorithm::ECDSA,
      ObjectType::PublicKey,
    ) => Tag::PublicKey,
    _ => return Ok(None),
  };

  if export != KeyExportMode::MetaDataOnly {
    let get_request = kmip::request::build(passwd, kmip::request::get_key(uuid));
    let key_material = send_request(tls, buf, &get_request, |ttlv: &Ttlv| {
      kmip::response::parse_key_material(ttlv, key_tag)
    })?;

    Ok(Some(KeyData {
      name: String::from(name),
      key_type: algo,
      object_type: obj_type,
      usage_mask: usage_mask,
      key_length: len,
      key_material,
      key_kmip_uuid: uuid.to_string(),
    }))
  } else {
    Ok(Some(KeyData {
      name: String::from(name),
      key_type: algo,
      object_type: obj_type,
      usage_mask: usage_mask,
      key_length: len,
      key_material: Vec::new(),
      key_kmip_uuid: uuid.to_string(),
    }))
  }
}

pub fn send_request<'a, T: Read + Write, F, R>(
  tls: &mut T, buf: &'a mut [u8], request: &Ttlv, func: F,
) -> MulTeeResult<R>
where
  F: FnOnce(&Ttlv) -> Result<R, KmipError>,
{
  let request_len = request.marshal(buf)?;
  let response_len = send_request_tls(tls, buf, request_len).map_err(|e| {
    format_rustls_io_err(e, MulTeeErrCode::RUSTLS_IO, "R/W IO error in KMIP session")
  })?;
  let (ttlv_response, _) = Ttlv::unmarshal(&buf[..response_len])?;

  // TODO: parse and return KMIP errors
  let payload = kmip::response::parse_batch_item(&ttlv_response).map_err(|e| {
    warn!("send_request.err {:?}", e);
    warn!("send_request.ttlv_response: {:?}", ttlv_response);
    MulTeeErrCode::KMIP.msg("Response didn't contain batch items")
  })?;

  func(&payload).map_err(|e| {
    warn!("send_request.parse..err {:?}", e);
    warn!("send_request.parse..ttlv_response: {:?}", payload);
    MulTeeErrCode::KMIP.msg(e.to_string())
  })
}

fn send_request_tls<T: Read + Write>(
  tls: &mut T, buf: &mut [u8], req_len: usize,
) -> Result<usize, std::io::Error> {
  tls.flush()?;
  tls.write_all(&buf[..req_len])?;
  tls.read_exact(&mut buf[..8])?;
  let size = parse_ttlv_len(&buf[4..8]) + 8;
  tls.read_exact(&mut buf[8..size])?;
  Ok(size)
}

#[inline]
fn flatten_fetch_filter<T>(item: MulTeeResult<Option<T>>) -> Option<MulTeeResult<T>> {
  match item {
    Ok(None) => None,
    Ok(Some(x)) => Some(Ok(x)),
    Err(e) => Some(Err(e)),
  }
}
