use common::api::{KMSEndPoint, KeyData, KeyUsageMask, MulTeeCore, RsaPadding};
use common::constants::{
  KMIP_OVERHEAD_HINT, MULTEE_GCM_IV_BYTES, MULTEE_GCM_TAG_BYTES, REMOTE_TTLV_BUFFER_SIZE,
};
use common::error::MulTeeErrCode::CRYPTO_INVALID_KEY_INDEX;
use common::error::MulTeeResult;
use either::{Either, Left, Right};
use kmip::enumerations::CryptographicAlgorithm;
use kmip::enumerations::HashingAlgorithm;
use log::info;
use multee_core::api::{MtlsImpl, Tee};
use multee_core::kmip_client::KeyExportMode;
use multee_core::serde_json::Value;
use multee_core::tls;
use rustls::ClientSession;
use rustls::Stream;
use std::cell::Cell;
use std::net::TcpStream;
use std::sync::Mutex;

pub(crate) struct RemoteKMIP {
  uri_passwd: Option<(String, String)>,
  keys: Vec<KeyData>,
  tls: Mutex<Cell<(ClientSession, TcpStream)>>,
}

impl RemoteKMIP {
  fn with_tls<X, F>(&self, f: F) -> MulTeeResult<X>
  where
    F: FnOnce(&mut Stream<ClientSession, TcpStream>) -> MulTeeResult<X>,
  {
    let mut tls = self.tls.lock().unwrap();
    let tls = tls.get_mut();
    let mut tls = Stream::new(&mut tls.0, &mut tls.1);
    f(&mut tls)
  }

  #[inline]
  fn get_key(&self, key_index: usize) -> MulTeeResult<&KeyData> {
    self
      .keys
      .get(key_index)
      .ok_or(CRYPTO_INVALID_KEY_INDEX.no_msg())
  }

  #[inline]
  fn get_key_uuid(&self, key_index: usize) -> MulTeeResult<String> {
    self.get_key(key_index).map(|k| k.key_kmip_uuid.clone())
  }

  pub fn load_keys(key_ref: Either<&KMSEndPoint, &Vec<KeyData>>) -> MulTeeResult<RemoteKMIP> {
    match key_ref {
      Left(kms_info) => {
        let client_cert = tls::client_cert(
          kms_info.id_cred_secret.as_slice(),
          kms_info.id_cred_pub.as_str(),
        )?;

        let mut tls = tls::connect(
          Some(client_cert),
          kms_info.trusted_ca.as_str(),
          kms_info.kms_url.as_str(),
          kms_info.conn_timeout_sec,
        )?;

        let mut tls_ = Stream::new(&mut tls.0, &mut tls.1);

        let uri_passwd = tls::uri_passwd(kms_info.kms_url.as_str())?;

        let keys = kms_info
          .key_names
          .iter()
          .map(|key_name| {
            multee_core::kmip_client::read_key_data(
              &mut tls_,
              &uri_passwd,
              key_name,
              KeyExportMode::MetaDataOnly,
            )
          })
          .collect::<MulTeeResult<Vec<KeyData>>>()?;

        Ok(RemoteKMIP {
          uri_passwd,
          keys,
          tls: Mutex::new(Cell::new(tls)),
        })
      }
      Right(_literal) => {
        unreachable!()
      }
    }
  }
}

impl Tee for RemoteKMIP {
  fn import_keys(
    self, _key_ref: Either<&KMSEndPoint, &Vec<KeyData>>,
  ) -> MulTeeResult<MtlsImpl<Self>> {
    unreachable!()
  }

  fn seal_data(input: &[u8]) -> MulTeeResult<Vec<u8>> {
    Ok(input.to_vec())
  }
  fn unseal_data(sealed_data: &[u8]) -> MulTeeResult<Vec<u8>> {
    Ok(sealed_data.to_vec())
  }
  fn attestation(_grant_request: &[u8]) -> MulTeeResult<Value> {
    unreachable!()
  }
  fn attestation_kind() -> String {
    unreachable!()
  }
}

impl MulTeeCore for RemoteKMIP {
  fn crypt_cbc(
    &self, key_index: usize, encrypt: bool, explicit_iv: bool, iv: &mut [u8],
    crypto_buf: &mut [u8], input_len: usize,
  ) -> MulTeeResult<()> {
    let uuid = self.get_key_uuid(key_index)?;
    let mut buf = vec![0u8; crypto_buf.len() + KMIP_OVERHEAD_HINT];

    if encrypt {
      let algo = self.meta_key_type(key_index)?;
      let iv_opt = if explicit_iv {
        Some(iv.iter().as_slice())
      } else {
        None
      };

      let request = kmip::request::build(
        &self.uri_passwd,
        kmip::cbc::encrypt_request(uuid.as_str(), algo, &crypto_buf[..input_len], iv_opt),
      );

      let data = if explicit_iv {
        self.with_tls(|tls| {
          multee_core::kmip_client::send_request(
            tls,
            &mut buf,
            &request,
            kmip::cbc::parse_encrypt_response_without_iv,
          )
        })?
      } else {
        let (data, iv_) = self.with_tls(|tls| {
          multee_core::kmip_client::send_request(
            tls,
            &mut buf,
            &request,
            kmip::cbc::parse_encrypt_response_with_iv,
          )
        })?;
        iv.copy_from_slice(iv_.as_slice());
        data
      };
      crypto_buf[..input_len].copy_from_slice(&data.as_slice()[..input_len]);
      Ok(())
    } else {
      let algo = self.meta_key_type(key_index)?;

      let request = kmip::request::build(
        &self.uri_passwd,
        kmip::cbc::decrypt_request(uuid.as_str(), algo, &crypto_buf[..input_len], iv),
      );

      let data = self.with_tls(|tls| {
        multee_core::kmip_client::send_request(
          tls,
          &mut buf,
          &request,
          kmip::cbc::parse_decrypt_response,
        )
      })?;
      info!(
        "lengths: data:{}, crypto_buf: {}, input_len: {}",
        data.len(),
        crypto_buf.len(),
        input_len
      );
      let data_len = data.len();
      crypto_buf[..data_len].copy_from_slice(data.as_slice());
      let _padded_len = crate::util::pkcs5_pad(crypto_buf, data_len);

      Ok(())
    }
  }

  fn crypt_gcm(
    &self, key_index: usize, encrypt: bool, iv: &mut [u8], aad: Option<&[u8]>, in_buf: &[u8],
    out_buf: &mut [u8], tag: &mut [u8],
  ) -> MulTeeResult<()> {
    let uuid = self.get_key_uuid(key_index)?;
    let mut buf = vec![0u8; in_buf.len() + aad.map(|s| s.len()).unwrap_or(0) + KMIP_OVERHEAD_HINT];

    if encrypt {
      let algo = self.meta_key_type(key_index)?;

      let request = kmip::request::build(
        &self.uri_passwd,
        kmip::gcm::encrypt_request(
          uuid.as_str(),
          algo,
          MULTEE_GCM_TAG_BYTES as i32,
          MULTEE_GCM_IV_BYTES as i32,
          in_buf,
          aad,
        ),
      );

      let (data, tag_, iv_) = self.with_tls(|tls| {
        multee_core::kmip_client::send_request(
          tls,
          &mut buf,
          &request,
          kmip::gcm::parse_encrypt_response,
        )
      })?;
      tag.copy_from_slice(tag_.as_slice());
      iv.copy_from_slice(iv_.as_slice());
      out_buf.copy_from_slice(data.as_slice());
      Ok(())
    } else {
      let algo = self.meta_key_type(key_index)?;

      let request = kmip::request::build(
        &self.uri_passwd,
        kmip::gcm::decrypt_request(uuid.as_str(), algo, in_buf, iv, tag, aad),
      );

      let data = self.with_tls(|tls| {
        multee_core::kmip_client::send_request(
          tls,
          &mut buf,
          &request,
          kmip::gcm::parse_decrypt_response,
        )
      })?;
      out_buf.copy_from_slice(data.as_slice());
      Ok(())
    }
  }

  fn sign<'a>(
    &self, key_index: usize, padding: Option<RsaPadding>, _md_type: HashingAlgorithm, digest: &[u8],
  ) -> MulTeeResult<Vec<u8>> {
    let uuid = self.get_key_uuid(key_index)?;
    let mut buf = [0u8; REMOTE_TTLV_BUFFER_SIZE];
    let algo = self.meta_key_type(key_index)?;

    let request = kmip::request::build(
      &self.uri_passwd,
      kmip::sign::request(uuid.as_str(), algo, &padding, digest),
    );

    self.with_tls(|tls| {
      multee_core::kmip_client::send_request(
        tls,
        &mut buf,
        &request,
        kmip::sign::parse_sign_response,
      )
      .map(|slice| slice.to_vec())
    })
  }

  fn hmac_sha256(&self, key_index: usize, input: &[u8]) -> MulTeeResult<Vec<u8>> {
    let uuid = self.get_key_uuid(key_index)?;
    let mut buf = vec![0u8; KMIP_OVERHEAD_HINT];

    let request = kmip::request::build(&self.uri_passwd, kmip::hmac::request(uuid.as_str(), input));

    self.with_tls(|tls| {
      multee_core::kmip_client::send_request(
        tls,
        &mut buf,
        &request,
        kmip::hmac::parse_mac_response,
      )
      .map(|slice| slice.to_vec())
    })
  }

  fn meta_key_type(&self, key_index: usize) -> MulTeeResult<CryptographicAlgorithm> {
    self.get_key(key_index).map(|k| k.key_type.clone())
  }

  fn meta_key_len(&self, key_index: usize) -> MulTeeResult<u64> {
    self.get_key(key_index).map(|k| k.key_length as u64)
  }

  fn meta_key_usage_mask(&self, key_index: usize) -> MulTeeResult<KeyUsageMask> {
    self.get_key(key_index).map(|k| k.usage_mask)
  }

  fn get_public_key(&self, key_index: usize) -> MulTeeResult<Vec<u8>> {
    let name = self.get_key(key_index).map(|k| k.name.clone())?;

    // info!("get_public_key");
    let pub_key: MulTeeResult<KeyData> = self.with_tls(|tls| {
      multee_core::kmip_client::read_key_data(
        tls,
        &self.uri_passwd,
        name.as_str(),
        KeyExportMode::PublicKeyOnly,
      )
    });

    pub_key.map(|k| k.key_material)
  }

  fn meta_key_count(&self) -> MulTeeResult<u64> {
    Ok(self.keys.len() as u64)
  }

  fn meta_key_name(&self, key_index: usize) -> MulTeeResult<String> {
    self.get_key(key_index).map(|k| k.name.clone())
  }

  fn mk_csr(&self, _subject_name: &str, _pinned: bool) -> MulTeeResult<(Vec<u8>, Vec<u8>)> {
    unreachable!()
  }

  fn seal_pk(&self, _private_key: &[u8]) -> MulTeeResult<Vec<u8>> {
    unreachable!()
  }
}
