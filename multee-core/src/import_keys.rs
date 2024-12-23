use std::io::{Read, Write};
use std::vec::Vec;

use http::uri;
use rustls::*;

use crate::api::CtxCTRDRBG;
use crate::api::Tee;
use crate::kmip_client::KMIPKeyImporter;
use common::api::KMSEndPoint;
use common::api::KeyData;
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use log::debug;

const ATTESTATION_URL_QUERY: &str = "triple_a=";
const TRIPLE_A_CSR_CN: &str = "triple_a_csr_cn=";

pub(crate) trait KeyImporter<T: Read + Write> {
  fn import_keys(&self, tls: &mut T, key_names: &Vec<String>) -> MulTeeResult<Vec<KeyData>>;
}

pub(crate) fn import_keys_from_end_point<T: Tee>(
  end_point_u: &KMSEndPoint, rng: &CtxCTRDRBG,
) -> MulTeeResult<Vec<KeyData>> {
  debug!("import_keys_from_end_point");
  match crate::tls::uri_scheme(end_point_u.kms_url.as_str())?.as_str() {
    "kmip" => {
      let pkey = T::unseal_pk(end_point_u.id_cred_secret.as_slice())?;

      let identity_cert =
        crate::tls::client_cert(pkey.as_slice(), end_point_u.id_cred_pub.as_str())?;

      let client_cert =
        match crate::tls::uri_query(end_point_u.kms_url.as_str(), ATTESTATION_URL_QUERY)? {
          Some(aaa_url) => {
            let _ = aaa_url
              .parse::<uri::Uri>()
              .map_err(|_| MulTeeErrCode::CORRUPT_URI.msg("Unable to parse TripleA URI"))?;

            if let Some(cn) = crate::tls::uri_query(end_point_u.kms_url.as_str(), TRIPLE_A_CSR_CN)?
            {
              let mut tls = crate::tls::connect(
                Some(identity_cert),
                end_point_u.trusted_ca.as_str(),
                aaa_url.as_str(),
                end_point_u.conn_timeout_sec,
              )?;
              let mut tls = Stream::new(&mut tls.0, &mut tls.1);

              let (cert, pk) = crate::triple_a_client::attest_csr::<T, _>(
                &mut tls,
                aaa_url.as_str(),
                cn.as_str(),
                rng,
              )?;

              crate::tls::client_cert(pk.as_slice(), cert.as_str())?
            } else {
              return Err(MulTeeErrCode::CORRUPT_URI.msg("Missing CN in TripleA parameters"));
            }
          }
          None => identity_cert,
        };

      let mut tls = crate::tls::connect(
        Some(client_cert),
        end_point_u.trusted_ca.as_str(),
        end_point_u.kms_url.as_str(),
        end_point_u.conn_timeout_sec,
      )?;
      let mut tls = Stream::new(&mut tls.0, &mut tls.1);

      let uri_passwd = crate::tls::uri_passwd(end_point_u.kms_url.as_str())?;
      let importer = KMIPKeyImporter::new(uri_passwd);

      importer.import_keys(&mut tls, &end_point_u.key_names)
    }
    s => Err(MulTeeErrCode::CRYPTO_UNSUPPORTED_SCHEME_FOR_KEY_IMPORT.msg(s)),
  }
}
