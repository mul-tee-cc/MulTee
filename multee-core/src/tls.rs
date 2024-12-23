use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use common::percent::percent_decode;
use http::uri::Uri;
use rustls::{internal::pemfile::*, *};
use std::convert::TryFrom;
use std::io::Error;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;
use webpki::DNSNameRef;

#[derive(Clone)]
pub struct CertAuth {
  pub certs: Vec<Certificate>,
  pub pk: PrivateKey,
}

pub(crate) fn uri_scheme(url: &str) -> MulTeeResult<String> {
  let uri = Uri::try_from(url).map_err(|e| MulTeeErrCode::CORRUPT_URI.msg(e))?;
  uri
    .scheme()
    .map(|f| f.to_string())
    .ok_or(MulTeeErrCode::CORRUPT_URI.msg("unable to get auth"))
}

pub(crate) fn uri_query(url: &str, what: &str) -> MulTeeResult<Option<String>> {
  let uri = Uri::try_from(url).map_err(|e| MulTeeErrCode::CORRUPT_URI.msg(e))?;
  match uri.query() {
    None => Ok(None),
    Some(q) => {
      let q: Vec<&str> = q.split("&").collect();
      if let Some(found) = q.iter().find(|s| s.starts_with(what)) {
        let url = found.replace(what, "");
        Ok(Some(url))
      } else {
        Err(MulTeeErrCode::CORRUPT_URI.msg("Missing TripleA query"))
      }
    }
  }
}

pub fn uri_passwd(url: &str) -> MulTeeResult<Option<(String, String)>> {
  let uri = url
    .parse::<Uri>()
    .map_err(|_| MulTeeErrCode::CORRUPT_URI.msg("Unable to parse URI"))?;

  let host = uri
    .host()
    .ok_or(MulTeeErrCode::CORRUPT_URI.msg("Unable to extract host from URI"))?;

  let authority = percent_decode(
    uri
      .authority()
      .ok_or(MulTeeErrCode::CORRUPT_URI.msg("Unable to extract authority from URI"))?
      .as_str(),
  )
  .map_err(|_| MulTeeErrCode::CORRUPT_UTF8.no_msg())?;

  let mut auth = String::from(host);
  auth.insert(0, '@');
  let passwd = match authority.as_str().find(auth.as_str()) {
    None => None,
    Some(l) => {
      let mut auth_iter = authority.as_str()[..l].split(':');
      let username = auth_iter
        .next()
        .ok_or(MulTeeErrCode::CORRUPT_URI.msg("Unable to extract username from URI"))?
        .to_string();
      let password = auth_iter
        .next()
        .ok_or(MulTeeErrCode::CORRUPT_URI.msg("Unable to extract password from URI"))?
        .to_string();
      Some((username, password))
    }
  };
  Ok(passwd)
}

pub fn connect(
  auth: Option<CertAuth>, ca: &str, url: &str, timeout: u64,
) -> MulTeeResult<(ClientSession, TcpStream)> {
  let default_port = match uri_scheme(url)?.as_str() {
    "kmip" | "remote" => 5696,
    "https" => 443,
    _ => return Err(MulTeeErrCode::CORRUPT_URI.msg("unsupported scheme")),
  };

  let uri = http::Uri::try_from(url).map_err(|e| MulTeeErrCode::CORRUPT_URI.msg(e))?;

  let port = uri.port_u16().unwrap_or(default_port);
  let host = uri
    .host()
    .ok_or(MulTeeErrCode::CORRUPT_URI.msg("unable to get host"))?;
  let host_ip = resolve_ip(host).map_err(|e| MulTeeErrCode::CORRUPT_URI.msg(e))?;

  let mut config = ClientConfig::new();

  if let Some(CertAuth { certs, pk }) = auth {
    config
      .set_single_client_cert(certs, pk)
      .map_err(|tls_err| {
        MulTeeErrCode::CREDENTIALS.msg(format!("Failed to set client certificate: {}", tls_err))
      })?;
  }

  let ca_certs = certs(&mut ca.as_bytes())
    .map_err(|_| MulTeeErrCode::CREDENTIALS.msg("Failed to extract CA certs"))?;

  if !ca_certs.is_empty() {
    for ca_cert in ca_certs {
      config
        .root_store
        .add(&ca_cert)
        .map_err(|_| MulTeeErrCode::CREDENTIALS.msg("Failed to add CA cert to root store"))?;
    }
  } else {
    config
      .dangerous()
      .set_certificate_verifier(Arc::new(DummyServerCertVerifier {}))
  }

  let timeout = Duration::new(timeout, 0);
  let ip_addr: IpAddr = host_ip
    .parse()
    .map_err(|_| MulTeeErrCode::CREDENTIALS.msg(format!("Error parsing IP address {}", host_ip)))?;
  let socket_addr: SocketAddr = SocketAddr::from((ip_addr, port));
  let dns_name: DNSNameRef = DNSNameRef::try_from_ascii_str(host).map_err(|e| {
    MulTeeErrCode::CREDENTIALS.msg(format!("Failed to resolve DNS name {} ({})", host, e))
  })?;

  let sess = ClientSession::new(&Arc::new(config), dns_name);
  let sock = TcpStream::connect_timeout(&socket_addr, timeout).map_err(|e| {
    format_rustls_io_err(
      e,
      MulTeeErrCode::RUSTLS_IO,
      "Failed to initialize TCP stream, possibly due to firewall",
    )
  })?;

  Ok((sess, sock))
}

pub fn client_cert(pk: &[u8], cert: &str) -> MulTeeResult<CertAuth> {
  let pk_buf = pk.to_vec();
  let mut pk = rsa_private_keys(&mut pk_buf.as_slice())
    .map_err(|_| MulTeeErrCode::CREDENTIALS.msg("Failed to extract RSA private key"))?;

  pk.append(
    &mut pkcs8_private_keys(&mut pk_buf.as_slice())
      .map_err(|_| MulTeeErrCode::CREDENTIALS.msg("Failed to extract PKCS8-encoded private key"))?,
  );
  if pk.is_empty() {
    return Err(MulTeeErrCode::CREDENTIALS.msg("Failed to extract private key"));
  } else if pk.len() > 1 {
    return Err(MulTeeErrCode::CREDENTIALS.msg("PEM file contains multiple private keys"));
  }
  let pk: PrivateKey = pk.remove(0);

  let certs = certs(&mut cert.as_bytes().to_vec().as_slice())
    .map_err(|_| MulTeeErrCode::CREDENTIALS.msg("Failed to extract client certificate"))?;
  if certs.is_empty() {
    return Err(MulTeeErrCode::CREDENTIALS.msg("Failed to extract client certificate"));
  }

  Ok(CertAuth { certs, pk })
}

struct DummyServerCertVerifier {}

impl ServerCertVerifier for DummyServerCertVerifier {
  fn verify_server_cert(
    &self, _roots: &RootCertStore, _presented_certs: &[Certificate], _dns_name: DNSNameRef<'_>,
    _ocsp_response: &[u8],
  ) -> Result<ServerCertVerified, TLSError> {
    Ok(ServerCertVerified::assertion())
  }
}

fn resolve_ip(host: &str) -> MulTeeResult<String> {
  let mut ips: Vec<IpAddr> = (host, 0)
    .to_socket_addrs()
    .map_err(|e| MulTeeErrCode::CREDENTIALS_IO.msg(format!("{}, {}", e, host)))?
    .map(|a| a.ip())
    .collect();
  Ok(ips.remove(0).to_string())
}

pub fn format_rustls_io_err(
  err: Error, tag: MulTeeErrCode, ctx_msg: &str,
) -> common::error::MulTeeError {
  tag.msg(format!(
    "{} ({}: {})",
    ctx_msg,
    err.kind().to_string(),
    err.to_string()
  ))
}
