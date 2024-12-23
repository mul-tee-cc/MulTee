use std::fmt::Display;
use std::io::{Read, Write};
use std::string::{String, ToString};
use std::vec::Vec;

use common::error::MulTeeErrCode;
use common::error::MulTeeResult;

use http::{Request, Response};

use crate::tls::format_rustls_io_err;

static USERAGENT: &str =
  const_format::formatcp!("User-Agent: multee/{}", env!("CARGO_PKG_VERSION"));

const TRIPLE_A_BUFFER_SIZE: usize = 32768;

pub(crate) fn do_get<I: Read + Write>(
  tls: &mut I, prefix: &str, path: &str, body: &str,
) -> MulTeeResult<Response<String>> {
  let buf = &mut [0u8; TRIPLE_A_BUFFER_SIZE];

  let request = Request::get(format!("{}{}", prefix, path))
    .body(body.to_string())
    .map_err(|_| {
      MulTeeErrCode::UNEXPECTED_OR_IMPOSSIBLE.msg("Impossible: unable to construct HTTP request")
    })?;

  let body_len = body.len().to_string();
  send(
    tls,
    buf,
    request,
    &[
      ("Content-Type", "application/json;charset=UTF-8"),
      ("Content-Length", body_len.as_str()),
    ],
  )
}

pub(crate) fn do_post<I: Read + Write>(
  tls: &mut I, prefix: &str, path: &str, body: &str,
) -> MulTeeResult<Response<String>> {
  let buf = &mut [0u8; TRIPLE_A_BUFFER_SIZE];

  let request = Request::post(format!("{}{}", prefix, path))
    .body(body.to_string())
    .map_err(|_| {
      MulTeeErrCode::UNEXPECTED_OR_IMPOSSIBLE.msg("Impossible: unable to construct HTTP request")
    })?;

  let body_len = body.len().to_string();
  send(
    tls,
    buf,
    request,
    &[
      ("Content-Type", "application/json;charset=UTF-8"),
      ("Content-Length", body_len.as_str()),
    ],
  )
}

pub(crate) fn send<T: Read + Write, D: Display>(
  tls: &mut T, buf: &mut [u8], request: Request<D>, req_headers: &[(&str, &str)],
) -> MulTeeResult<Response<String>> {
  let uri = request.uri();
  println!("HTTP: {:x?}", uri);

  let mut headers: Vec<String> = Vec::new();
  headers.push("Accept: */*".to_string());
  headers.push(USERAGENT.to_string());
  for (key, val) in req_headers {
    headers.push(format!("{}: {}", key, val));
  }

  let host = uri
    .host()
    .ok_or(MulTeeErrCode::UNEXPECTED_OR_IMPOSSIBLE.msg("Uri without host"))?;

  let chars = format!(
    "{} {} HTTP/1.1\r\nHost: {}:{}\r\n{}\r\n\r\n{}",
    request.method().as_str(),
    uri.path(),
    host,
    uri.port_u16().unwrap_or(443),
    headers.join("\r\n"),
    request.body(),
  );

  attempt_send(tls, buf, chars.as_bytes())
}

fn attempt_send<T: Read + Write>(
  tls: &mut T, buf: &mut [u8], req: &[u8],
) -> MulTeeResult<Response<String>> {
  let resp_len = send_recieve_tls(tls, buf, req)?;
  let resp = core::str::from_utf8(&buf[..resp_len])?;
  let resp: Vec<&str> = resp.split_terminator("\r\n").collect();
  parse_response(resp.as_slice()).map_err(|err| err)
}

fn parse_response(resp: &[&str]) -> MulTeeResult<Response<String>> {
  let resp: Vec<&[&str]> = resp.split(|s| (*s).is_empty()).collect();
  http_err_check(resp.len() >= 2)?;

  let rb = Response::builder();

  // parse response header
  let header = resp[0];
  http_err_check(header.len() > 2)?;
  http_err_check(header[0].starts_with("HTTP/"))?;
  let code: Vec<&str> = header[0].split_terminator(' ').collect();
  http_err_check(code[1].parse::<u16>().is_ok())?;
  let response = rb.status(code[1]);

  // parse response body
  let body = resp[1];
  let body = if body.len() == 1 {
    body[0].to_string()
  } else {
    collect_chunked_body(body)
  };

  response.body(body).map_err(|_| {
    MulTeeErrCode::HTTP_MALFORMATTED_RESPONSE.msg("Unexpected: unable to parse request body")
  })
}

// TODO: handling of transfer-encoding: chunked?
fn collect_chunked_body(body: &[&str]) -> String {
  let mut collected_body = String::new();

  for i in (1..body.len()).step_by(2) {
    collected_body.push_str(body[i]);
  }

  collected_body
}

fn http_err_check(assertion: bool) -> MulTeeResult<()> {
  if assertion {
    Ok(())
  } else {
    Err(MulTeeErrCode::HTTP_MALFORMATTED_RESPONSE.into())
  }
}

fn send_recieve_tls<T: Read + Write>(
  tls: &mut T, buf: &mut [u8], req: &[u8],
) -> MulTeeResult<usize> {
  tls
    .flush()
    .and_then(|_| tls.write_all(req))
    .and_then(|_| tls.read(buf))
    .map_err(|e| {
      format_rustls_io_err(
        e,
        MulTeeErrCode::RUSTLS_IO,
        format!("IO error in {} session", "AA").as_str(),
      )
    })
}
