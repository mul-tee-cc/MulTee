use std::fs::{create_dir_all, File};
use std::io::{Result, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use log::info;
use raw_cpuid::CpuId;

pub(crate) fn extract_enclave(enclave_bytes: &[u8]) -> Result<(PathBuf, PathBuf)> {
  let rndir = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .expect("impossible")
    .as_micros()
    .to_string();
  let tmp_dir = std::env::var("MULTEE_TMPDIR")
    .map(PathBuf::from)
    .ok()
    .unwrap_or(std::env::temp_dir());
  let extract_dir: PathBuf = tmp_dir.join(format!("multee-{}-{}", std::process::id(), rndir));
  let _ = create_dir_all(extract_dir.as_path());
  let enclave_path = extract_dir.join("enclave.so.signed");

  info!("extracted enclave path: {}", enclave_path.display());

  let mut enclave_file = File::create(enclave_path.as_path())?;
  enclave_file.write_all(enclave_bytes)?;
  Ok((extract_dir, enclave_path))
}

pub(crate) fn is_hw_sgx() -> bool {
  let cpu_info = CpuId::new();

  let has_sgx = matches!(
    cpu_info
      .get_sgx_info()
      .map(|sgx_info| sgx_info.has_sgx1() || sgx_info.has_sgx2()),
    Some(true),
  );

  let aesm_socket_exists = Path::new("/var/run/aesmd/aesm.socket").exists();

  aesm_socket_exists && has_sgx
}

// pub(crate) fn to_err(err: sgx_types::error::SgxStatus) -> Error {
//   Error {tag: ErrorTag::SGX_ECALL, sub: err as i32, message: Some( format!( "{}{{{}}} - {}", err.as_str(), err, err.__description() ))}
// }
// fn to_err(code: common::error::MulTeeErrCode, err: sgx_types::error::SgxStatus) -> common::error::MulTeeError {
//   code.nested(err as i32,format!( "{}{{{}}} - {}", err.as_str(), err, err.__description() ))
// }
