use crate::DLL;
use common::constants::MULTEE_BLOCK_SIZE;
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use log::debug;
use raw_cpuid::CpuId;
use std::env;
use std::ffi::OsString;
use std::fs::{create_dir_all, File};
use std::io::{BufRead, BufReader, Result, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub(crate) fn hostname() -> String {
  gethostname::gethostname()
    .into_string()
    .unwrap_or("no-hn".to_string())
}

#[inline]
pub(crate) fn pkcs5_pad(buf: &mut [u8], input_len: usize) -> usize {
  let pad_bytes = MULTEE_BLOCK_SIZE - (input_len % MULTEE_BLOCK_SIZE);
  for i in 0..pad_bytes {
    buf[input_len + i] = pad_bytes as u8;
  }
  input_len + pad_bytes
}

pub(crate) fn microcode_version() -> MulTeeResult<String> {
  let f = File::open("/proc/cpuinfo")
    .map_err(|_| MulTeeErrCode::MACHINE_INFO_NOT_FOUND.msg("Unable to open /proc/cpuinfo"))?;
  let file = BufReader::new(&f);
  for line in file.lines() {
    let line = line
      .map_err(|_| MulTeeErrCode::MACHINE_INFO_NOT_FOUND.msg("Unable to read /proc/cpuinfo"))?;

    if line.contains("microcode") {
      let mut split = line.split(':');
      split.next();
      let ver = split
        .next()
        .expect("impossible: Has /proc/cpuinfo output format changed?")
        .trim();

      return Ok(ver.trim_start_matches("0x").to_owned());
    };
  }
  Err(MulTeeErrCode::MACHINE_INFO_NOT_FOUND.msg("No microcode in /proc/cpuinfo"))
}

pub(crate) fn cpu_info() -> (u32, u32) {
  // www.lpjjl.net/pgm/fichiers/intelcountingprocessors.htm

  let cpuinfo = unsafe { core::arch::x86_64::__cpuid(4) };
  let physical_cores = ((cpuinfo.eax >> 26) & 63) + 1;
  let cpuinfo = unsafe { core::arch::x86_64::__cpuid(1) };
  let logical_processors = (cpuinfo.ebx >> 16) & 255;
  let cpuid = cpuinfo.eax & ((1 << 20) - 1);
  let hyper_threading = if physical_cores != logical_processors {
    1
  } else {
    0
  };

  (cpuid, hyper_threading)
}

pub(crate) fn delete_tmp_dir(file_path: PathBuf) -> Result<()> {
  std::fs::remove_dir_all(file_path.as_path())
}

#[cfg(not(feature = "with-dcap"))]
pub(crate) fn extract_files() -> Result<(PathBuf, String)> {
  unreachable!()
}
#[cfg(feature = "with-dcap")]
pub(crate) fn extract_files() -> Result<(PathBuf, String)> {
  let sim: bool = want_sim();

  let rndir = SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .expect("impossible")
    .as_micros()
    .to_string();

  let tmp_dir = env::var("MULTEE_TMPDIR")
    .map(PathBuf::from)
    .ok()
    .unwrap_or(std::env::temp_dir());
  let extract_dir: PathBuf = tmp_dir.join(format!("multee-{}-{}", std::process::id(), rndir));
  let _ = create_dir_all(extract_dir.as_path())?;

  if sim && cfg!(feature = "with-dcap") {
    debug!("Extracting SGX SIM libraries");
    let _file = extract_file(
      crate::dcap_test_blobs::URTS_SIM,
      extract_dir.join("libsgx_urts.so"),
    )?;
    let _file = extract_file(
      crate::dcap_test_blobs::UAE_SIM,
      extract_dir.join("libsgx_uae_service_sim.so"),
    )?;
    let _file = extract_file(
      crate::dcap_test_blobs::PCE_LOGIC,
      extract_dir.join("libsgx_pce_logic.so.1"),
    )?;
    let _file = extract_file(
      crate::dcap_test_blobs::QE3_LOGIC,
      extract_dir.join("libsgx_qe3_logic.so"),
    )?;
    let _file = extract_file(
      crate::dcap_test_blobs::DCAP_QL,
      extract_dir.join("libsgx_dcap_ql.so.1"),
    )?;
  }
  debug!("Extracting SGX untrusted module");
  let file = extract_file(DLL, extract_dir.join("multee.so"))?;

  Ok((extract_dir, file))
}

fn extract_file(enclave_bytes: &[u8], file_path: PathBuf) -> Result<String> {
  // info!("extracted enclave path: {}", enclave_path.display());

  let mut enclave_file = File::create(file_path.as_path())?;
  enclave_file.write_all(enclave_bytes)?;
  let os_str: OsString = file_path.into_os_string();
  let strr: String = os_str.into_string().expect("Impossible");

  debug!("A {}", strr.as_str());
  Ok(strr)
}

pub(crate) fn is_intel() -> bool {
  let cpuid = CpuId::new();
  match cpuid.get_vendor_info() {
    None => false,
    Some(v) => v.as_str() == "GenuineIntel",
  }
}

pub(crate) fn want_sim() -> bool {
  !Path::new("/var/run/aesmd/aesm.socket").exists() || env::var("MULTEE_FORCE_SIM").is_ok()
}

pub(crate) fn has_sev() -> bool {
  Path::new("/dev/sev-guest").exists()
}

pub(crate) fn has_tdx() -> bool {
  Path::new("/dev/tdx-guest").exists()
}
