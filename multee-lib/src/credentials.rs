use crate::util::cpu_info;
use crate::util::hostname;
use crate::util::microcode_version;
use crate::yaml::Put;
use common::api::MulTeeCore;
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use log::{info, warn};
use std::fs::{rename, File};
use std::io::{BufReader, Read, Seek, Write};
use std::vec::Vec;
use yaml_rust2::yaml::Hash;
use yaml_rust2::YamlLoader;
use zip::{ZipArchive, ZipWriter};

fn platform_yaml() -> MulTeeResult<Hash> {
  let ucode = microcode_version()?;
  let (cpuid, hyper_threading) = cpu_info();

  Ok(
    Hash::new()
      .put_str("cpuid", cpuid)
      .put_str("microcode", ucode)
      .put_str("hyperthreading", hyper_threading)
      .get(),
  )
}

pub(crate) fn multee_mk_csr_zip(
  multee: &dyn MulTeeCore, filename: &str, sn: &str, unpinned: bool,
) -> MulTeeResult<()> {
  let sn = sn.replace("CN=auto", format!("CN={}", hostname()).as_str());

  let zero_terminated =
    std::ffi::CString::new(sn).expect("impossible - can't have 0 inside the string");
  let subject_name = zero_terminated
    .to_str()
    .expect("impossible - all inputs are utf8");

  let (csr, pk) = multee.mk_csr(subject_name, true)?;

  let entry = if unpinned {
    "unpinned".to_string()
  } else {
    hostname()
  };

  let manifest_data = Hash::new()
    .put_str("hostname", hostname())
    .put_hash(
      "credentials",
      Hash::new()
        .put_hash(
          entry.as_str(),
          Hash::new()
            .put_str("csr", "csr.pem")
            .put_str("pk", "key.pem")
            .get(),
        )
        .get(),
    )
    .put_hash("platform", platform_yaml()?)
    .dump();

  let zip_data = &[
    ("csr.pem", csr.as_slice()),
    ("key.pem", pk.as_slice()),
    ("MANIFEST.YAML", manifest_data.as_bytes()),
  ];
  write_zip_file(filename, zip_data)
}

fn write_pinned_creds(filename: &str, ca: &[u8], cert: &[u8], pk: &[u8]) -> MulTeeResult<()> {
  let manifest_data = Hash::new()
    .put_str("CA", "ca.pem")
    .put_str("hostname", hostname())
    .put_hash(
      "credentials",
      Hash::new()
        .put_hash(
          hostname().as_str(),
          Hash::new()
            .put_str("cert", "cert.pem")
            .put_str("pk", "key.pem")
            .get(),
        )
        .get(),
    )
    .put_hash("platform", platform_yaml()?)
    .dump();

  let zip_data = &[
    ("ca.pem", ca),
    ("cert.pem", cert),
    ("key.pem", pk),
    ("MANIFEST.YAML", manifest_data.as_bytes()),
  ];
  write_zip_file(filename, zip_data)
}

fn write_zip_file(filename: &str, files: &[(&str, &[u8])]) -> MulTeeResult<()> {
  let file = File::create(&filename).expect("Unable to create file");
  let options =
    zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
  let mut z = ZipWriter::new(file);

  for (file_name, file_data) in files {
    z.start_file(*file_name, options)
      .map_err(|e| MulTeeErrCode::CREDENTIALS_PINNING.msg(e))?;
    z.write(*file_data)
      .and(z.flush())
      .map_err(|e| MulTeeErrCode::CREDENTIALS_PINNING.msg(e))?;
  }
  Ok(())
}

fn get_credentials_from_zip_entry(
  zip_file_name: &str, entry: &str,
) -> MulTeeResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
  let f = File::open(zip_file_name).map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;
  let file_reader = BufReader::new(&f);
  let archive = ZipArchive::new(file_reader);
  if archive.is_err() && std::env::var("container").is_ok() {
    warn!("Potential problem: MulTee when is run in unprivileged container on older OS, using credentials mounted from the host, requires that path to the credentials be readable by UID of nginx user in the container namespace");
  }
  let mut archive = archive.map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;
  read_credentials(&mut archive, entry)
}

pub(crate) fn get_credentials_from_zip(
  zip_file_name: &str,
) -> MulTeeResult<(Vec<u8>, Vec<u8>, Vec<u8>, bool)> {
  if let Ok((ca, cert, pinned_pk)) =
    get_credentials_from_zip_entry(zip_file_name, hostname().as_str())
  {
    Ok((ca, cert, pinned_pk, true))
  } else {
    get_credentials_from_zip_entry(zip_file_name, "unpinned")
      .map(|(ca, cert, pinned_pk)| (ca, cert, pinned_pk, false))
  }
}

pub(crate) fn pin_credentials(multee: &dyn MulTeeCore, zip_file_name: &str) -> MulTeeResult<()> {
  if let (ca, cert, pk, false) = get_credentials_from_zip("unpinned")? {
    info!("pinning credentials to hostname: {}", hostname());
    let sealed_pk = multee.seal_pk(pk.as_slice())?; // sealed
    let pinned_zip_file_name = format!("{}.pinned", zip_file_name);

    write_pinned_creds(
      pinned_zip_file_name.as_str(),
      ca.as_slice(),
      cert.as_slice(),
      sealed_pk.as_slice(),
    )?;
    rename(pinned_zip_file_name, zip_file_name).expect("Unable to rename credentials ZIP");
  }
  Ok(())
}

fn read_credentials<R: Read + Seek>(
  archive: &mut ZipArchive<R>, creds_key: &str,
) -> MulTeeResult<(Vec<u8>, Vec<u8>, Vec<u8>)> {
  let manifest_file = read_zip_file(archive, "MANIFEST.YAML")?;
  let manifest_str = String::from_utf8(manifest_file)?;
  let manifests = YamlLoader::load_from_str(manifest_str.as_str())
    .map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;
  let manifest = &manifests[0];
  if manifest.is_badvalue() {
    return Err(MulTeeErrCode::CORRUPT_YAML.no_msg());
  }

  let yaml = &manifest["credentials"][creds_key];
  if yaml.is_badvalue() {
    return Err(MulTeeErrCode::CREDENTIALS.msg("Missing machine_id/unpinned entry in YAML file"));
  }
  let ca_file = manifest["CA"]
    .as_str()
    .ok_or(MulTeeErrCode::CREDENTIALS.msg("Missing CA field in YAML file"))?;
  let cert_file = yaml["cert"]
    .as_str()
    .ok_or(MulTeeErrCode::CREDENTIALS.msg("Missing cert field in YAML file"))?;
  let pk_file = yaml["pk"]
    .as_str()
    .ok_or(MulTeeErrCode::CREDENTIALS.msg("Missing pk field in YAML file"))?;

  let ca = read_zip_file(archive, ca_file)?;
  let cert = read_zip_file(archive, cert_file)?;
  let pk = read_zip_file(archive, pk_file)?;
  Ok((ca, cert, pk))
}

pub(crate) fn read_zip_file<R: Read + Seek>(
  archive: &mut ZipArchive<R>, name: &str,
) -> MulTeeResult<Vec<u8>> {
  let mut entry = archive
    .by_name(name)
    .map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;
  let size = entry.size();

  let mut bytes: Vec<u8> = Vec::new();

  bytes.resize(size as usize, 0);
  entry
    .read(bytes.as_mut_slice())
    .map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;
  Ok(bytes)
}
