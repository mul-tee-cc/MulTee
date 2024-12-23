use std::{fs::File, io::BufReader, vec::Vec};

use common::error::MulTeeErrCode;
use common::error::MulTeeResult;

use log::warn;
use yaml_rust2::YamlLoader;
use zip::ZipArchive;

use common::api::KeyData;
use multee_core::api::key_meta_new;

use crate::credentials::read_zip_file;

pub(crate) fn read_literal(
  zip_file_name: &str, creds_key: &str, key_names: Vec<String>,
) -> MulTeeResult<Vec<KeyData>> {
  let f = File::open(zip_file_name).map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;
  let file_reader = BufReader::new(&f);
  let archive = ZipArchive::new(file_reader);
  if archive.is_err() && std::env::var("container").is_ok() {
    warn!("Potential problem: MulTee when is run in (1) unprivileged container, using (2) podman 3.x series, on (3) 4.x series Linux kernel, using (4) credentials mounted from the host, requires that path to the credentials be readable by UID of nginx user in the container namespace");
  }
  let archive = &mut archive.map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;

  let manifest_file = read_zip_file(archive, "MANIFEST.YAML")?;
  let manifest_str = String::from_utf8(manifest_file)?;
  let manifests = YamlLoader::load_from_str(manifest_str.as_str())
    .map_err(|e| MulTeeErrCode::CREDENTIALS.msg(e))?;
  let manifest = &manifests[0];
  if manifest.is_badvalue() {
    return Err(MulTeeErrCode::CORRUPT_YAML.no_msg());
  }

  let yaml = &manifest["literals"][creds_key];
  if yaml.is_badvalue() {
    return Err(
      MulTeeErrCode::CREDENTIALS
        .msg("Missing machine_id/unpinned entry in YAML file")
        .into(),
    );
  }

  let keys_yaml = yaml
    .as_vec()
    .ok_or(MulTeeErrCode::CREDENTIALS.msg("Malformed key literal in YAML file"))?;

  let mut kmap = std::collections::HashMap::new();

  for k in keys_yaml.iter() {
    let name = k["name"]
      .as_str()
      .ok_or(MulTeeErrCode::CREDENTIALS.msg("Malformed key literal in YAML file (name)"))?
      .to_string();

    if key_names.contains(&name) {
      let key_material_file = k["key_material_file"].as_str().ok_or(
        MulTeeErrCode::CREDENTIALS.msg("Malformed key literal in YAML file (key_material_file)"),
      )?;
      let key_material = read_zip_file(archive, key_material_file)?;

      let km = key_meta_new(
        name.as_str(),
        key_material.as_slice(),
        k["key_type"]
          .as_i64()
          .ok_or(MulTeeErrCode::CREDENTIALS.msg("Malformed key literal in YAML file (key_type)"))?
          as u32,
        k["object_type"].as_i64().ok_or(
          MulTeeErrCode::CREDENTIALS.msg("Malformed key literal in YAML file (object_type)"),
        )? as u32,
        k["usage_mask"].as_i64().ok_or(
          MulTeeErrCode::CREDENTIALS.msg("Malformed key literal in YAML file (usage_mask)"),
        )? as u32,
        k["key_length"].as_i64().ok_or(
          MulTeeErrCode::CREDENTIALS.msg("Malformed key literal in YAML file (key_length)"),
        )? as usize,
      )?;

      kmap.insert(name, km);
    }
  }
  // Preserving key order
  let mut keys: Vec<KeyData> = Vec::new();

  for k in key_names.iter() {
    let kk = kmap.remove(k).expect("impossible");
    keys.push(kk);
  }

  Ok(keys)
}
