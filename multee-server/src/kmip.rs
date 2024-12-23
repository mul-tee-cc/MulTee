use anyhow::{Context, Error, Result};
use common::constants::{
  KMIP_RESPONSE_OVERHEAD_HINT, MULTEE_BLOCK_SIZE, MULTEE_GCM_IV_BYTES, MULTEE_GCM_TAG_BYTES,
};
use kmip::constants::Tag;
use kmip::enumerations::{CryptographicAlgorithm, CryptographicUsageMask, ObjectType, Operation};
use kmip::ttlv::Value::{ByteString, Enumeration, Integer, Structure, TextString};
use kmip::ttlv::{Ttlv, TtlvError};
use kmip::KmipOp;
use multee_lib::api::EnclaveSession;
use std::collections::HashMap;

#[inline]
fn uuid_to_index(uuid: &String) -> Option<usize> {
  uuid.parse::<usize>().ok()
}

fn pub_uuid_to_index(uuid: &String) -> Option<usize> {
  uuid
    .strip_suffix(".pub")
    .and_then(|s| s.parse::<usize>().ok())
}

pub(crate) fn process_msg(
  msg: &[u8], multee: &EnclaveSession, key_index_map: &HashMap<String, usize>,
) -> Result<Vec<u8>> {
  let mut buf = vec![0u8; msg.len() + KMIP_RESPONSE_OVERHEAD_HINT];

  let (ttlv_request, _) = Ttlv::unmarshal(&msg)?;
  let payload = kmip::request::parse(&ttlv_request);
  let payload = payload?;

  match payload {
    KmipOp::Locate(key_name) => {
      let key_index: usize = *key_index_map
        .get(key_name.as_str())
        .context("Unknown key")?;
      match multee.get_key_type(key_index)? {
        CryptographicAlgorithm::RSA | CryptographicAlgorithm::ECDSA => Ok(render_many(
          &mut buf,
          Operation::Locate,
          vec![
            Ttlv::new(
              Tag::UniqueIdentifier,
              TextString(key_index.to_string().as_str()),
            ),
            Ttlv::new(
              Tag::UniqueIdentifier,
              TextString(format!("{}.pub", key_index).as_str()),
            ),
          ],
        )?),
        _ => Ok(render_one(
          &mut buf,
          Operation::Locate,
          Ttlv::new(
            Tag::UniqueIdentifier,
            TextString(key_index.to_string().as_str()),
          ),
        )?),
      }
    }
    KmipOp::GetAttrs(key_uuid) => {
      let (key_index, algo, obj_type, usage_mask) =
        if let Some(key_index) = uuid_to_index(&key_uuid) {
          let algo = multee.get_key_type(key_index)?;
          let obj_type = match algo {
            CryptographicAlgorithm::RSA | CryptographicAlgorithm::ECDSA => ObjectType::PrivateKey,
            CryptographicAlgorithm::AES
            | CryptographicAlgorithm::SM4
            | CryptographicAlgorithm::HMAC_SHA256 => ObjectType::SymmetricKey,
          };
          let usage_mask = match algo {
            CryptographicAlgorithm::RSA => {
              CryptographicUsageMask::Sign as u32
                | CryptographicUsageMask::Verify as u32
                | CryptographicUsageMask::Encrypt as u32
                | CryptographicUsageMask::Decrypt as u32
            }
            CryptographicAlgorithm::ECDSA => {
              CryptographicUsageMask::Sign as u32 | CryptographicUsageMask::Verify as u32
            }
            CryptographicAlgorithm::HMAC_SHA256 => CryptographicUsageMask::MACGenerate as u32,
            CryptographicAlgorithm::AES | CryptographicAlgorithm::SM4 => {
              CryptographicUsageMask::Encrypt as u32 | CryptographicUsageMask::Decrypt as u32
            }
          };
          (key_index, algo, obj_type, usage_mask)
        } else if let Some(key_index) = pub_uuid_to_index(&key_uuid) {
          let algo = multee.get_key_type(key_index)?;
          let obj_type = match algo {
            CryptographicAlgorithm::RSA | CryptographicAlgorithm::ECDSA => ObjectType::PublicKey,
            _ => return Err(Error::msg("Impossible")),
          };
          let usage_mask = match algo {
            CryptographicAlgorithm::RSA => {
              CryptographicUsageMask::Verify as u32 | CryptographicUsageMask::Encrypt as u32
            }
            CryptographicAlgorithm::ECDSA => CryptographicUsageMask::Verify as u32,
            _ => return Err(Error::msg("Impossible")),
          };
          (key_index, algo, obj_type, usage_mask)
        } else {
          return Err(Error::msg("Unknown UUID"));
        };

      Ok(render_many(
        &mut buf,
        Operation::GetAttributes,
        vec![
          Ttlv::new(
            Tag::Attribute,
            Structure(vec![
              Ttlv::new(Tag::AttributeName, TextString("Cryptographic Algorithm")),
              Ttlv::new(Tag::AttributeValue, Enumeration(algo as u32)),
            ]),
          ),
          Ttlv::new(
            Tag::Attribute,
            Structure(vec![
              Ttlv::new(Tag::AttributeName, TextString("Cryptographic Length")),
              Ttlv::new(
                Tag::AttributeValue,
                Integer(multee.key_len(key_index)? as i32),
              ),
            ]),
          ),
          Ttlv::new(
            Tag::Attribute,
            Structure(vec![
              Ttlv::new(Tag::AttributeName, TextString("Cryptographic Usage Mask")),
              Ttlv::new(Tag::AttributeValue, Integer(usage_mask as i32)),
            ]),
          ),
          Ttlv::new(
            Tag::Attribute,
            Structure(vec![
              Ttlv::new(Tag::AttributeName, TextString("Object Type")),
              Ttlv::new(Tag::AttributeValue, Enumeration(obj_type as u32)),
            ]),
          ),
        ],
      )?)
    }
    KmipOp::Get(key_uuid) => {
      let key_index = pub_uuid_to_index(&key_uuid).context("Unknown UUID")?;
      match multee.get_key_type(key_index)? {
        CryptographicAlgorithm::RSA | CryptographicAlgorithm::ECDSA => {
          let key_material = multee.get_public_key(key_index)?;
          Ok(render_many(
            &mut buf,
            Operation::Get,
            vec![
              Ttlv::new(Tag::UniqueIdentifier, TextString(key_uuid.as_str())),
              Ttlv::new(Tag::ObjectType, Enumeration(ObjectType::PublicKey as u32)),
              Ttlv::new(
                Tag::PublicKey,
                Structure(vec![Ttlv::new(
                  Tag::KeyBlock,
                  Structure(vec![Ttlv::new(
                    Tag::KeyValue,
                    Structure(vec![Ttlv::new(
                      Tag::KeyMaterial,
                      ByteString(key_material.as_slice()),
                    )]),
                  )]),
                )]),
              ),
            ],
          )?)
        }
        _ => todo!("Handle"),
      }
    }
    KmipOp::MAC(key_uuid, algo, data) => {
      if algo != CryptographicAlgorithm::HMAC_SHA256 {
        todo!("")
      }
      let key_index = uuid_to_index(&key_uuid).context("Unknown UUID")?;
      match multee.get_key_type(key_index)? {
        CryptographicAlgorithm::AES => {
          let mac = multee.hmac_sha256(key_index, data.as_slice())?;
          Ok(render_many(
            &mut buf,
            Operation::Mac,
            vec![
              Ttlv::new(Tag::UniqueIdentifier, TextString(key_uuid.as_str())),
              Ttlv::new(Tag::MacData, ByteString(mac.as_slice())),
            ],
          )?)
        }
        _ => {
          todo!("Handle")
        }
      }
    }
    KmipOp::Sign(key_uuid, padding, md_type, hash) => {
      let key_index = uuid_to_index(&key_uuid).context("Unknown UUID")?;
      match multee.get_key_type(key_index)? {
        CryptographicAlgorithm::RSA | CryptographicAlgorithm::ECDSA => {
          let signature = multee.sign_hash(key_index, padding, md_type, hash.as_slice())?;
          Ok(render_many(
            &mut buf,
            Operation::Sign,
            vec![
              Ttlv::new(Tag::UniqueIdentifier, TextString(key_uuid.as_str())),
              Ttlv::new(Tag::SignatureData, ByteString(signature.as_slice())),
            ],
          )?)
        }
        _ => Err(Error::msg("Unsupported algorithm")),
      }
    }
    KmipOp::EncryptGCM(key_uuid, algo, data, aad_opt, (iv_len, tag_len)) => {
      let key_index = uuid_to_index(&key_uuid).context("Unknown UUID")?;

      match multee.get_key_type(key_index)? {
        a @ (CryptographicAlgorithm::AES | CryptographicAlgorithm::SM4) if a == algo => {
          if iv_len != MULTEE_GCM_IV_BYTES || tag_len != MULTEE_GCM_TAG_BYTES {
            Err(Error::msg("Unsupported GCM parameters iv_len or tag_len"))
          } else {
            let (data, iv, tag) = multee.encrypt_gcm(
              key_index,
              aad_opt.as_ref().map(Vec::as_slice),
              data.as_slice(),
            )?;

            Ok(render_many(
              &mut buf,
              Operation::Encrypt,
              vec![
                Ttlv::new(Tag::UniqueIdentifier, TextString(key_uuid.as_str())),
                Ttlv::new(Tag::Data, ByteString(data.as_slice())),
                Ttlv::new(Tag::IvCounterNonce, ByteString(iv.as_slice())),
                Ttlv::new(Tag::AuthenticatedEncryptionTag, ByteString(tag.as_slice())),
              ],
            )?)
          }
        }
        _ => Err(Error::msg("Unsupported algorithm")),
      }
    }
    KmipOp::EncryptCBC(key_uuid, algo, mut data, iv_opt) => {
      let key_index = uuid_to_index(&key_uuid).context("Unknown UUID")?;

      match multee.get_key_type(key_index)? {
        a @ (CryptographicAlgorithm::AES | CryptographicAlgorithm::SM4) if a == algo => {
          let explicit_iv = iv_opt.is_some();
          let mut iv = if let Some(iv_) = iv_opt {
            iv_
          } else {
            vec![0; MULTEE_BLOCK_SIZE]
          };
          let data_len = data.len();
          data.resize(data_len + MULTEE_BLOCK_SIZE, 0);

          let size = multee.encrypt_cbc(
            key_index,
            explicit_iv,
            iv.as_mut_slice(),
            data.as_mut_slice(),
            data_len,
          )?;

          Ok(render_many(
            &mut buf,
            Operation::Encrypt,
            vec![
              Ttlv::new(Tag::UniqueIdentifier, TextString(key_uuid.as_str())),
              Ttlv::new(Tag::Data, ByteString(&data.as_slice()[..size])),
              Ttlv::new(Tag::IvCounterNonce, ByteString(iv.as_slice())),
            ],
          )?)
        }
        _ => Err(Error::msg("Unsupported algorithm")),
      }
    }
    KmipOp::DecryptGCM(key_uuid, algo, data, aad_opt, iv, tag) => {
      let key_index = uuid_to_index(&key_uuid).context("Unknown UUID")?;

      match multee.get_key_type(key_index)? {
        a @ (CryptographicAlgorithm::AES | CryptographicAlgorithm::SM4) if a == algo => {
          let data = multee.decrypt_gcm(
            key_index,
            aad_opt.as_ref().map(Vec::as_slice),
            data.as_slice(),
            iv.as_slice(),
            tag.as_slice(),
          )?;

          Ok(render_many(
            &mut buf,
            Operation::Encrypt,
            vec![
              Ttlv::new(Tag::UniqueIdentifier, TextString(key_uuid.as_str())),
              Ttlv::new(Tag::Data, ByteString(data.as_slice())),
            ],
          )?)
        }
        _ => Err(Error::msg("Unsupported algorithm")),
      }
    }
    KmipOp::DecryptCBC(key_uuid, algo, mut data, mut iv) => {
      let key_index = uuid_to_index(&key_uuid).context("Unknown UUID")?;
      match multee.get_key_type(key_index)? {
        a @ (CryptographicAlgorithm::AES | CryptographicAlgorithm::SM4) if a == algo => {
          let data_len = data.len();
          let size = multee.decrypt_cbc(
            key_index,
            true,
            iv.as_mut_slice(),
            data.as_mut_slice(),
            data_len,
          )?;

          Ok(render_many(
            &mut buf,
            Operation::Encrypt,
            vec![
              Ttlv::new(Tag::UniqueIdentifier, TextString(key_uuid.as_str())),
              Ttlv::new(Tag::Data, ByteString(&data.as_slice()[..size])),
            ],
          )?)
        }
        _ => Err(Error::msg("Unsupported algorithm")),
      }
    }
  }
}

fn render_many(buf: &mut Vec<u8>, op: Operation, msg: Vec<Ttlv>) -> Result<Vec<u8>> {
  let timestamp = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("Impossible")
    .as_secs() as i64;

  let response = kmip::response::from_vec(timestamp, op, msg);

  render_buf(buf, response)
}

fn render_one(buf: &mut Vec<u8>, op: Operation, msg: Ttlv) -> Result<Vec<u8>> {
  let timestamp = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .expect("Impossible")
    .as_secs() as i64;

  let response = kmip::response::from(timestamp, op, msg);

  render_buf(buf, response)
}

fn render_buf(buf: &mut Vec<u8>, response: Ttlv) -> Result<Vec<u8>> {
  match response.marshal(buf.as_mut()) {
    Ok(size) => Ok(buf[..size].to_vec()),
    Err(TtlvError::CorruptBufferSize) if buf.len() != crate::srv::MAX_MESSAGE_SIZE_BYTES => {
      buf.resize(crate::srv::MAX_MESSAGE_SIZE_BYTES, 0);
      let len = response.marshal(buf.as_mut())?;
      Ok(buf[..len].to_vec())
    }
    Err(e) => Err(e.into()),
  }
}

// use combine::parser::
