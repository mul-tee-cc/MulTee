use crate::constants::Tag;
use core::convert::Into;
use core::slice::Iter;
use core::str::from_utf8;

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;
use num_traits::ToPrimitive;
use scroll::{Cread, Cwrite, BE};

use crate::util::padded_len;
use crate::util::TryFromValue;
use core::fmt::Display;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct Ttlv<'a> {
  pub tag: Tag,
  pub value: Value<'a>,
}
#[derive(Debug, Clone, FromPrimitive, ToPrimitive)]
#[repr(u8)]
enum Type {
  Structure = 0x01,
  Integer,
  LongInteger,
  BigInteger,
  Enumeration,
  Boolean,
  TextString,
  ByteString,
  DateTime,
  Interval,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
  Structure(Vec<Ttlv<'a>>),
  Integer(i32),
  LongInteger(i64),
  BigInteger(&'a [u8]), // Not fully supported
  Enumeration(u32),
  Boolean(bool),
  TextString(&'a str),
  ByteString(&'a [u8]),
  DateTime(i64), // POSIX Time, as described in IEEE Standard 1003.1 [FIPS202]
  Interval(u32),
}

const START_BYTE: u8 = 0x42;

/// TTLV-related erorrs. can be used for more targeted error-handling.
#[derive(Debug)]
pub enum TtlvError {
  UnimplementedType,
  UnimplementedTag,
  TypeMismatch,
  PathNotFound,
  CorruptStruct,
  StructEmpty,
  CorruptStartByte,
  CorruptBufferSize,
  CorruptUtf8,
}

impl Display for TtlvError {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}
impl std::error::Error for TtlvError {}

impl<'a> Ttlv<'a> {
  pub fn new(tag: Tag, value: Value<'a>) -> Self {
    Ttlv {
      tag: tag.into(),
      value,
    }
  }
  pub fn tag(&self) -> Tag {
    self.tag
  }
  pub fn unbox<T: TryFromValue<'a>>(&'a self) -> Result<T, TtlvError> {
    T::try_from(&self.value).ok_or(TtlvError::TypeMismatch)
  }
  pub fn child_iter(&self) -> Result<Iter<Ttlv>, TtlvError> {
    if let Value::Structure(val) = &self.value {
      Ok(val.iter())
    } else {
      Err(TtlvError::TypeMismatch)
    }
  }
  pub fn path(&self, tags: &[Tag]) -> Result<&Ttlv, TtlvError> {
    self
      .child_iter()?
      .find(|c| {
        let child_tag = c.tag();
        child_tag == tags[0]
      })
      .ok_or(TtlvError::PathNotFound)
      .and_then(|c| {
        if tags.len() == 1 {
          Ok(c)
        } else {
          c.path(&tags[1..])
        }
      })
  }

  pub fn paths(&self, tags: &[Tag]) -> Result<Vec<&Ttlv>, TtlvError> {
    let mut it = self.child_iter()?;
    if tags.len() == 1 {
      let r: Vec<&Ttlv> = it
        .filter(|c| {
          let child_tag = c.tag();
          child_tag == tags[0]
        })
        .collect();
      if r.len() == 0 {
        Err(TtlvError::PathNotFound)
      } else {
        Ok(r)
      }
    } else {
      it.find(|c| {
        let child_tag = c.tag();
        child_tag == tags[0]
      })
      .ok_or(TtlvError::PathNotFound)
      .and_then(|c| c.paths(&tags[1..]))
    }
  }

  pub fn marshal(&self, buf: &mut [u8]) -> Result<usize, TtlvError> {
    if buf.len() < 16 {
      return Err(TtlvError::CorruptBufferSize);
    }
    buf.cwrite_with::<u8>(START_BYTE.to_u8().expect("Impossible"), 0, BE);
    buf.cwrite_with::<u16>(self.tag as u16, 1, BE);
    let (type_, len) = match &self.value {
      Value::Structure(children) => {
        let mut cursor = 8;
        for c in children {
          cursor += c.marshal(&mut buf[cursor..])?;
        }
        (Type::Structure, cursor - 8)
      }
      Value::Integer(val) => {
        buf.cwrite_with::<i32>(*val, 8, BE);
        buf.cwrite_with::<u32>(0, 12, BE);
        (Type::Integer, 4)
      }
      Value::LongInteger(val) => {
        buf.cwrite_with::<i64>(*val, 8, BE);
        (Type::LongInteger, 8)
      }
      // Big Integers are padded with leading sign-extended bytes (which are included in the length).
      Value::BigInteger(_) => return Err(TtlvError::UnimplementedType),
      Value::Enumeration(val) => {
        buf.cwrite_with::<u32>(*val, 8, BE);
        buf.cwrite_with::<u32>(0, 12, BE);
        (Type::Enumeration, 4)
      }
      Value::Boolean(val) => {
        buf.cwrite_with::<u64>(if *val { 1 } else { 0 }, 8, BE);
        (Type::Boolean, 8)
      }
      Value::DateTime(val) => {
        buf.cwrite_with::<i64>(*val, 8, BE);
        (Type::DateTime, 8)
      }
      Value::Interval(val) => {
        buf.cwrite_with::<u32>(*val, 8, BE);
        buf.cwrite_with::<u32>(0, 12, BE);
        (Type::Interval, 4)
      }
      Value::TextString(val) => {
        write_bin_string(buf, val)?;
        (Type::TextString, val.len())
      }
      Value::ByteString(val) => {
        write_bin_string(buf, val)?;
        (Type::ByteString, val.len())
      }
    };
    buf.cwrite_with::<u8>(type_ as u8, 3, BE);
    buf.cwrite_with::<u32>(len as u32, 4, BE);
    Ok(8 + padded_len(len))
  }
  pub fn unmarshal(buf: &'a [u8]) -> Result<(Self, usize), TtlvError> {
    if buf.len() < 8 {
      if buf.len() == 0 {
        return Err(TtlvError::StructEmpty);
      } else {
        return Err(TtlvError::CorruptBufferSize);
      }
    }
    if buf.cread_with::<u8>(0, BE) != START_BYTE {
      return Err(TtlvError::CorruptStartByte);
    }

    let tag_u16 = buf.cread_with::<u16>(1, BE);
    let tag = Tag::from_u16(tag_u16).ok_or(TtlvError::UnimplementedTag)?;
    let type_ = Type::from_u8(buf.cread_with::<u8>(3, BE)).ok_or(TtlvError::UnimplementedType)?;
    let len = buf.cread_with::<u32>(4, BE) as usize;
    let padded_len = padded_len(len);
    if buf.len() < 8 + padded_len {
      return Err(TtlvError::CorruptBufferSize);
    }

    let value = match type_ {
      Type::Structure => {
        let mut cursor = 8;
        let mut children = Vec::new();
        loop {
          match Ttlv::unmarshal(&buf[cursor..8 + len]) {
            Ok((c, c_len)) => {
              cursor += c_len;
              children.push(c);
            }
            Err(TtlvError::StructEmpty) => break,
            e => return e,
          }
        }
        Value::Structure(children)
      }
      Type::Integer => Value::Integer(buf.cread_with::<i32>(8, BE)),
      Type::LongInteger => Value::LongInteger(buf.cread_with::<i64>(8, BE)),
      Type::BigInteger => Value::BigInteger(&buf[8..8 + len]),
      Type::Enumeration => Value::Enumeration(buf.cread_with::<u32>(8, BE)),
      Type::Boolean => Value::Boolean(buf.cread_with::<u64>(8, BE) != 0),
      Type::TextString => Value::TextString(from_utf8(&buf[8..8 + len])?),
      Type::ByteString => Value::ByteString(&buf[8..8 + len]),
      Type::DateTime => Value::DateTime(buf.cread_with::<i64>(8, BE)),
      Type::Interval => Value::Interval(buf.cread_with::<u32>(8, BE)),
    };
    Ok((Ttlv::new(tag, value), 8 + padded_len))
  }
}

fn write_bin_string<T: AsRef<[u8]>>(buf: &mut [u8], data: T) -> Result<(), TtlvError> {
  let offset: usize = 8;

  let data_len = data.as_ref().len();
  let padded_len = padded_len(data_len);

  if buf.len() < offset + padded_len {
    return Err(TtlvError::CorruptBufferSize);
  }

  let buf = &mut buf[offset..];

  buf[..data_len].copy_from_slice(data.as_ref());
  for pad in &mut buf[data_len..padded_len] {
    *pad = 0;
  }
  Ok(())
}

pub fn parse_ttlv_len(buf: &[u8]) -> usize {
  assert_eq!(4, buf.len());
  let len = buf.cread_with::<i32>(0, BE);
  padded_len(len as usize)
}
