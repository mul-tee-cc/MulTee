// use alloc::string::FromUtf8Error;
// use alloc::string::String;
use core::slice;
use std::string::FromUtf8Error;
use std::vec::Vec;

pub fn percent_decode<T: AsRef<[u8]>>(input: T) -> Result<String, FromUtf8Error> {
  let dec = PercentDecode {
    bytes: input.as_ref().iter(),
  };
  String::from_utf8(dec.decode())
}

impl<'a> Iterator for PercentDecode<'a> {
  type Item = u8;

  fn next(&mut self) -> Option<u8> {
    self.bytes.next().map(|&byte| {
      if byte == b'%' {
        after_percent_sign(&mut self.bytes).unwrap_or(byte)
      } else {
        byte
      }
    })
  }

  fn size_hint(&self) -> (usize, Option<usize>) {
    let bytes = self.bytes.len();
    (bytes / 3, Some(bytes))
  }
}

#[derive(Clone, Debug)]
struct PercentDecode<'a> {
  bytes: slice::Iter<'a, u8>,
}

fn after_percent_sign(iter: &mut slice::Iter<u8>) -> Option<u8> {
  let initial_iter = iter.clone();
  let h = iter.next().and_then(|&b| (b as char).to_digit(16));
  let l = iter.next().and_then(|&b| (b as char).to_digit(16));
  if let (Some(h), Some(l)) = (h, l) {
    Some(h as u8 * 0x10 + l as u8)
  } else {
    *iter = initial_iter;
    None
  }
}

impl<'a> PercentDecode<'a> {
  /// If the percent-decoding is different from the input, return it as a new bytes vector.
  pub(crate) fn decode(&self) -> Vec<u8> {
    let mut bytes_iter = self.bytes.clone();
    while bytes_iter.any(|&b| b == b'%') {
      if let Some(decoded_byte) = after_percent_sign(&mut bytes_iter) {
        let initial_bytes = self.bytes.as_slice();
        let unchanged_bytes_len = initial_bytes.len() - bytes_iter.len() - 3;
        let mut decoded = initial_bytes[..unchanged_bytes_len].to_vec();
        decoded.push(decoded_byte);
        decoded.extend(PercentDecode { bytes: bytes_iter });
        return decoded;
      }
    }
    // Nothing to decode
    self.bytes.as_slice().to_vec()
  }
}
