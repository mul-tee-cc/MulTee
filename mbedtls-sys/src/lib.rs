// #![feature(concat_idents)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// // #[macro_use]
// extern crate paste;
// #[macro_use]
// use paste::paste;

// #![feature(const_if_match)]

// extern crate mashup;
// #[macro_use]
// use paste::paste;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod libc {
  #[cfg(any(
    all(
      target_os = "linux",
      any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x"
      )
    ),
    all(
      target_os = "freebsd",
      any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
      )
    ),
    all(
      target_os = "netbsd",
      any(target_arch = "aarch64", target_arch = "arm", target_arch = "powerpc")
    ),
    all(
      target_os = "android",
      any(target_arch = "aarch64", target_arch = "arm")
    ),
    all(target_os = "openbsd", target_arch = "aarch64"),
    all(target_os = "fuchsia", target_arch = "aarch64"),
    all(target_os = "l4re", target_arch = "x86_64"),
  ))]
  pub type c_char = u8;
  #[cfg(not(any(
    all(
      target_os = "linux",
      any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x"
      )
    ),
    all(
      target_os = "freebsd",
      any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
      )
    ),
    all(
      target_os = "netbsd",
      any(target_arch = "aarch64", target_arch = "arm", target_arch = "powerpc")
    ),
    all(
      target_os = "android",
      any(target_arch = "aarch64", target_arch = "arm")
    ),
    all(target_os = "openbsd", target_arch = "aarch64"),
    all(target_os = "fuchsia", target_arch = "aarch64"),
    all(target_os = "l4re", target_arch = "x86_64"),
  )))]
  pub type c_char = i8;
  pub type c_schar = i8;
  pub type c_uchar = u8;
  pub type c_short = i16;
  pub type c_ushort = u16;
  pub type c_int = i32;
  pub type c_uint = u32;
  #[cfg(any(target_pointer_width = "32", windows))]
  pub type c_long = i32;
  #[cfg(any(target_pointer_width = "32", windows))]
  pub type c_ulong = u32;
  #[cfg(all(target_pointer_width = "64", not(windows)))]
  pub type c_long = i64;
  #[cfg(all(target_pointer_width = "64", not(windows)))]
  pub type c_ulong = u64;
  pub type c_longlong = i64;
  pub type c_ulonglong = u64;
  pub type c_float = f32;
  pub type c_double = f64;
  pub type c_void = core::ffi::c_void;
}

// Target crate will need to "use paste::paste;"
#[macro_export]
macro_rules! mbedtls_struct {
  ($rname:ident, $cname:ident, $ctxname:ident) => {
    pub struct $rname {
      pub ctx: std::boxed::Box<$ctxname>,
    }
    paste! {
      impl $rname {
        pub fn new() -> Self {
          let mut slf = $rname { ctx: std::boxed::Box::new(core::default::Default::default()) };
          slf.init();
          slf
        }
        fn init(&mut self) {
          unsafe { [<mbedtls_ $cname _init>](self.as_mut_ptr()) }
        }
      }
    }
    paste! {
      impl Drop for $rname {
        fn drop(&mut self) {
          unsafe { [<mbedtls_ $cname _free>](self.as_mut_ptr()) }
        }
      }
    }
    impl Ctx for $rname {
      type CtxType = $ctxname;
      fn as_ptr(&self) -> *const Self::CtxType {
        core::borrow::Borrow::borrow(&self.ctx) as *const Self::CtxType
      }
      fn as_mut_ptr(&mut self) -> *mut Self::CtxType {
        core::borrow::BorrowMut::borrow_mut(&mut self.ctx) as *mut Self::CtxType
      }
      fn force_mut_ptr(&self) -> *mut Self::CtxType {
        core::borrow::Borrow::borrow(&self.ctx) as *const Self::CtxType as *mut Self::CtxType
      }
    }
    unsafe impl Send for $rname {}
    unsafe impl Sync for $rname {}
  };
}
#[macro_export]
macro_rules! mbedtls_struct_plus2 {
  ($rname:ident, $cname:ident, $ctxname:ident, $p1:ident, $p1_type:ty, $p2:ident, $p2_type:ty) => {
    pub struct $rname {
      pub ctx: std::boxed::Box<$ctxname>,
    }
    paste! {
      impl $rname {
        pub fn new($p1: $p1_type, $p2: $p2_type) -> Self {
          let mut slf = $rname { ctx: std::boxed::Box::new(core::default::Default::default()) };
          slf.init($p1, $p2);
          slf
        }
        fn init(&mut self, $p1: $p1_type, $p2: $p2_type) {
          unsafe { [<mbedtls_ $cname _init>](self.as_mut_ptr(), $p1, $p2) }
        }
      }
    }
    paste! {
      impl Drop for $rname {
        fn drop(&mut self) {
          unsafe { [<mbedtls_ $cname _free>](self.as_mut_ptr()) }
        }
      }
    }
    impl Ctx for $rname {
      type CtxType = $ctxname;
      fn as_ptr(&self) -> *const Self::CtxType {
        core::borrow::Borrow::borrow(&self.ctx) as *const Self::CtxType
      }
      fn as_mut_ptr(&mut self) -> *mut Self::CtxType {
        core::borrow::BorrowMut::borrow_mut(&mut self.ctx) as *mut Self::CtxType
      }
      fn force_mut_ptr(&self) -> *mut Self::CtxType {
        core::borrow::Borrow::borrow(&self.ctx) as *const Self::CtxType as *mut Self::CtxType
      }
    }
    unsafe impl Send for $rname {}
    unsafe impl Sync for $rname {}
  };
}

pub trait Ctx {
  type CtxType;
  fn as_ptr(&self) -> *const Self::CtxType;
  fn as_mut_ptr(&mut self) -> *mut Self::CtxType;
  fn force_mut_ptr(&self) -> *mut Self::CtxType;
}

// mbedtls_struct!(Pk, pk, mbedtls_pk_context);
// mbedtls_struct!(CsrBuilder, x509write_csr, mbedtls_x509write_csr);

#[cfg(not(target_arch = "x86_64"))]
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
  return 0;
}

#[cfg(target_arch = "x86_64")]
#[doc(hidden)]
#[no_mangle]
pub extern "C" fn mbedtls_aesni_has_support(_what: u32) -> i32 {
  return 1;
}

#[cfg(feature = "multee_sgx")]
#[doc(hidden)]
#[no_mangle]
pub unsafe extern "C" fn mbedtls_hardware_poll(
  _data: *const u8, output: *mut u8, len: usize, olen: *mut usize,
) -> libc::c_int {
  match getrandom(core::slice::from_raw_parts_mut(output, len)) {
    Ok(()) => {
      *olen = len;
      0
    }
    // Err(_) => MBEDTLS_ERR_ENTROPY_SOURCE_FAILED
    Err(x) => x,
  }
}

#[cfg(feature = "multee_sgx")]
const RETRY_LIMIT: usize = 100;
#[cfg(feature = "multee_sgx")]
const WORD_SIZE: usize = core::mem::size_of::<usize>();

#[cfg(feature = "multee_sgx")]
unsafe fn getrandom(dest: &mut [u8]) -> Result<(), i32> {
  let mut chunks = dest.chunks_exact_mut(WORD_SIZE);
  for chunk in chunks.by_ref() {
    chunk.copy_from_slice(&rdrand()?);
  }

  let tail = chunks.into_remainder();
  let n = tail.len();
  if n > 0 {
    tail.copy_from_slice(&rdrand()?[..n]);
  }
  Ok(())
}

#[cfg(feature = "multee_sgx")]
unsafe fn rdrand() -> Result<[u8; WORD_SIZE], i32> {
  for _ in 0..RETRY_LIMIT {
    let mut el = core::mem::zeroed();
    if core::arch::x86_64::_rdrand64_step(&mut el) == 1 {
      return Ok(el.to_ne_bytes());
    }
  }
  Err(MBEDTLS_ERR_ENTROPY_SOURCE_FAILED)
}
