use std::boxed::Box;
use std::sync::{Mutex, MutexGuard};
// Inspiration from: https://github.com/fortanix/rust-mbedtls/blob/master/mbedtls/src/threading.rs

// TODO: revisit all

use multee_core::{
  mbedtls_threading_mutex_t, mbedtls_threading_set_alt, MBEDTLS_ERR_THREADING_BAD_INPUT_DATA,
  MBEDTLS_ERR_THREADING_MUTEX_ERROR,
};

pub(crate) struct MbetlstMutex {
  guard: Option<MutexGuard<'static, ()>>,
  mutex: Mutex<()>,
}

#[allow(improper_ctypes)]
impl MbetlstMutex {
  unsafe extern "C" fn init(mutex: *mut mbedtls_threading_mutex_t) {
    let mutex = mutex as *mut *mut MbetlstMutex;
    if let Some(m) = mutex.as_mut() {
      *m = Box::into_raw(Box::new(MbetlstMutex {
        guard: None,
        mutex: Mutex::new(()),
      }));
    }
  }

  unsafe extern "C" fn free(mutex: *mut mbedtls_threading_mutex_t) {
    let mutex = mutex as *mut *mut MbetlstMutex;
    if let Some(m) = mutex.as_mut() {
      if *m != core::ptr::null_mut() {
        let _mutex: Box<MbetlstMutex> = Box::from_raw(*m);
        // mutex.guard.take();
        *m = core::ptr::null_mut();
      }
    }
  }

  unsafe extern "C" fn lock(mutex: *mut mbedtls_threading_mutex_t) -> i32 {
    let mutex = mutex as *mut *mut MbetlstMutex;
    if let Some(m) = mutex.as_mut().and_then(|p| p.as_mut()) {
      m.guard = Some(
        m.mutex
          .lock()
          .expect("another user of this mutex panicked while holding the mutex"),
      );
      0
    } else {
      MBEDTLS_ERR_THREADING_BAD_INPUT_DATA
    }
  }

  unsafe extern "C" fn unlock(mutex: *mut mbedtls_threading_mutex_t) -> i32 {
    let mutex = mutex as *mut *mut MbetlstMutex;
    if let Some(m) = mutex.as_mut().and_then(|p| p.as_mut()) {
      if m.guard.take().is_none() {
        MBEDTLS_ERR_THREADING_MUTEX_ERROR
      } else {
        0
      }
    } else {
      MBEDTLS_ERR_THREADING_MUTEX_ERROR
    }
  }

  pub fn set_alt() {
    unsafe {
      mbedtls_threading_set_alt(
        Some(MbetlstMutex::init),
        Some(MbetlstMutex::free),
        Some(MbetlstMutex::lock),
        Some(MbetlstMutex::unlock),
      );
    }
  }
}
