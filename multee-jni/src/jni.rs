use std::boxed::Box;
use std::os::raw::c_void;

use common::constants::MAX_CIPHERTEXT_EXPANSION;
use common::error::MulTeeResult;
use common::to_bool;
use kmip::enumerations::CryptographicAlgorithm;

use jni::objects::{GlobalRef, JClass, JObject, JStaticMethodID, JString, JValue};
use jni::signature::ReturnType;
use jni::sys::{jarray, jboolean, jbyteArray, jint, jlong, jobject, jvalue, JNI_VERSION_1_8};
use jni::{JNIEnv, JavaVM};

use lazycell::AtomicLazyCell;

use multee_lib::api::EnclaveSession;

trait ToRust<'a, T: Sized + 'a> {
  fn to_rust(&self, env: &'a JNIEnv) -> T;
}

impl<'a> ToRust<'a, String> for JString<'a> {
  fn to_rust(&self, env: &'a JNIEnv) -> String {
    String::from(env.get_string(*self).expect("Corrupt data from JNI"))
  }
}

static JLONG_CLASS: AtomicLazyCell<GlobalRef> = AtomicLazyCell::NONE;
static JLONG_VALUEOF: AtomicLazyCell<JStaticMethodID> = AtomicLazyCell::NONE;
static EITHER_CLASS: AtomicLazyCell<GlobalRef> = AtomicLazyCell::NONE;
static EITHER_RESULTOK: AtomicLazyCell<JStaticMethodID> = AtomicLazyCell::NONE;
static EITHER_RESULTERR: AtomicLazyCell<JStaticMethodID> = AtomicLazyCell::NONE;
static OPTION_NONE: AtomicLazyCell<GlobalRef> = AtomicLazyCell::NONE;
static BOOL_TRUE: AtomicLazyCell<GlobalRef> = AtomicLazyCell::NONE;
static BOOL_FALSE: AtomicLazyCell<GlobalRef> = AtomicLazyCell::NONE;

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut c_void) -> jint {
  let env = vm.get_env().expect("Cannot get reference to the JNIEnv");
  let l_class = env
    .find_class("java/lang/Long")
    .expect("Failed to load the target class");
  let l_method = env
    .get_static_method_id(l_class, "valueOf", "(J)Ljava/lang/Long;")
    .expect("Failed to load the target method");
  let g_class = env
    .new_global_ref(l_class)
    .expect("Failed to load the target class");
  // let g_method = env.new_global_ref(l_method).expect("Failed to load the target method");
  JLONG_CLASS
    .fill(g_class)
    .expect("Failed to fill static cache");
  JLONG_VALUEOF
    .fill(l_method)
    .expect("Failed to fill static cache");

  let l_class = env
    .find_class("cc/multee/impl/Native")
    .expect("Failed to load the target class");
  let l_method = env
    .get_static_method_id(
      l_class,
      "resultOk",
      "(Ljava/lang/Object;)Lio/vavr/control/Either;",
    )
    .expect("Failed to load the target method");
  let g_class = env
    .new_global_ref(l_class)
    .expect("Failed to load the target class");

  EITHER_CLASS
    .fill(g_class)
    .expect("Failed to fill static cache");
  EITHER_RESULTOK
    .fill(l_method)
    .expect("Failed to fill static cache");

  let l_method = env
    .get_static_method_id(
      l_class,
      "resultErr",
      "(IILjava/lang/String;)Lio/vavr/control/Either;",
    )
    .expect("Failed to load the target method");

  EITHER_RESULTERR
    .fill(l_method)
    .expect("Failed to fill static cache");

  let l_class = env
    .find_class("io/vavr/control/Option")
    .expect("Failed to load the target class");
  let l_method = env
    .get_static_method_id(l_class, "none", "()Lio/vavr/control/Option;")
    .expect("Failed to load the target method");
  let l_value = env
    .call_static_method_unchecked(l_class, l_method, ReturnType::Object, &[])
    .expect("Failed to call the target method")
    .l()
    .expect("Failed to convert to JObject");
  let g_value = env
    .new_global_ref(l_value)
    .expect("Failed to load the target class");

  OPTION_NONE
    .fill(g_value)
    .expect("Failed to fill static cache");

  let l_class = env
    .find_class("java/lang/Boolean")
    .expect("Failed to load the target class");
  let l_method = env
    .get_static_method_id(l_class, "valueOf", "(Z)Ljava/lang/Boolean;")
    .expect("Failed to load the target method");
  let ljv = jvalue {
    z: true as jboolean,
  };
  let l_value = env
    .call_static_method_unchecked(l_class, l_method, ReturnType::Object, &[ljv])
    .expect("Failed to call the target method")
    .l()
    .expect("Failed to convert to JObject");
  let g_value = env
    .new_global_ref(l_value)
    .expect("Failed to load the target class");
  BOOL_TRUE
    .fill(g_value)
    .expect("Failed to fill static cache");
  let ljv = jvalue {
    z: false as jboolean,
  };
  let l_value = env
    .call_static_method_unchecked(l_class, l_method, ReturnType::Object, &[ljv])
    .expect("Failed to call the target method")
    .l()
    .expect("Failed to convert to JObject");
  let g_value = env
    .new_global_ref(l_value)
    .expect("Failed to load the target class");
  BOOL_FALSE
    .fill(g_value)
    .expect("Failed to fill static cache");

  JNI_VERSION_1_8
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "system" fn JNI_OnUnload(_vm: JavaVM, _: *mut c_void) {}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_loadKeys(
  env: JNIEnv, _class: JClass, url: JString, key_names: jarray, creds_zip: JString,
) -> jobject {
  let creds_file = creds_zip.to_rust(&env);
  let url = url.to_rust(&env);

  let key_names_len = env
    .get_array_length(key_names)
    .expect("Corrupt data from JNI");

  // convert String[] to array of C string
  let mut k_names: Vec<String> = Vec::with_capacity(key_names_len as usize);
  for i in 0..key_names_len {
    let j_str = JString::from(
      env
        .get_object_array_element(key_names, i)
        .expect("Corrupt data from JNI"),
    );
    k_names.push(j_str.to_rust(&env));
  }

  let e =
    EnclaveSession::load_keys(creds_file.as_str(), url.as_str(), k_names, None).map(|enc_sess| {
      let ptr = Box::into_raw(Box::new(enc_sess)) as i64;
      wrap_long(env, ptr)
    });

  to_java_either(env, e)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_destroyEnclave(
  _env: JNIEnv, _class: JClass, global_eid: jlong,
) {
  unsafe {
    let _ = Box::from_raw(global_eid as *mut EnclaveSession);
  };
  // drop enclave after taking ownership
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_hmacSha256(
  env: JNIEnv, _class: JClass, global_eid: i64, key_index: jint, input: jbyteArray,
) -> jobject {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };

  let input = env
    .convert_byte_array(input)
    .expect("Corrupt data from JNI");

  let result = enc_sess
    .hmac_sha256(key_index as usize, input.as_slice())
    .map(|output| {
      wrap_byte_array(
        env
          .byte_array_from_slice(output.as_slice())
          .expect("Corrupt data from JNI"),
      )
    });

  to_java_either(env, result)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_generateCSR(
  env: JNIEnv, _class: JClass, global_eid: i64, zip_name: JString, subject_name: JString,
) -> jobject {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };
  let sn = subject_name.to_rust(&env);
  let filename = zip_name.to_rust(&env);
  let res = enc_sess
    .mk_csr_zip(filename.as_str(), sn.as_str())
    .map(wrap_unit);
  to_java_either(env, res)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_cryptCbc(
  env: JNIEnv, _class: JClass, global_eid: i64, key_index: jint, encrypt: jboolean,
  explicit_iv: jboolean, jiv: jbyteArray, data: jbyteArray,
) -> jobject {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };

  let key_index = key_index as usize;
  // let padding = true; // TODO: decide whether is needed
  let explicit_iv = to_bool(explicit_iv as usize);
  let mut iv: Vec<u8> = env.convert_byte_array(jiv).expect("Corrupt data from JNI");
  let input_len = env.get_array_length(data).expect("Corrupt data from JNI") as usize;
  let mut crypto_buf = vec![0u8; input_len + MAX_CIPHERTEXT_EXPANSION];
  let crypto_buf = crypto_buf.as_mut_slice();
  env
    .get_byte_array_region(data, 0, unsafe {
      std::mem::transmute(&mut crypto_buf[0..input_len])
    })
    .expect("Corrupt data from JNI");

  let res = if to_bool(encrypt as usize) {
    enc_sess.encrypt_cbc(
      key_index,
      explicit_iv,
      iv.as_mut_slice(),
      crypto_buf,
      input_len,
    )
  } else {
    enc_sess.decrypt_cbc(
      key_index,
      explicit_iv,
      iv.as_mut_slice(),
      crypto_buf,
      input_len,
    )
  };

  if res.is_ok() && !explicit_iv {
    set_byte_array(env, jiv, iv.as_slice()).expect("Unexpected error populating IV");
  }

  let res = res.map(|output_len| {
    wrap_byte_array(
      env
        .byte_array_from_slice(&crypto_buf[..output_len])
        .expect("Corrupt data from JNI"),
    )
  });
  to_java_either(env, res)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_cryptGcm(
  env: JNIEnv, _class: JClass, global_eid: i64, key_index: jint, encrypt: jboolean, iv: jbyteArray,
  aad: jbyteArray, data: jbyteArray, tag: jbyteArray,
) -> jbyteArray {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };

  let key_index = key_index as usize;
  let encrypt = to_bool(encrypt as usize);

  // set aad to None if null or empty
  let aad = env.convert_byte_array(aad).expect("Corrupt data from JNI");
  let aad = if aad.is_empty() {
    None
  } else {
    Some(aad.as_slice())
  };
  let mut crypto_buf = env.convert_byte_array(data).expect("Corrupt data from JNI");

  let result = if encrypt {
    enc_sess
      .encrypt_gcm(key_index, aad, crypto_buf.as_slice()) //.expect("Cannot happen, until key restrictions");
      .map(|(out, iv_vec, tag_vec)| {
        set_byte_array(env, iv, iv_vec.as_slice()).expect("Unexpected error populating IV");
        set_byte_array(env, tag, tag_vec.as_slice()).expect("Unexpected error populating Tag");
        env
          .byte_array_from_slice(out.as_slice())
          .expect("Unexpected error populating crypto_buf")
      })
  } else {
    let iv = env.convert_byte_array(iv).expect("Corrupt data from JNI");
    let tag = env.convert_byte_array(tag).expect("Corrupt data from JNI");

    enc_sess
      .decrypt_gcm(
        key_index,
        aad,
        crypto_buf.as_mut_slice(),
        iv.as_slice(),
        tag.as_slice(),
      )
      .map(|out| {
        env
          .byte_array_from_slice(out.as_slice())
          .expect("Unexpected error populating crypto_buf")
      })
  };

  to_java_either(env, result.map(wrap_byte_array))
}

use multee_core::api::DEFAULT_SIG_HASH;
use multee_core::api::DEFAULT_SIG_PADDING;
#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_sign(
  env: JNIEnv, _class: JClass, global_eid: i64, key_index: jint, data: jbyteArray,
) -> jobject {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };

  let key_index = key_index as usize;
  let input = env.convert_byte_array(data).expect("Corrupt data from JNI");

  let result = enc_sess
    .sign(
      key_index,
      Some(DEFAULT_SIG_PADDING),
      DEFAULT_SIG_HASH,
      input.as_slice(),
    )
    .map(|output| {
      wrap_byte_array(
        env
          .byte_array_from_slice(output.as_slice())
          .expect("Corrupt data from JNI"),
      )
    });

  to_java_either(env, result)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_verify(
  env: JNIEnv, _class: JClass, global_eid: i64, key_index: jint, message: jbyteArray,
  signature: jbyteArray,
) -> jobject {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };

  let key_index = key_index as usize;
  let msg = env
    .convert_byte_array(message)
    .expect("Corrupt data from JNI");
  let sig = env
    .convert_byte_array(signature)
    .expect("Corrupt data from JNI");

  let is_rsa = matches!(
    enc_sess.get_key_type(key_index),
    Ok(CryptographicAlgorithm::RSA)
  );

  let padding = if is_rsa {
    Some(DEFAULT_SIG_PADDING)
  } else {
    None
  };

  let result = enc_sess
    .verify(
      key_index,
      padding,
      DEFAULT_SIG_HASH,
      msg.as_slice(),
      sig.as_slice(),
    )
    .map(wrap_bool);

  to_java_either(env, result)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_getLength(
  env: JNIEnv, _class: JClass, global_eid: i64, key_index: jint,
) -> jobject {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };

  let key_index = key_index as usize;

  let result = enc_sess
    .key_len(key_index)
    .map(|v| wrap_long(env, v as i64));

  to_java_either(env, result)
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn Java_cc_multee_impl_Native_getName(
  env: JNIEnv, _class: JClass, global_eid: i64, key_index: jint,
) -> jobject {
  let enc_sess: &EnclaveSession = unsafe { &*(global_eid as *const EnclaveSession) };

  let key_index = key_index as usize;
  let result = enc_sess.key_name(key_index).map(|v| jvalue {
    l: env
      .new_string(v)
      .expect("couldn't create java string")
      .into_raw(),
  });

  to_java_either(env, result)
}

/*
    SGX helpers
*/

fn set_byte_array<'a>(env: JNIEnv, array: jbyteArray, slice: &[u8]) -> jni::errors::Result<()> {
  let buf: &[i8] = unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const i8, slice.len()) };

  env.set_byte_array_region(array, 0, buf)
}

fn wrap_long(env: JNIEnv, v: i64) -> jvalue {
  let g_class = JLONG_CLASS
    .borrow()
    .expect("Impossible - initialized on load")
    .as_obj();
  let g_method = JLONG_VALUEOF
    .get()
    .expect("Impossible, would have failed ONLoad");

  let l = jvalue { j: v };
  let l = env
    .call_static_method_unchecked(g_class, g_method, ReturnType::Object, &[l])
    .expect("Failed to call the target method");
  jvalue {
    l: l.l().expect("Failed to convert result").into_raw(),
  }
}

fn wrap_byte_array(v: jbyteArray) -> jvalue {
  jvalue { l: v }
}

fn wrap_unit(_v: ()) -> jvalue {
  let g = OPTION_NONE
    .borrow()
    .expect("Impossible - initialized on load")
    .as_obj();
  jvalue { l: g.into_raw() }
}

fn to_java_either(env: JNIEnv, res: MulTeeResult<jvalue>) -> jobject {
  let class = EITHER_CLASS
    .borrow()
    .expect("Impossible - initialized on load")
    .as_obj();

  let v: JValue = match res {
    Ok(jval) => {
      let ok_method = EITHER_RESULTOK
        .get()
        .expect("Impossible, would have failed ONLoad");
      env
        .call_static_method_unchecked(class, ok_method, ReturnType::Object, &[jval])
        .expect("Failed to call the target method")
    }
    Err(e) => {
      let code = jvalue { i: e.tag as jint };
      let sub = jvalue { i: e.sub as jint };
      let msg = jvalue {
        l: env
          .new_string(e.message.unwrap_or("".to_string()))
          .expect("Failed to create string")
          .into_raw(),
      };
      let err_method = EITHER_RESULTERR
        .get()
        .expect("Impossible, would have failed ONLoad");

      env
        .call_static_method_unchecked(class, err_method, ReturnType::Object, &[code, sub, msg])
        .expect("Failed to call the target method")
    }
  };
  let r: JObject = v.l().expect("Failed to convert result");
  r.into_raw()
}

fn wrap_bool(v: bool) -> jvalue {
  let o = if v {
    BOOL_TRUE.borrow()
  } else {
    BOOL_FALSE.borrow()
  };

  jvalue {
    l: o
      .expect("Impossible - initialized on load")
      .as_obj()
      .into_raw(),
  }
}
