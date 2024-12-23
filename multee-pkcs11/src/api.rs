#![allow(non_camel_case_types, non_snake_case)]
use crate::{
  MULTEE_CK_INFO, MULTEE_SESSION_HANDLE, MULTEE_SLOT_ID, MULTEE_SLOT_INFO, MULTEE_TOKEN_INFO,
  PKCS11_FUNCTIONS,
};
use common::error::MulTeeErrCode;
use common::error::MulTeeResult;
use dotenvy;
use multee_lib::api::EnclaveSession;
use once_cell::sync::Lazy;
use pkcs11::types::*;
use std::cell::RefCell;
use std::env;
use std::fs::OpenOptions;
use std::os::unix::fs;
use std::os::unix::fs::MetadataExt;
use std::sync::Mutex;

pub(crate) static MAX_KEYS: usize = 100;

fn build_multee() -> MulTeeResult<EnclaveSession> {
  let (url, name, zip) = dotenvy::var("MULTEE_KEY_URL_PREFIX")
    .and_then( |url| dotenvy::var("MULTEE_KEY_NAME").map(|name| (url, name)))
    .and_then( |(url, name)| dotenvy::var("MULTEE_CREDENTIALS_ZIP").map(|zip| (url, name, zip)))
    .map_err(|_| MulTeeErrCode::CREDENTIALS.msg("Missing credentials specification (parameters MULTEE_KEY_URL_PREFIX, MULTEE_KEY_NAME and MULTEE_CREDENTIALS_ZIP are mandatory"))?;

  let key_names: Vec<String> = name.split(",").map(|s| s.to_string()).collect();

  let sess = EnclaveSession::load_keys(zip.as_str(), url.as_str(), key_names, None)?;

  Ok(sess)
}

pub(crate) static NGINX_MASTER: Lazy<u32> = Lazy::new(|| std::process::id());

static MASTER: Mutex<RefCell<MulTeeResult<EnclaveSession>>> = Mutex::new(RefCell::new(Err(
  MulTeeErrCode::PKCS11_PROTOCOL_VIOLATION.no_msg(),
)));
static WORKER: Mutex<RefCell<MulTeeResult<EnclaveSession>>> = Mutex::new(RefCell::new(Err(
  MulTeeErrCode::PKCS11_PROTOCOL_VIOLATION.no_msg(),
)));

pub(crate) fn get_session() -> &'static Mutex<RefCell<MulTeeResult<EnclaveSession>>> {
  if std::process::id() == *NGINX_MASTER {
    &MASTER
  } else {
    &WORKER
  }
}

pub(crate) fn get_key_count() -> usize {
  get_session()
    .lock()
    .unwrap()
    .get_mut()
    .as_ref()
    .map(|sh| sh.key_count().unwrap())
    .unwrap()
}

pub(crate) fn load_env() {
  eprintln!("MULTEE_PARAMETERS = {:?}", env::var("MULTEE_PARAMETERS"));
  if let Ok(path) = env::var("MULTEE_PARAMETERS") {
    dotenvy::from_path_override(path).expect("Missing or malformed MULTEE_PARAMETERS file");
  }
}

/// `C_Initialize` initializes the Cryptoki library.
///
/// # Function Parameters
///
/// * `pInitArgs`: if this is not NULL_PTR, it gets cast to CK_C_INITIALIZE_ARGS_PTR and dereferenced
///
#[no_mangle]
pub extern "C" fn C_Initialize(pInitArgs: CK_C_INITIALIZE_ARGS_PTR) -> CK_RV {
  let args: &mut CK_C_INITIALIZE_ARGS = unsafe { &mut *pInitArgs };
  if args.pReserved != std::ptr::null_mut() {
    return CKR_ARGUMENTS_BAD;
  }

  load_env();

  let file = dotenvy::var("MULTEE_LOG_FILE").unwrap_or("/tmp/multee-pkcs11.log".to_string());
  let created = OpenOptions::new()
    .append(true)
    .write(true)
    .create(true)
    .open(&file);
  match created {
    Ok(f) => {
      if let Some(pat) = dotenvy::var("MULTEE_LOG_FILE_OWNER_PATTERN").ok() {
        if let Some(uid) = std::fs::metadata(pat).map(|m| m.uid()).ok() {
          if let Err(e) = fs::chown(file, Some(uid), None) {
            eprintln!(
              "Unable to change log ownership per $MULTEE_LOG_FILE_OWNER_PATTERN: {}",
              e
            );
          }
        }
      }
      EnclaveSession::configure_logging(Some(Box::new(f)));
    }
    Err(e) => {
      if dotenvy::var("MULTEE_LOG_MANDATORY").is_ok() {
        panic!("Unable to open {} for writing: {}", file, e);
      } else {
        eprintln!("Unable to open {} for writing: {}", file, e);
      }
    }
  };

  log::info!(
    "MulTee Initialization postponed till C_FindObjectsInit call  (PID: {}, Master: {})",
    std::process::id(),
    *NGINX_MASTER
  );
  CKR_OK
}

/// `C_Finalize` indicates that an application is done with the Cryptoki library.
///
/// # Function Parameters
///
/// * `pReserved`: reserved.  Should be NULL_PTR
///
#[no_mangle]
pub extern "C" fn C_Finalize(pReserved: CK_VOID_PTR) -> CK_RV {
  log::debug!("MulTee.C_Finalize");

  if pReserved == std::ptr::null_mut() {
    CKR_OK
  } else {
    log::error!("MulTee CKR_ARGUMENTS_BAD");
    CKR_ARGUMENTS_BAD
  }
}

/// `C_GetInfo` returns general information about Cryptoki.
///
/// # Function Parameters
///
/// * `pInfo`: location that receives information
///
#[no_mangle]
pub extern "C" fn C_GetInfo(pInfo: CK_INFO_PTR) -> CK_RV {
  log::debug!("@@@ C_GetInfo");

  unsafe {
    *pInfo = MULTEE_CK_INFO;
  }
  CKR_OK
}

/// `C_GetFunctionList` returns the function list.
///
/// # Function Parameters
///
/// * `ppFunctionList`: receives pointer to function list
///
#[no_mangle]
pub extern "C" fn C_GetFunctionList(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV {
  log::debug!("MulTee.C_GetFunctionList");

  if ppFunctionList == std::ptr::null_mut() {
    log::error!("MulTee CKR_ARGUMENTS_BAD");
    CKR_ARGUMENTS_BAD
  } else {
    unsafe {
      *ppFunctionList = &mut PKCS11_FUNCTIONS;
    }
    CKR_OK
  }
}

/// `C_GetSlotList` obtains a list of slots in the system.
///
/// # Function Parameters
///
/// * `tokenPresent`: only slots with tokens
/// * `pSlotList`: receives array of slot IDs
/// * `pulCount`: receives number of slots
///
#[no_mangle]
pub extern "C" fn C_GetSlotList(
  _tokenPresent: CK_BBOOL, pSlotList: CK_SLOT_ID_PTR, pulCount: CK_ULONG_PTR,
) -> CK_RV {
  log::debug!("MulTee.C_GetSlotList");

  if pulCount == std::ptr::null_mut() {
    log::error!("MulTee CKR_ARGUMENTS_BAD");
    CKR_ARGUMENTS_BAD
  } else {
    unsafe {
      *pulCount = 1;
    }
    if pSlotList != std::ptr::null_mut() {
      unsafe {
        *pSlotList = MULTEE_SLOT_ID;
      }
    }
    CKR_OK
  }
}

/// `C_GetSlotInfo` obtains information about a particular slot in the system.
///
/// # Function Parameters
///
/// * `slotID`: the ID of the slot
/// * `pInfo`: receives the slot information
///
#[no_mangle]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: CK_SLOT_INFO_PTR) -> CK_RV {
  log::debug!("MulTee.C_GetSlotInfo");

  if slotID != MULTEE_SLOT_ID {
    log::error!("MulTee CKR_SLOT_ID_INVALID");
    CKR_SLOT_ID_INVALID
  } else if pInfo == std::ptr::null_mut() {
    log::error!("MulTee CKR_ARGUMENTS_BAD");
    CKR_ARGUMENTS_BAD
  } else {
    unsafe {
      *pInfo = MULTEE_SLOT_INFO;
    }
    CKR_OK
  }
}

/// `C_GetTokenInfo` obtains information about a particular token in the system.
///
/// # Function Parameters
///
/// * `slotID`: ID of the token's slot
/// * `pInfo`: receives the token information
///
#[no_mangle]
pub extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: CK_TOKEN_INFO_PTR) -> CK_RV {
  log::debug!("MulTee.C_GetTokenInfo");

  if slotID != MULTEE_SLOT_ID {
    log::error!("MulTee CKR_SLOT_ID_INVALID");
    CKR_SLOT_ID_INVALID
  } else if pInfo == std::ptr::null_mut() {
    log::error!("MulTee CKR_ARGUMENTS_BAD");
    CKR_ARGUMENTS_BAD
  } else {
    unsafe {
      *pInfo = MULTEE_TOKEN_INFO;
    }
    CKR_OK
  }
}

/// `C_OpenSession` opens a session between an application and a token.
///
/// # Function Parameters
///
/// * `slotID`: the slot's ID
/// * `flags`: from CK_SESSION_INFO
/// * `pApplication`: passed to callback
/// * `Notify`: callback function
/// * `phSession`: gets session handle
///
#[no_mangle]
pub extern "C" fn C_OpenSession(
  slotID: CK_SLOT_ID, _flags: CK_FLAGS, _pApplication: CK_VOID_PTR, _Notify: CK_NOTIFY,
  phSession: CK_SESSION_HANDLE_PTR,
) -> CK_RV {
  log::debug!("MulTee.C_OpenSession");

  if slotID != MULTEE_SLOT_ID {
    log::error!("MulTee CKR_SLOT_ID_INVALID");
    CKR_SLOT_ID_INVALID
  } else if phSession == std::ptr::null_mut() {
    log::error!("MulTee CKR_ARGUMENTS_BAD");
    CKR_ARGUMENTS_BAD
  } else {
    unsafe {
      *phSession = MULTEE_SESSION_HANDLE;
    }
    CKR_OK
  }
}

/// `C_CloseSession` closes a session between an application and a token.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
#[no_mangle]
pub extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
  log::debug!("MulTee.C_CloseSession");

  if hSession != MULTEE_SESSION_HANDLE {
    log::error!("MulTee CKR_SESSION_HANDLE_INVALID");
    CKR_SESSION_HANDLE_INVALID
  } else {
    CKR_OK
  }
}

pub(crate) mod findobject {
  #![allow(non_camel_case_types, non_snake_case)]
  use crate::api::*;
  use crate::MULTEE_SESSION_HANDLE;
  use cryptoki::object::{Attribute, ObjectClass};
  use pkcs11::types::*;
  use std::cell::RefCell;
  use std::collections::HashMap;
  use std::convert::TryFrom;
  use std::sync::atomic::{AtomicUsize, Ordering};
  use std::sync::Mutex;

  struct FindOp {
    attrs: HashMap<CK_ATTRIBUTE_TYPE, Attribute>,
    position: usize,
  }
  impl FindOp {
    fn inc(&mut self) {
      self.position = self.position + 1;
    }
  }

  static FIND_OP_STATE: Mutex<RefCell<Option<FindOp>>> = Mutex::new(RefCell::new(None));

  pub(crate) static FIND_OP_BASE: AtomicUsize = AtomicUsize::new(1);

  /// `C_FindObjectsInit` initializes a search for token and session objects that match a template.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pTemplate`: attribute values to match
  /// * `ulCount`: attrs in search template
  ///
  #[no_mangle]
  pub extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG,
  ) -> CK_RV {
    log::debug!(
      "MulTee.C_FindObjectsInit (PID: {}, Master: {})",
      std::process::id(),
      *NGINX_MASTER
    );

    if hSession != MULTEE_SESSION_HANDLE {
      CKR_SESSION_HANDLE_INVALID
    } else if pTemplate == std::ptr::null_mut() /*|| ulCount == 0*/ || ulCount > 2 {
      log::error!("MulTee CKR_ARGUMENTS_BAD");
      CKR_ARGUMENTS_BAD
    } else if FIND_OP_STATE.lock().unwrap().borrow().is_some() {
      log::error!("MulTee CKR_OPERATION_ACTIVE");
      CKR_OPERATION_ACTIVE
    } else {
      let mut attrs: HashMap<CK_ATTRIBUTE_TYPE, Attribute> = HashMap::new();
      for i in 0..ulCount {
        let a = unsafe { *pTemplate.add(i as usize) };

        if a.attrType == CKA_CLASS
          && (a.ulValueLen as usize) == std::mem::size_of::<CK_OBJECT_CLASS>()
        {
          let val = a.pValue as *const CK_OBJECT_CLASS;
          let object_class: CK_OBJECT_CLASS = unsafe { *val };
          let attr = Attribute::Class(ObjectClass::try_from(object_class).unwrap());

          log::trace!("MulTee Attr: {}: {:?}", a.attrType, attr);
          let _ = attrs.insert(a.attrType, attr);
        } else if a.attrType == CKA_ID {
          let val =
            unsafe { std::slice::from_raw_parts(a.pValue as *const u8, a.ulValueLen as usize) };
          let attr = Attribute::ObjectId(val.to_vec());

          log::trace!("MulTee Attr: {}: {:?}", a.attrType, attr);
          let _ = attrs.insert(a.attrType, attr);
        } else {
          log::error!("MulTee Unknown FindObjects ATTR: {}", a.attrType);
        }
      }
      load_env();
      let ses = build_multee().expect("Valid session is required");
      let _ = get_session().lock().unwrap().replace(Ok(ses));
      // CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
      let state = FindOp { attrs, position: 0 };
      FIND_OP_STATE.lock().unwrap().replace(Some(state));

      CKR_OK
    }
    // Logic originally from https://aws.github.io/aws-iot-device-sdk-embedded-C/202012.00/libraries/standard/corePKCS11/docs/doxygen/output/html/pkcs11_mbedtls_function_c_findobjectsinit.html
  }

  /// `C_FindObjects` continues a search for token and session objects that match a template, obtaining additional object handles.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `phObject`: gets obj. handles
  /// * `ulMaxObjectCount`: max handles to get
  /// * `pulObjectCount`: actual # returned
  ///
  #[no_mangle]
  pub extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE, phObject: CK_OBJECT_HANDLE_PTR, ulMaxObjectCount: CK_ULONG,
    pulObjectCount: CK_ULONG_PTR,
  ) -> CK_RV {
    log::debug!("MulTee.C_FindObjects");

    if hSession != MULTEE_SESSION_HANDLE {
      log::error!("MulTee CKR_SESSION_HANDLE_INVALID");
      CKR_SESSION_HANDLE_INVALID
    } else if phObject == std::ptr::null_mut() || pulObjectCount == std::ptr::null_mut()
    /*|| ulMaxObjectCount != 1 */
    {
      log::debug!("MulTee.C_FindObjects max {}", ulMaxObjectCount);
      CKR_ARGUMENTS_BAD
    } else {
      match FIND_OP_STATE.lock().unwrap().get_mut() {
        None => CKR_OPERATION_NOT_INITIALIZED,
        Some(op_state) => {
          unsafe {
            if op_state.position == get_key_count() {
              *pulObjectCount = 0;
            } else if let Some(Attribute::ObjectId(id)) = op_state.attrs.get(&CKA_ID) {
              let ptr = id.as_ptr() as *const usize;
              *pulObjectCount = 1 as CK_ULONG;
              *phObject = *ptr as CK_OBJECT_HANDLE;
              log::debug!("MulTee.C_FindObjects hObject={}", *phObject);
            } else {
              *pulObjectCount = 1 as CK_ULONG;
              let base = FIND_OP_BASE.load(Ordering::SeqCst) * MAX_KEYS;
              *phObject = (base + op_state.position) as CK_OBJECT_HANDLE;
              log::debug!("MulTee.C_FindObjects hObject={}", *phObject);
              op_state.inc();
            }
          }
          CKR_OK
        }
      }
    }
  }

  /// `C_FindObjectsFinal` finishes a search for token and session objects.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  ///
  #[no_mangle]
  pub extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    log::debug!("MulTee.C_FindObjectsFinal");

    FIND_OP_BASE.fetch_add(1, Ordering::SeqCst);

    if hSession != MULTEE_SESSION_HANDLE {
      log::error!("MulTee CKR_SESSION_HANDLE_INVALID");
      CKR_SESSION_HANDLE_INVALID
    } else {
      FIND_OP_STATE.lock().unwrap().replace(None);
      CKR_OK
    }
  }
}

pub(crate) mod getattribute {
  #![allow(non_camel_case_types, non_snake_case)]

  use std::convert::TryFrom;

  use cryptoki::object::AttributeType;
  use pkcs11::types::*;

  use crate::api::*;
  use crate::{MULTEE_KEY_ID, MULTEE_SESSION_HANDLE};
  use kmip::enumerations::CryptographicAlgorithm;

  // Workaround: Library doesn't cover some types, specifically CKA_CERTIFICATE_TYPE
  fn to_attr_type(typ: CK_ATTRIBUTE_TYPE) -> AttributeType {
    if typ == CKA_CERTIFICATE_TYPE {
      AttributeType::CertificateType
    } else {
      AttributeType::try_from(typ).expect("Unexpected attribute")
    }
  }

  /// `C_GetAttributeValue` obtains the value of one or more object attributes.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `hObject`: the object's handle
  /// * `pTemplate`: specifies attrs; gets vals
  /// * `ulCount`: attributes in template
  ///
  #[no_mangle]
  pub extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE, hObject: CK_OBJECT_HANDLE, pTemplate: CK_ATTRIBUTE_PTR,
    ulCount: CK_ULONG,
  ) -> CK_RV {
    let key_index = hObject as usize % MAX_KEYS;
    log::debug!(
      "MulTee.C_GetAttributeValue hObject={} ulCount={}",
      hObject as usize,
      ulCount as usize
    );

    if hSession != MULTEE_SESSION_HANDLE {
      log::error!("MulTee CKR_SESSION_HANDLE_INVALID");
      CKR_SESSION_HANDLE_INVALID
    } else if key_index >= get_key_count() {
      log::error!("MulTee CKR_OBJECT_HANDLE_INVALID");
      CKR_OBJECT_HANDLE_INVALID
    } else if pTemplate == std::ptr::null_mut() || ulCount == 0 {
      log::error!("MulTee CKR_ARGUMENTS_BAD");
      CKR_ARGUMENTS_BAD
    } else {
      match get_session().lock().unwrap().get_mut() {
        Ok(enc_sess) => unsafe {
          for i in 0..ulCount {
            let a_ptr = pTemplate.add(i as usize);
            let attr_type = to_attr_type((*a_ptr).attrType);
            match attr_type {
              AttributeType::KeyType => {
                let is_rsa = enc_sess
                  .get_key_type(key_index)
                  .is_ok_and(|x| x == CryptographicAlgorithm::RSA);
                let key_type = if is_rsa {
                  cryptoki::object::KeyType::RSA
                } else {
                  cryptoki::object::KeyType::EC
                };
                copy_attr(&key_type, a_ptr, "KeyType")
              }
              AttributeType::Label => {
                let name = Vec::from(enc_sess.key_name(key_index).unwrap());
                copy_attr_bytes(&name, a_ptr, "Label")
              }
              AttributeType::Id => {
                let mut copy = Vec::from(MULTEE_KEY_ID);
                let ptr = copy.as_mut_ptr() as *mut usize;
                *ptr = hObject as usize;
                copy_attr_bytes(&copy, a_ptr, "ID")
              }
              AttributeType::Modulus => {
                let modulus = enc_sess.get_modulus(key_index).expect("Impossible: Modulus should be available, because we reported RSA key type in C_GetAttributeValue.KeyType");
                copy_attr_bytes(&modulus, a_ptr, "Modulus")
              }
              AttributeType::PublicExponent => {
                let exp = enc_sess.get_exponent(key_index).expect("Impossible: PublicExponent should be available, because we reported RSA key type in C_GetAttributeValue.KeyType");
                copy_attr_bytes(&exp, a_ptr, "PublicExponent")
              }
              AttributeType::AlwaysAuthenticate => copy_attr(&false, a_ptr, "AlwaysAuthenticate"),
              AttributeType::Class => {
                copy_attr(&cryptoki::object::ObjectClass::PRIVATE_KEY, a_ptr, "Class")
              }
              AttributeType::CertificateType => copy_attr(
                &cryptoki::object::CertificateType::X_509,
                a_ptr,
                "CertificateType",
              ),
              AttributeType::EcParams => {
                let ec_params = enc_sess.get_ec_params(key_index).expect("Impossible: EcParams should be available, because we reported EC key type in C_GetAttributeValue.KeyType");
                copy_attr_bytes(&ec_params, a_ptr, "EcParams")
              }
              AttributeType::EcPoint => {
                let ec_point = enc_sess.get_ec_point(key_index).expect("Impossible: EcParams should be available, because we reported EC key type in C_GetAttributeValue.KeyType");
                copy_attr_bytes(&ec_point, a_ptr, "EcPoint")
              }
              other => {
                log::error!("MulTee unhandled attr {:?}", other);
                return CKR_ARGUMENTS_BAD;
              }
            }
            // log::trace!("MulTee Attr type: {} {}", ulCount, AttributeType::try_from(a.attrType).unwrap());
          }
          CKR_OK
        },
        Err(e) => {
          log::error!("Unable to initialize MulTee: {}", e);
          CKR_ARGUMENTS_BAD
        }
      }
    }
  }

  unsafe fn copy_attr_bytes(bytes: &Vec<u8>, attr_ptr: *mut CK_ATTRIBUTE, msg: &str) {
    (*attr_ptr).ulValueLen = bytes.len() as CK_ULONG;
    if (*attr_ptr).pValue != std::ptr::null_mut() {
      std::ptr::copy_nonoverlapping(bytes.as_ptr(), (*attr_ptr).pValue as *mut u8, bytes.len());
      log::debug!("MulTee attr {} {} {:?}", msg, bytes.len(), bytes);
    }
  }
  unsafe fn copy_attr<T: std::fmt::Debug + Copy>(x: &T, attr_ptr: *mut CK_ATTRIBUTE, msg: &str) {
    let len = std::mem::size_of::<T>();
    (*attr_ptr).ulValueLen = len as CK_ULONG;
    if (*attr_ptr).pValue != std::ptr::null_mut() {
      *((*attr_ptr).pValue as *mut T) = T::try_from(*x).unwrap();
      log::debug!(
        "MulTee attr {} {:?} {} {:?}",
        msg,
        T::try_from(*x).unwrap(),
        len,
        (*attr_ptr).pValue
      );
    }
  }
}

pub(crate) mod sign {
  #![allow(non_camel_case_types, non_snake_case)]
  use crate::api::*;
  use crate::MULTEE_SESSION_HANDLE;
  use common::error::MulTeeErrCode;
  use common::error::MulTeeResult;
  use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsPssParams};
  use cryptoki::mechanism::{Mechanism, MechanismType};
  use cryptoki::types::Ulong;
  use kmip::enumerations::HashingAlgorithm;
  use multee_core::api::DEFAULT_SIG_PADDING;
  use multee_core::mtls::pkcss_ecdsa_sig;
  use pkcs11::types::*;
  use std::cell::RefCell;
  use std::convert::TryFrom;
  use std::sync::Mutex;

  struct SignOp {
    mech_param: Option<PkcsPssParams>,
    key_index: usize,
    md_alg: Option<HashingAlgorithm>,
    mech_type: MechanismType,
  }

  static SIGN_OP_STATE: Mutex<RefCell<Option<SignOp>>> = Mutex::new(RefCell::new(None));

  /// `C_SignInit` initializes a signature (private key encryption) operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: the signature mechanism
  /// * `hKey`: handle of signature key
  ///
  #[no_mangle]
  pub extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    log::debug!("MulTee.C_SignInit");

    let key_index = hKey as usize % MAX_KEYS;

    if hSession != MULTEE_SESSION_HANDLE {
      log::error!("MulTee CKR_SESSION_HANDLE_INVALID");
      CKR_SESSION_HANDLE_INVALID
    } else if key_index >= get_key_count() {
      log::error!("MulTee CKR_OBJECT_HANDLE_INVALID");
      CKR_OBJECT_HANDLE_INVALID
    } else if pMechanism == std::ptr::null_mut() {
      log::error!("MulTee CKR_ARGUMENTS_BAD");
      CKR_ARGUMENTS_BAD
    } else {
      unsafe {
        let mech_type = MechanismType::try_from((*pMechanism).mechanism).expect(format!("Incompatible: MulTee hasn't been tested with this brand/revision of PKCS11 user, unexpected signature mechanism type: {}",(*pMechanism).mechanism).as_str());

        match mech_type {
          // RSASSA-PSS (aka PKCS#1 v2.1).
          MechanismType::RSA_PKCS_PSS => {
            let param_ptr = (*pMechanism).pParameter as CK_RSA_PKCS_PSS_PARAMS_PTR;
            let hash_alg = (*param_ptr).hashAlg;
            let params = PkcsPssParams {
              hash_alg: MechanismType::try_from(hash_alg).expect("Incompatible: MulTee hasn't been tested with this brand/revision of PKCS11 user, unexpected PkcsPss mechanism type"),
              mgf: PkcsMgfType::try_from((*param_ptr).mgf).expect("Incompatible: MulTee hasn't been tested with this brand/revision of PKCS11 user, unexpected PkcsPss PkcsMgfType"),
              s_len: Ulong::from((*param_ptr).sLen)
            };
            let _mech = Mechanism::RsaPkcsPss(params);

            if let Ok(md_alg) = pkcs11_2_kmip_md_alg(hash_alg) {
              log::trace!(
                "MulTee RSA_PKCS_PSS hash {}, mfg {:?}, salt_len {}",
                params.hash_alg,
                params.mgf,
                params.s_len
              );
              let state = SignOp {
                mech_param: Some(params),
                key_index,
                md_alg: Some(md_alg),
                mech_type,
              };
              SIGN_OP_STATE.lock().unwrap().replace(Some(state));
              CKR_OK
            } else {
              CKR_MECHANISM_INVALID
            }
          }
          MechanismType::ECDSA => {
            let state = SignOp {
              mech_param: None,
              key_index,
              md_alg: None,
              mech_type,
            };
            SIGN_OP_STATE.lock().unwrap().replace(Some(state));
            CKR_OK
          }
          _ => {
            log::error!(
              "MulTee CKR_MECHANISM_INVALID type {}, len {}",
              mech_type,
              (*pMechanism).ulParameterLen
            );
            CKR_MECHANISM_INVALID
          }
        }
      }
    }
  }
  /// `C_Sign` signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pData`: the data to sign
  /// * `ulDataLen`: count of bytes to sign
  /// * `pSignature`: gets the signature
  /// * `pulSignatureLen`: gets signature length
  ///
  #[no_mangle]
  pub extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR,
    pulSignatureLen: CK_ULONG_PTR,
  ) -> CK_RV {
    log::debug!("MulTee.C_Sign");

    if hSession != MULTEE_SESSION_HANDLE {
      log::error!("MulTee CKR_SESSION_HANDLE_INVALID");
      CKR_SESSION_HANDLE_INVALID
    } else if pSignature == std::ptr::null_mut() || pulSignatureLen == std::ptr::null_mut() {
      log::error!("MulTee CKR_ARGUMENTS_BAD");
      CKR_ARGUMENTS_BAD
    } else if let Some(SignOp {
      mech_param,
      key_index,
      md_alg: Some(md_alg),
      mech_type,
    }) = SIGN_OP_STATE.lock().unwrap().replace(None)
    {
      match get_session().lock().unwrap().get_mut() {
        Err(e) => {
          eprintln!("Unable to initialize MulTee: {}", e);
          CKR_ARGUMENTS_BAD
        }
        Ok(enc_sess) => {
          // TODO: should not need to override. Parse instead
          let padding = mech_param.map(|_| DEFAULT_SIG_PADDING);

          let data = unsafe { std::slice::from_raw_parts(pData as *const u8, ulDataLen as usize) };

          let sig = enc_sess
            .sign_hash(key_index, padding, md_alg, data)
            .expect("Impossible: Can't sign using private key?");

          let sig = if mech_type == MechanismType::ECDSA {
            let key_length = enc_sess
              .key_len(key_index)
              .expect("Impossible: key_len_internal - internal use only")
              as usize;
            unsafe {
              pkcss_ecdsa_sig(sig, key_length)
                .expect("Impossible: parsing DER signature produce by MbedTLS using MbedTLS")
            }
          } else {
            sig
          };

          unsafe {
            *pulSignatureLen = sig.len() as CK_ULONG;
            std::ptr::copy_nonoverlapping(sig.as_ptr(), pSignature as *mut u8, sig.len());
          }
          log::trace!(
            "MulTee C_Sign OK data len {} sig len {}",
            data.len(),
            sig.len()
          );
          CKR_OK
        }
      }
    } else {
      log::error!("MulTee CKR_OPERATION_NOT_INITIALIZED");
      CKR_OPERATION_NOT_INITIALIZED
    }
  }

  fn pkcs11_2_kmip_md_alg(value: CK_MECHANISM_TYPE) -> MulTeeResult<HashingAlgorithm> {
    match value {
      CKM_SHA256 => Ok(HashingAlgorithm::SHA256),
      CKM_SHA384 => Ok(HashingAlgorithm::SHA384),
      CKM_SHA512 => Ok(HashingAlgorithm::SHA512),
      _ => {
        log::error!(
          "MulTee CKR_ARGUMENTS_BAD: CRYPTO_UNSUPPORTED_HASH {}",
          value
        );
        Err(MulTeeErrCode::CRYPTO_UNSUPPORTED_HASH.msg("Unsupported hash algorithm"))
      }
    }
  }
}

pub(crate) mod todo {
  #![allow(non_camel_case_types, non_snake_case)]

  use pkcs11::types::*;

  /// `C_GetMechanismList` obtains a list of mechanism types supported by a token.
  ///
  /// # Function Parameters
  ///
  /// * `slotID`: ID of token's slot
  /// * `pMechanismList`: gets mech. array
  /// * `pulCount`: gets # of mechs.
  ///
  #[no_mangle]
  pub extern "C" fn C_GetMechanismList(
    _slotID: CK_SLOT_ID, _pMechanismList: CK_MECHANISM_TYPE_PTR, _pulCount: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_GetMechanismList")
  }

  /// `C_GetMechanismInfo` obtains information about a particular mechanism possibly supported by a token.
  ///
  /// # Function Parameters
  ///
  /// * `slotID`: ID of the token's slot
  /// * `mechType`: type of mechanism
  /// * `pInfo`: receives mechanism info
  ///
  #[no_mangle]
  pub extern "C" fn C_GetMechanismInfo(
    _slotID: CK_SLOT_ID, _mechType: CK_MECHANISM_TYPE, _pInfo: CK_MECHANISM_INFO_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_GetMechanismInfo")
  }

  /// `C_InitToken` initializes a token.
  ///
  /// # Function Parameters
  ///
  /// * `slotID`: ID of the token's slot
  /// * `pPin`: the SO's initial PIN
  /// * `ulPinLen`: length in bytes of the PIN
  /// * `pLabel`: 32-byte token label (blank padded)
  ///
  #[no_mangle]
  pub extern "C" fn C_InitToken(
    _slotID: CK_SLOT_ID, _pPin: CK_UTF8CHAR_PTR, _ulPinLen: CK_ULONG, _pLabel: CK_UTF8CHAR_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_InitToken")
  }

  /// `C_InitPIN` initializes the normal user's PIN.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pPin`: the normal user's PIN
  /// * `ulPinLen`: length in bytes of the PIN
  ///
  pub extern "C" fn C_InitPIN(
    _hSession: CK_SESSION_HANDLE, _pPin: CK_UTF8CHAR_PTR, _ulPinLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_InitPIN")
  }

  /// `C_SetPIN` modifies the PIN of the user who is logged in.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pOldPin`: the old PIN
  /// * `ulOldLen`: length of the old PIN
  /// * `pNewPin`: the new PIN
  /// * `ulNewLen`: length of the new PIN
  ///
  #[no_mangle]
  pub extern "C" fn C_SetPIN(
    _hSession: CK_SESSION_HANDLE, _pOldPin: CK_UTF8CHAR_PTR, _ulOldLen: CK_ULONG,
    _pNewPin: CK_UTF8CHAR_PTR, _ulNewLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_SetPIN")
  }

  /// `C_CloseAllSessions` closes all sessions with a token.
  ///
  /// # Function Parameters
  ///
  /// * `slotID`: the token's slot
  ///
  #[no_mangle]
  pub extern "C" fn C_CloseAllSessions(_slotID: CK_SLOT_ID) -> CK_RV {
    todo!("MulTee.C_CloseAllSessions")
  }

  /// `C_GetSessionInfo` obtains information about the session.
  ///
  /// # Function Paramters
  ///
  /// * `hSession`: the session's handle
  /// * `pInfo`: receives session info
  ///
  pub extern "C" fn C_GetSessionInfo(
    _hSession: CK_SESSION_HANDLE, _pInfo: CK_SESSION_INFO_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_GetSessionInfo")
  }

  /// `C_GetOperationState` obtains the state of the cryptographic operation in a session.
  ///
  /// # Function Paramters
  ///
  /// * `hSession`: session's handle
  /// * `pOperationState`: gets state
  /// * `pulOperationStateLen`: gets state length
  ///
  #[no_mangle]
  pub extern "C" fn C_GetOperationState(
    _hSession: CK_SESSION_HANDLE, _pOperationState: CK_BYTE_PTR,
    _pulOperationStateLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_GetOperationState")
  }

  /// `C_SetOperationState` restores the state of the cryptographic operation in a session.
  ///
  /// # Function Paramters
  ///
  /// * `hSession`: session's handle
  /// * `pOperationState`: holds state
  /// * `ulOperationStateLen`: holds state length
  /// * `hEncryptionKey`: en/decryption key
  /// * `hAuthenticationKey`: sign/verify key
  ///
  #[no_mangle]
  pub extern "C" fn C_SetOperationState(
    _hSession: CK_SESSION_HANDLE, _pOperationState: CK_BYTE_PTR, _ulOperationStateLen: CK_ULONG,
    _hEncryptionKey: CK_OBJECT_HANDLE, _hAuthenticationKey: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    todo!("MulTee.C_SetOperationState")
  }

  /// `C_Login` logs a user into a token.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `userType`: the user type
  /// * `pPin`: the user's PIN
  /// * `ulPinLen`: the length of the PIN
  ///
  #[no_mangle]
  pub extern "C" fn C_Login(
    _hSession: CK_SESSION_HANDLE, _userType: CK_USER_TYPE, _pPin: CK_UTF8CHAR_PTR,
    _ulPinLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_Login")
  }

  /// `C_Logout` logs a user out from a token.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  #[no_mangle]
  pub extern "C" fn C_Logout(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    todo!("MulTee.C_Logout")
  }

  /// `C_CreateObject` creates a new object.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pTemplate`: the object's template
  /// * `ulCount`: attributes in template
  /// * `phObject`: gets new object's handle.
  ///
  #[no_mangle]
  pub extern "C" fn C_CreateObject(
    _hSession: CK_SESSION_HANDLE, _pTemplate: CK_ATTRIBUTE_PTR, _ulCount: CK_ULONG,
    _phObject: CK_OBJECT_HANDLE_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_CreateObject")
  }

  /// `C_CopyObject` copies an object, creating a new object for the copy.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `hObject`: the object's handle
  /// * `pTemplate`: template for new object
  /// * `ulCount`: attributes in template
  /// * `phNewObject`: receives handle of copy
  ///
  #[no_mangle]
  pub extern "C" fn C_CopyObject(
    _hSession: CK_SESSION_HANDLE, _hObject: CK_OBJECT_HANDLE, _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG, _phNewObject: CK_OBJECT_HANDLE_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_CopyObject")
  }

  /// `C_DestroyObject` destroys an object.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `hObject`: the object's handle
  ///
  pub extern "C" fn C_DestroyObject(
    _hSession: CK_SESSION_HANDLE, _hObject: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    todo!("MulTee.C_DestroyObject")
  }

  /// `C_GetObjectSize` gets the size of an object in bytes.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `hObject`: the object's handle
  /// * `pulSize`: receives size of object
  ///
  #[no_mangle]
  pub extern "C" fn C_GetObjectSize(
    _hSession: CK_SESSION_HANDLE, _hObject: CK_OBJECT_HANDLE, _pulSize: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_GetObjectSize")
  }

  /// `C_SetAttributeValue` modifies the value of one or more object attributes.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `hObject`: the object's handle
  /// * `pTemplate`: specifies attrs and values
  /// * `ulCount`: attributes in template
  ///
  #[no_mangle]
  pub extern "C" fn C_SetAttributeValue(
    _hSession: CK_SESSION_HANDLE, _hObject: CK_OBJECT_HANDLE, _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_SetAttributeValue")
  }

  /// `C_EncryptInit` initializes an encryption operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: the encryption mechanism
  /// * `hKey`: handle of encryption key
  ///
  #[no_mangle]
  pub extern "C" fn C_EncryptInit(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    todo!("MulTee.C_EncryptInit")
  }

  /// `C_Encrypt` encrypts single-part data.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pData`: the plaintext data
  /// * `ulDataLen`: bytes of plaintext
  /// * `pEncryptedData`: gets ciphertext
  /// * `pulEncryptedDataLen`: gets c-text size
  ///
  #[no_mangle]
  pub extern "C" fn C_Encrypt(
    _hSession: CK_SESSION_HANDLE, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG,
    _pEncryptedData: CK_BYTE_PTR, _pulEncryptedDataLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_Encrypt")
  }

  /// `C_EncryptUpdate` continues a multiple-part encryption operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pPart`: the plaintext data
  /// * `ulPartLen`: plaintext data len
  /// * `pEncryptedPart`: gets ciphertext
  /// * `pulEncryptedPartLen`: gets c-text size
  ///
  #[no_mangle]
  pub extern "C" fn C_EncryptUpdate(
    _hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG,
    _pEncryptedPart: CK_BYTE_PTR, _pulEncryptedPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_EncryptUpdate")
  }

  /// `C_EncryptFinal` finishes a multiple-part encryption operation
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session handle
  /// * `pLastEncryptedPart` last c-text
  /// * `pulLastEncryptedPartLen`: gets last size
  ///
  #[no_mangle]
  pub extern "C" fn C_EncryptFinal(
    _hSession: CK_SESSION_HANDLE, _pLastEncryptedPart: CK_BYTE_PTR,
    _pulLastEncryptedPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_EncryptFinal")
  }

  /// `C_DecryptInit` initializes a decryption operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: the decryption mechanism
  /// * `hKey`: handle of decryption key
  ///
  #[no_mangle]
  pub extern "C" fn C_DecryptInit(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    todo!("MulTee.C_DecryptInit")
  }

  /// `C_Decrypt` decrypts encrypted data in a single part.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pEncryptedData`: ciphertext
  /// * `ulEncryptedDataLen`: ciphertext length
  /// * `pData`: gets plaintext
  /// * `pulDataLen`: gets p-text size
  ///
  #[no_mangle]
  pub extern "C" fn C_Decrypt(
    _hSession: CK_SESSION_HANDLE, _pEncryptedData: CK_BYTE_PTR, _ulEncryptedDataLen: CK_ULONG,
    _pData: CK_BYTE_PTR, _pulDataLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_Decrypt")
  }

  /// `C_DecryptUpdate` continues a multiple-part decryption operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pEncryptedPart`: encrypted data
  /// * `ulEncryptedPartLen`: input length
  /// * `pPart`: gets plaintext
  /// * `pulPartLen`: p-text size
  ///
  #[no_mangle]
  pub extern "C" fn C_DecryptUpdate(
    _hSession: CK_SESSION_HANDLE, _pEncryptedPart: CK_BYTE_PTR, _ulEncryptedPartLen: CK_ULONG,
    _pPart: CK_BYTE_PTR, _pulPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DecryptUpdate")
  }

  /// `C_DecryptFinal` finishes a multiple-part decryption operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pLastPart`: gets plaintext
  /// * `pulLastPartLen`: p-text size
  ///
  #[no_mangle]
  pub extern "C" fn C_DecryptFinal(
    _hSession: CK_SESSION_HANDLE, _pLastPart: CK_BYTE_PTR, _pulLastPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DecryptFinal")
  }

  /// `C_DigestInit` initializes a message-digesting operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: the digesting mechanism
  ///
  pub extern "C" fn C_DigestInit(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DigestInit")
  }

  /// `C_Digest` digests data in a single part.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pData`: data to be digested
  /// * `ulDataLen`: bytes of data to digest
  /// * `pDigest`: gets the message digest
  /// * `pulDigestLen`: gets digest length
  ///
  #[no_mangle]
  pub extern "C" fn C_Digest(
    _hSession: CK_SESSION_HANDLE, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG, _pDigest: CK_BYTE_PTR,
    _pulDigestLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_Digest")
  }

  /// `C_DigestUpdate` continues a multiple-part message-digesting operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pPart`: data to be digested
  /// * `ulPartLen`: bytes of data to be digested
  ///
  pub extern "C" fn C_DigestUpdate(
    _hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_DigestUpdate")
  }

  /// `C_DigestKey` continues a multi-part message-digesting operation, by digesting the value of a secret key as part of the data already digested.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `hKey`: secret key to digest
  #[no_mangle]
  pub extern "C" fn C_DigestKey(_hSession: CK_SESSION_HANDLE, _hKey: CK_OBJECT_HANDLE) -> CK_RV {
    todo!("MulTee.C_DigestKey")
  }

  /// `C_DigestFinal` finishes a multiple-part message-digesting operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pDigest`: gets the message digest
  /// * `pulDigestLen`: gets byte count of digest
  ///
  #[no_mangle]
  pub extern "C" fn C_DigestFinal(
    _hSession: CK_SESSION_HANDLE, _pDigest: CK_BYTE_PTR, _pulDigestLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DigestFinal")
  }

  /// `C_SignUpdate` continues a multiple-part signature operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pPart`: the data to sign
  /// * `ulPartLen`: count of bytes to sign
  ///
  pub extern "C" fn C_SignUpdate(
    _hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_SignUpdate")
  }

  /// `C_SignFinal` finishes a multiple-part signature operation, returning the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pSignature`: gets the signature
  /// * `pulSignatureLen`: gets signature length
  ///
  #[no_mangle]
  pub extern "C" fn C_SignFinal(
    _hSession: CK_SESSION_HANDLE, _pSignature: CK_BYTE_PTR, _pulSignatureLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_SignFinal")
  }

  /// `C_SignRecoverInit` initializes a signature operation, where the data can be recovered from the signature.
  /// `hSession`: the session's handle
  /// `pMechanism`: the signature mechanism
  /// `hKey`: handle of the signature key
  #[no_mangle]
  pub extern "C" fn C_SignRecoverInit(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    todo!("MulTee.C_SignRecoverInit")
  }

  /// `C_SignRecover` signs data in a single operation, where the data can be recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pData`: the data to sign
  /// * `ulDataLen`: count of bytes to sign
  /// * `pSignature`: gets the signature
  /// * `pulSignatureLen`: gets signature length
  ///
  #[no_mangle]
  pub extern "C" fn C_SignRecover(
    _hSession: CK_SESSION_HANDLE, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG,
    _pSignature: CK_BYTE_PTR, _pulSignatureLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_SignRecover")
  }

  /// `C_VerifyInit` initializes a verification operation, where the signature is an appendix to the data, and plaintext cannot cannot be recovered from the signature (e.g. DSA).
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: the verification mechanism
  /// * `hKey`: verification key
  ///
  #[no_mangle]
  pub extern "C" fn C_VerifyInit(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    todo!("MulTee.C_VerifyInit")
  }

  /// `C_Verify` verifies a signature in a single-part operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pData`: signed data
  /// * `ulDataLen`: length of signed data
  /// * `pSignature`: signature
  /// * `ulSignatureLen`: signature length
  ///
  #[no_mangle]
  pub extern "C" fn C_Verify(
    _hSession: CK_SESSION_HANDLE, _pData: CK_BYTE_PTR, _ulDataLen: CK_ULONG,
    _pSignature: CK_BYTE_PTR, _ulSignatureLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_Verify")
  }

  /// `C_VerifyUpdate` continues a multiple-part verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pPart`: signed data
  /// * `ulPartLen`: length of signed data
  ///
  pub extern "C" fn C_VerifyUpdate(
    _hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_VerifyUpdate")
  }

  /// `C_VerifyFinal` finishes a multiple-part verification operation, checking the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pSignature`: signature to verify
  /// * `ulSignatureLen`: signature length
  ///
  #[no_mangle]
  pub extern "C" fn C_VerifyFinal(
    _hSession: CK_SESSION_HANDLE, _pSignature: CK_BYTE_PTR, _ulSignatureLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_VerifyFinal")
  }

  /// `C_VerifyRecoverInit` initializes a signature verification operation, where the data is recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: the verification mechanism
  /// * `hKey`: verification key
  ///
  #[no_mangle]
  pub extern "C" fn C_VerifyRecoverInit(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hKey: CK_OBJECT_HANDLE,
  ) -> CK_RV {
    todo!("MulTee.C_VerifyRecoverInit")
  }

  /// `C_VerifyRecover` verifies a signature in a single-part operation, where the data is recovered from the signature.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pSignature`: signature to verify
  /// * `ulSignatureLen`: signature length
  /// * `pData`: gets signed data
  /// * `pulDataLen`: gets signed data len
  ///
  #[no_mangle]
  pub extern "C" fn C_VerifyRecover(
    _hSession: CK_SESSION_HANDLE, _pSignature: CK_BYTE_PTR, _ulSignatureLen: CK_ULONG,
    _pData: CK_BYTE_PTR, _pulDataLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_VerifyRecover")
  }

  /// `C_DigestEncryptUpdate` continues a multiple-part digesting and encryption operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pPart`: the plaintext data
  /// * `ulPartLen`: plaintext length
  /// * `pEncryptedPart`: gets ciphertext
  /// * `pulEncryptedPartLen`: gets c-text length
  ///
  #[no_mangle]
  pub extern "C" fn C_DigestEncryptUpdate(
    _hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG,
    _pEncryptedPart: CK_BYTE_PTR, _pulEncryptedPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DigestEncryptUpdate")
  }

  /// `C_DecryptDigestUpdate` continues a multiple-part decryption and digesting operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pEncryptedPart`: ciphertext
  /// * `ulEncryptedPartLen`: ciphertext length
  /// * `pPart:`: gets plaintext
  /// * `pulPartLen`: gets plaintext len
  ///
  #[no_mangle]
  pub extern "C" fn C_DecryptDigestUpdate(
    _hSession: CK_SESSION_HANDLE, _pEncryptedPart: CK_BYTE_PTR, _ulEncryptedPartLen: CK_ULONG,
    _pPart: CK_BYTE_PTR, _pulPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DecryptDigestUpdate")
  }

  /// `C_SignEncryptUpdate` continues a multiple-part signing and encryption operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pPart`: the plaintext data
  /// * `ulPartLen`: plaintext length
  /// * `pEncryptedPart`: gets ciphertext
  /// * `pulEncryptedPartLen`: gets c-text length
  ///
  #[no_mangle]
  pub extern "C" fn C_SignEncryptUpdate(
    _hSession: CK_SESSION_HANDLE, _pPart: CK_BYTE_PTR, _ulPartLen: CK_ULONG,
    _pEncryptedPart: CK_BYTE_PTR, _pulEncryptedPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_SignEncryptUpdate")
  }

  /// `C_DecryptVerifyUpdate` continues a multiple-part decryption and verify operation.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pEncryptedPart`: ciphertext
  /// * `ulEncryptedPartLen`: ciphertext length
  /// * `pPart`: gets plaintext
  /// * `pulPartLen`: gets p-text length
  ///
  #[no_mangle]
  pub extern "C" fn C_DecryptVerifyUpdate(
    _hSession: CK_SESSION_HANDLE, _pEncryptedPart: CK_BYTE_PTR, _ulEncryptedPartLen: CK_ULONG,
    _pPart: CK_BYTE_PTR, _pulPartLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DecryptVerifyUpdate")
  }

  /// `C_GenerateKey` generates a secret key, creating a new key object.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: key generation mech.
  /// * `pTemplate`: template for new key
  /// * `ulCount`: # of attrs in template
  /// * `phKey`: gets handle of new key
  ///
  #[no_mangle]
  pub extern "C" fn C_GenerateKey(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG, _phKey: CK_OBJECT_HANDLE_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_GenerateKey")
  }

  /// `C_GenerateKeyPair` generates a public-key/private-key pair, creating new key objects.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session handle
  /// * `pMechanism`: key-gen mech.
  /// * `pPublicKeyTemplate`: template for pub. key
  /// * `ulPublicKeyAttributeCount`: # pub. attrs.
  /// * `pPrivateKeyTemplate`: template for priv. key
  /// * `ulPrivateKeyAttributeCount`: # priv.  attrs.
  /// * `phPublicKey`: gets pub. key handle
  /// * `phPrivateKey`: gets priv. key handle
  ///
  #[no_mangle]
  pub extern "C" fn C_GenerateKeyPair(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR,
    _pPublicKeyTemplate: CK_ATTRIBUTE_PTR, _ulPublicKeyAttributeCount: CK_ULONG,
    _pPrivateKeyTemplate: CK_ATTRIBUTE_PTR, _ulPrivateKeyAttributeCount: CK_ULONG,
    _phPublicKey: CK_OBJECT_HANDLE_PTR, _phPrivateKey: CK_OBJECT_HANDLE_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_GenerateKeyPair")
  }

  /// `C_WrapKey` wraps (i.e., encrypts) a key.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pMechanism`: the wrapping mechanism
  /// * `hWrappingKey`: wrapping key
  /// * `hKey`: key to be wrapped
  /// * `pWrappedKey`: gets wrapped key
  /// * `pulWrappedKeyLen`: gets wrapped key size
  ///
  #[no_mangle]
  pub extern "C" fn C_WrapKey(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hWrappingKey: CK_OBJECT_HANDLE,
    _hKey: CK_OBJECT_HANDLE, _pWrappedKey: CK_BYTE_PTR, _pulWrappedKeyLen: CK_ULONG_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_WrapKey")
  }

  /// `C_UnwrapKey` unwraps (decrypts) a wrapped key, creating a new key object.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pMechanism`: unwrapping mech.
  /// * `hUnwrappingKey`: unwrapping key
  /// * `pWrappedKey`: the wrapped key
  /// * `ulWrappedKeyLen`: wrapped key len
  /// * `pTemplate`: new key template
  /// * `ulAttributeCount`: template length
  /// * `phKey`: gets new handle
  ///
  #[no_mangle]
  pub extern "C" fn C_UnwrapKey(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hUnwrappingKey: CK_OBJECT_HANDLE,
    _pWrappedKey: CK_BYTE_PTR, _ulWrappedKeyLen: CK_ULONG, _pTemplate: CK_ATTRIBUTE_PTR,
    _ulAttributeCount: CK_ULONG, _phKey: CK_OBJECT_HANDLE_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_UnwrapKey")
  }

  /// `C_DeriveKey` derives a key from a base key, creating a new key object.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: session's handle
  /// * `pMechanism`: key deriv. mech.
  /// * `hBaseKey`: base key
  /// * `pTemplate`: new key template
  /// * `ulAttributeCount`: template length
  /// * `phKey`: gets new handle
  ///
  #[no_mangle]
  pub extern "C" fn C_DeriveKey(
    _hSession: CK_SESSION_HANDLE, _pMechanism: CK_MECHANISM_PTR, _hBaseKey: CK_OBJECT_HANDLE,
    _pTemplate: CK_ATTRIBUTE_PTR, _ulAttributeCount: CK_ULONG, _phKey: CK_OBJECT_HANDLE_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_DeriveKey")
  }

  /// `C_SeedRandom` mixes additional seed material into the token's random number generator.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `pSeed`: the seed material
  /// * `ulSeedLen`: length of seed material
  ///
  pub extern "C" fn C_SeedRandom(
    _hSession: CK_SESSION_HANDLE, _pSeed: CK_BYTE_PTR, _ulSeedLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_SeedRandom")
  }

  /// `C_GenerateRandom` generates random data.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  /// * `RandomData`: receives the random data
  /// * `ulRandomLen`: # of bytes to generate
  ///
  #[no_mangle]
  pub extern "C" fn C_GenerateRandom(
    _hSession: CK_SESSION_HANDLE, _RandomData: CK_BYTE_PTR, _ulRandomLen: CK_ULONG,
  ) -> CK_RV {
    todo!("MulTee.C_GenerateRandom")
  }

  /// `C_GetFunctionStatus` is a legacy function; it obtains an updated status of a function running in parallel with an application.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  ///
  #[no_mangle]
  pub extern "C" fn C_GetFunctionStatus(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    todo!("MulTee.C_GetFunctionStatus")
  }

  /// `C_CancelFunction` is a legacy function; it cancels a function running in parallel.
  ///
  /// # Function Parameters
  ///
  /// * `hSession`: the session's handle
  ///
  #[no_mangle]
  pub extern "C" fn C_CancelFunction(_hSession: CK_SESSION_HANDLE) -> CK_RV {
    todo!("MulTee.C_CancelFunction")
  }

  /// `C_WaitForSlotEvent` waits for a slot event (token insertion, removal, etc.) to occur.
  ///
  /// # Function Parameters
  ///
  /// * `flags`: blocking/nonblocking flag
  /// * `pSlot`: location that receives the slot ID
  /// * `pRserved`: reserved.  Should be NULL_PTR
  ///
  pub extern "C" fn C_WaitForSlotEvent(
    _flags: CK_FLAGS, _pSlot: CK_SLOT_ID_PTR, _pRserved: CK_VOID_PTR,
  ) -> CK_RV {
    todo!("MulTee.C_WaitForSlotEvent")
  }
}
