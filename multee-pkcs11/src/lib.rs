pub mod api;

use crate::api::{findobject, getattribute, sign, todo};
use pkcs11::types::padding::{
  BlankPaddedString16, BlankPaddedUtf8String16, BlankPaddedUtf8String32, BlankPaddedUtf8String64,
};
use pkcs11::types::{
  CKF_CLOCK_ON_TOKEN, CKF_DUAL_CRYPTO_OPERATIONS, CKF_HW_SLOT, CKF_PROTECTED_AUTHENTICATION_PATH,
  CKF_RESTORE_KEY_NOT_NEEDED, CKF_RNG, CKF_TOKEN_INITIALIZED, CKF_TOKEN_PRESENT,
  CKF_USER_PIN_INITIALIZED, CK_FLAGS, CK_FUNCTION_LIST, CK_INFO, CK_SESSION_HANDLE, CK_SLOT_ID,
  CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_UTF8CHAR, CK_VERSION,
};

const MULTEE_SLOT_ID: CK_SLOT_ID = 1;
pub(crate) const MULTEE_SESSION_HANDLE: CK_SESSION_HANDLE = 1;
const MULTEE_PKCS11_VERSION: CK_VERSION = CK_VERSION {
  major: 2,
  minor: 40,
};
const MULTEE_SW_VER: CK_VERSION = CK_VERSION { major: 0, minor: 1 };
const MULTEE_TOKEN_FLAGS: CK_FLAGS = CKF_RNG
  | CKF_USER_PIN_INITIALIZED
  | CKF_CLOCK_ON_TOKEN
  | CKF_TOKEN_INITIALIZED
  | CKF_PROTECTED_AUTHENTICATION_PATH
  | CKF_DUAL_CRYPTO_OPERATIONS
  | CKF_RESTORE_KEY_NOT_NEEDED;
const MULTEE_SLOT_FLAGS: CK_FLAGS = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
const BLANK: CK_UTF8CHAR = 32;
static MULTEE_MANUFACTURER: [CK_UTF8CHAR; 32] = [
  0x6d, 0x75, 0x6c, 0x74, 0x65, 0x2e, 0x63, 0x63, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK,
];
static MULTEE_DESCR: [CK_UTF8CHAR; 32] = [
  0x4d, 0x75, 0x6c, 0x54, 0x65, 0x65, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK,
];
static MULTEE_LABEL: [CK_UTF8CHAR; 32] = [
  0x6d, 0x75, 0x6c, 0x74, 0x65, 0x65, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, 32, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK,
];
pub(crate) static MULTEE_KEY_ID: [CK_UTF8CHAR; 20] =
  [0, 99, 1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2, 1, 99];
static MULTEE_MODEL: [CK_UTF8CHAR; 16] = [
  0x6d, 0x75, 0x6c, 0x74, 0x65, 0x65, 0x2d, 0x70, 0x6b, 0x63, 0x73, 0x31, 0x31, BLANK, BLANK, BLANK,
];
static MULTEE_SERIAL: [CK_UTF8CHAR; 16] = [
  0x75, 0x6e, 0x69, 0x71, 0x75, 0x65, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK,
];
static MULTEE_SLOT_DESCR: [CK_UTF8CHAR; 64] = [
  0x4d, 0x75, 0x6c, 0x54, 0x65, 0x65, 0x20, 0x50, 0x4b, 0x43, 0x53, 0x23, 0x31, 0x31, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
  BLANK, BLANK, BLANK, BLANK, BLANK, BLANK,
];
const MULTEE_MAX_SESS_COUNT: CK_ULONG = 1000;
const MULTEE_FREE_MEM: CK_ULONG = 10 * 1024 * 1024;
static mut PKCS11_FUNCTIONS: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
  version: MULTEE_PKCS11_VERSION,
  C_Initialize: Some(api::C_Initialize),
  C_Finalize: Some(api::C_Finalize),
  C_GetInfo: Some(api::C_GetInfo),
  C_GetFunctionList: Some(api::C_GetFunctionList),
  C_GetSlotList: Some(api::C_GetSlotList),
  C_GetSlotInfo: Some(api::C_GetSlotInfo),
  C_GetTokenInfo: Some(api::C_GetTokenInfo),
  C_GetMechanismList: Some(todo::C_GetMechanismList),
  C_GetMechanismInfo: Some(todo::C_GetMechanismInfo),
  C_InitToken: Some(todo::C_InitToken),
  C_InitPIN: Some(todo::C_InitPIN),
  C_SetPIN: Some(todo::C_SetPIN),
  C_OpenSession: Some(api::C_OpenSession),
  C_CloseSession: Some(api::C_CloseSession),
  C_CloseAllSessions: Some(todo::C_CloseAllSessions),
  C_GetSessionInfo: Some(todo::C_GetSessionInfo),
  C_GetOperationState: Some(todo::C_GetOperationState),
  C_SetOperationState: Some(todo::C_SetOperationState),
  C_Login: Some(todo::C_Login),
  C_Logout: Some(todo::C_Logout),
  C_CreateObject: Some(todo::C_CreateObject),
  C_CopyObject: Some(todo::C_CopyObject),
  C_DestroyObject: Some(todo::C_DestroyObject),
  C_GetObjectSize: Some(todo::C_GetObjectSize),
  C_GetAttributeValue: Some(getattribute::C_GetAttributeValue),
  C_SetAttributeValue: Some(todo::C_SetAttributeValue),
  C_FindObjectsInit: Some(findobject::C_FindObjectsInit),
  C_FindObjects: Some(findobject::C_FindObjects),
  C_FindObjectsFinal: Some(findobject::C_FindObjectsFinal),
  C_EncryptInit: Some(todo::C_EncryptInit),
  C_Encrypt: Some(todo::C_Encrypt),
  C_EncryptUpdate: Some(todo::C_EncryptUpdate),
  C_EncryptFinal: Some(todo::C_EncryptFinal),
  C_DecryptInit: Some(todo::C_DecryptInit),
  C_Decrypt: Some(todo::C_Decrypt),
  C_DecryptUpdate: Some(todo::C_DecryptUpdate),
  C_DecryptFinal: Some(todo::C_DecryptFinal),
  C_DigestInit: Some(todo::C_DigestInit),
  C_Digest: Some(todo::C_Digest),
  C_DigestUpdate: Some(todo::C_DigestUpdate),
  C_DigestKey: Some(todo::C_DigestKey),
  C_DigestFinal: Some(todo::C_DigestFinal),
  C_SignInit: Some(sign::C_SignInit),
  C_Sign: Some(sign::C_Sign),
  C_SignUpdate: Some(todo::C_SignUpdate),
  C_SignFinal: Some(todo::C_SignFinal),
  C_SignRecoverInit: Some(todo::C_SignRecoverInit),
  C_SignRecover: Some(todo::C_SignRecover),
  C_VerifyInit: Some(todo::C_VerifyInit),
  C_Verify: Some(todo::C_Verify),
  C_VerifyUpdate: Some(todo::C_VerifyUpdate),
  C_VerifyFinal: Some(todo::C_VerifyFinal),
  C_VerifyRecoverInit: Some(todo::C_VerifyRecoverInit),
  C_VerifyRecover: Some(todo::C_VerifyRecover),
  C_DigestEncryptUpdate: Some(todo::C_DigestEncryptUpdate),
  C_DecryptDigestUpdate: Some(todo::C_DecryptDigestUpdate),
  C_SignEncryptUpdate: Some(todo::C_SignEncryptUpdate),
  C_DecryptVerifyUpdate: Some(todo::C_DecryptVerifyUpdate),
  C_GenerateKey: Some(todo::C_GenerateKey),
  C_GenerateKeyPair: Some(todo::C_GenerateKeyPair),
  C_WrapKey: Some(todo::C_WrapKey),
  C_UnwrapKey: Some(todo::C_UnwrapKey),
  C_DeriveKey: Some(todo::C_DeriveKey),
  C_SeedRandom: Some(todo::C_SeedRandom),
  C_GenerateRandom: Some(todo::C_GenerateRandom),
  C_GetFunctionStatus: Some(todo::C_GetFunctionStatus),
  C_CancelFunction: Some(todo::C_CancelFunction),
  C_WaitForSlotEvent: Some(todo::C_WaitForSlotEvent),
};
static mut MULTEE_CK_INFO: CK_INFO = CK_INFO {
  cryptokiVersion: MULTEE_PKCS11_VERSION, /* Cryptoki interface ver */
  manufacturerID: BlankPaddedUtf8String32(MULTEE_MANUFACTURER), /* blank padded */
  flags: 0,                               /* must be zero */
  libraryDescription: BlankPaddedUtf8String32(MULTEE_DESCR), /* blank padded */
  libraryVersion: MULTEE_SW_VER,          /* version of library */
};
static mut MULTEE_SLOT_INFO: CK_SLOT_INFO = CK_SLOT_INFO {
  slotDescription: BlankPaddedUtf8String64(MULTEE_SLOT_DESCR), /* blank padded */
  manufacturerID: BlankPaddedUtf8String32(MULTEE_MANUFACTURER), /* blank padded */
  flags: MULTEE_SLOT_FLAGS,
  hardwareVersion: MULTEE_SW_VER, /* version of hardware */
  firmwareVersion: MULTEE_SW_VER, /* version of firmware */
};
static mut MULTEE_TOKEN_INFO: CK_TOKEN_INFO = CK_TOKEN_INFO {
  label: BlankPaddedUtf8String32(MULTEE_LABEL), /* blank padded */
  manufacturerID: BlankPaddedUtf8String32(MULTEE_MANUFACTURER), /* blank padded */
  model: BlankPaddedUtf8String16(MULTEE_MODEL), /* blank padded */
  serialNumber: BlankPaddedString16(MULTEE_SERIAL), /* blank padded */
  flags: MULTEE_TOKEN_FLAGS,                    /* see below */
  ulMaxSessionCount: MULTEE_MAX_SESS_COUNT,     /* max open sessions */
  ulSessionCount: MULTEE_MAX_SESS_COUNT,        /* sess. now open */
  ulMaxRwSessionCount: MULTEE_MAX_SESS_COUNT,   /* max R/W sessions */
  ulRwSessionCount: MULTEE_MAX_SESS_COUNT,      /* R/W sess. now open */
  ulMaxPinLen: 40960,                           /* in bytes */
  ulMinPinLen: 4,                               /* in bytes */
  ulTotalPublicMemory: MULTEE_FREE_MEM,         /* in bytes */
  ulFreePublicMemory: MULTEE_FREE_MEM,          /* in bytes */
  ulTotalPrivateMemory: MULTEE_FREE_MEM,        /* in bytes */
  ulFreePrivateMemory: MULTEE_FREE_MEM,         /* in bytes */
  hardwareVersion: MULTEE_SW_VER,               /* version of hardware */
  firmwareVersion: MULTEE_SW_VER,               /* version of firmware */
  utcTime: [32; 16],                            /* time */
};
