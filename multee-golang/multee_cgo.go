package multee

/*
#cgo LDFLAGS: -lmultee_cgo -L. -ldl -lm
#include "multee.h"
*/
import "C"
import (
	"unsafe"
)

// TODO: -lssl -lcrypto are needed because of Rust sev-snp-utilities, revisit

func destroyEnclave(sessionId uint64) {
	C.multee_destroy(C.ulong(sessionId))
}

func loadKeys(uri string, keyNames []string, credsZip string) (uint64, error) {
	uriCStr := C.CString(uri)
	defer C.free(unsafe.Pointer(uriCStr))
	credsZipCStr := C.CString(credsZip)
	defer C.free(unsafe.Pointer(credsZipCStr))

	keyNamesCArr := C.malloc(C.size_t(len(keyNames)) * C.sizeof_uintptr_t)
	keyNamesCArr_ := (*[1 << 30]*C.char)(keyNamesCArr)
	for i, keyName := range keyNames {
		keyNamesCArr_[i] = C.CString(keyName)
	}
	sessionId, err := rustLong(C.multee_load_keys(uriCStr, (**C.char)(keyNamesCArr), C.ulong(len(keyNames)), credsZipCStr))
	for i := range keyNames {
		C.free(unsafe.Pointer(keyNamesCArr_[i]))
	}
	C.free(keyNamesCArr)
	return sessionId, err
}

func fromBool(v bool) C.ulong {
	if v {
		return 1
	} else {
		return 0
	}
}

func keyLength(sessionId uint64, keyIndex int) (uint64, error) {

	return rustLong(C.multee_key_length(C.ulong(sessionId), C.ulong(keyIndex)))
}

func cryptCBC(sessionId uint64, keyIndex int, encrypt bool, input []byte, iv *[]byte) ([]byte, []byte, error) {

	ivCArr := C.malloc(C.size_t(CONST_MULTEE_BLOCK_SIZE))
	defer C.free(ivCArr)

	if iv != nil {
		copy((*[1 << 30]byte)(ivCArr)[:], (*iv)[:])
	}

	inputLen := len(input)
	cryptoBuf := C.malloc(C.size_t(inputLen + CONST_MULTEE_BLOCK_SIZE))
	defer C.free(cryptoBuf)
	copy((*[1 << 30]byte)(cryptoBuf)[:], input)

	outLen, err := rustLong(C.multee_crypt_cbc(C.ulong(sessionId),
		C.ulong(keyIndex),
		fromBool(encrypt),
		fromBool(iv != nil),
		(*C.uint8_t)(ivCArr),
		(*C.uint8_t)(cryptoBuf),
		C.ulong(inputLen)))
	if err != nil {
		return nil, nil, err
	}
	return C.GoBytes(cryptoBuf, C.int(outLen)), C.GoBytes(ivCArr, CONST_MULTEE_BLOCK_SIZE), nil
}

func encryptGCM(sessionId uint64, keyIndex int, input []byte, aad *[]byte) ([]byte, []byte, []byte, error) {

	ivCArr := C.malloc(C.size_t(CONST_MULTEE_GCM_IV_BYTES))
	defer C.free(ivCArr)

	tagCArr := C.malloc(C.size_t(CONST_MULTEE_GCM_TAG_BYTES))
	defer C.free(tagCArr)

	inputLen := len(input)
	cryptoBuf := C.malloc(C.size_t(inputLen))
	defer C.free(cryptoBuf)
	copy((*[1 << 30]byte)(cryptoBuf)[:], input)

	aadLen := optionalLen(aad)
	var aadPtr *C.uint8_t
	if aad != nil {

		aadBuf := C.malloc(C.size_t(aadLen))
		defer C.free(aadBuf)
		copy((*[1 << 30]byte)(aadBuf)[:], *aad)
		aadPtr = (*C.uint8_t)(aadBuf)
	} else {
		aadPtr = (*C.uint8_t)(nil)
	}

	err := rustUnit(C.multee_crypt_gcm(
		C.ulong(sessionId),
		C.ulong(keyIndex),
		fromBool(true),
		aadPtr, aadLen,
		(*C.uint8_t)(cryptoBuf), C.ulong(inputLen),
		(*C.uint8_t)(ivCArr),
		(*C.uint8_t)(tagCArr)))

	if err != nil {
		return nil, nil, nil, err
	}
	return C.GoBytes(cryptoBuf, C.int(inputLen)), C.GoBytes(ivCArr, CONST_MULTEE_GCM_IV_BYTES), C.GoBytes(tagCArr, CONST_MULTEE_GCM_TAG_BYTES), nil
}

func decryptGCM(sessionId uint64, keyIndex int, input []byte, iv []byte, tag []byte, aad *[]byte) ([]byte, error) {

	ivCArr := C.malloc(C.size_t(CONST_MULTEE_GCM_IV_BYTES))
	defer C.free(ivCArr)
	copy((*[1 << 30]byte)(ivCArr)[:], iv)

	tagCArr := C.malloc(C.size_t(CONST_MULTEE_GCM_TAG_BYTES))
	defer C.free(tagCArr)
	copy((*[1 << 30]byte)(tagCArr)[:], tag)

	inputLen := len(input)
	cryptoBuf := C.malloc(C.size_t(inputLen))
	defer C.free(cryptoBuf)
	copy((*[1 << 30]byte)(cryptoBuf)[:], input)

	aadLen := optionalLen(aad)
	var aadPtr *C.uint8_t
	if aad != nil {

		aadBuf := C.malloc(C.size_t(aadLen))
		defer C.free(aadBuf)
		copy((*[1 << 30]byte)(aadBuf)[:], *aad)
		aadPtr = (*C.uint8_t)(aadBuf)
	} else {
		aadPtr = (*C.uint8_t)(nil)
	}

	err := rustUnit(C.multee_crypt_gcm(
		C.ulong(sessionId),
		C.ulong(keyIndex),
		fromBool(false),
		aadPtr, aadLen,
		(*C.uint8_t)(cryptoBuf), C.ulong(inputLen),
		(*C.uint8_t)(ivCArr),
		(*C.uint8_t)(tagCArr)))

	if err != nil {
		return nil, err
	}
	return C.GoBytes(cryptoBuf, C.int(inputLen)), nil
}

func hmacSHA256(sessionId uint64, keyIndex int, input []byte) ([]byte, error) {
	inputBuf := C.malloc(C.size_t(len(input)))
	defer C.free(inputBuf)
	copy((*[1 << 30]byte)(inputBuf)[:], input)

	outputBuf := C.malloc(C.size_t(CONST_MULTEE_HMAC256_BYTES))

	err := rustUnit(C.multee_hmac_sha256(C.ulong(sessionId),
		C.ulong(keyIndex),
		(*C.uint8_t)(inputBuf),
		C.ulong(len(input)),
		(*C.uint8_t)(outputBuf)))
	if err != nil {
		return nil, err
	}
	return C.GoBytes(outputBuf, C.int(CONST_MULTEE_HMAC256_BYTES)), nil
}

func sign(sessionId uint64, keyIndex int, input []byte) ([]byte, error) {
	inputBuf := C.malloc(C.size_t(len(input)))
	defer C.free(inputBuf)
	copy((*[1 << 30]byte)(inputBuf)[:], input)

	outputBuf := C.malloc(C.size_t(CONST_MULTEE_SIG_LEN_MAX))
	var outputLen C.size_t

	err := rustUnit(C.multee_sign(C.ulong(sessionId),
		C.ulong(keyIndex),
		(*C.uint8_t)(inputBuf),
		C.ulong(len(input)),
		(*C.uint8_t)(outputBuf),
		&outputLen))
	if err != nil {
		return nil, err
	}
	return C.GoBytes(outputBuf, C.int(outputLen)), nil
}

func verify(sessionId uint64, keyIndex int, message []byte, signature []byte) (bool, error) {
	messageBuf := C.malloc(C.size_t(len(message)))
	defer C.free(messageBuf)
	copy((*[1 << 30]byte)(messageBuf)[:], message)

	signatureBuf := C.malloc(C.size_t(len(signature)))
	defer C.free(signatureBuf)
	copy((*[1 << 30]byte)(signatureBuf)[:], signature)

	res, err := rustBool(C.multee_verify(C.ulong(sessionId),
		C.ulong(keyIndex),
		(*C.uint8_t)(messageBuf),
		C.ulong(len(message)),
		(*C.uint8_t)(signatureBuf),
		C.ulong(len(signature))))
	if err != nil {
		return false, err
	}
	return res, nil
}

func rustLong(val C.struct_RustLong) (uint64, error) {
	if val.status != 0 {
		if val.msg != nil {
			defer C.multee_free_rust_str(val.msg)
		}
		return 0, NewMulTeeError(int(val.status), int(val.sub), C.GoString(val.msg))
	}
	return uint64(val.val), nil
}

func rustUnit(val C.struct_RustUnit) error {

	if val.status != 0 {
		if val.msg != nil {
			defer C.multee_free_rust_str(val.msg)
		}
		return NewMulTeeError(int(val.status), int(val.sub), C.GoString(val.msg))
	} else {
		return nil
	}
}

func rustBool(val C.struct_RustBool) (bool, error) {

	if val.status != 0 {
		if val.msg != nil {
			defer C.multee_free_rust_str(val.msg)
		}
		return false, NewMulTeeError(int(val.status), int(val.sub), C.GoString(val.msg))
	} else {
		if val.val != 0 {
			return true, nil
		} else {
			return false, nil
		}
	}
}

//func rustString(val C.struct_RustStr) (string, error) {
//
//	if val.err != nil {
//		defer C.multee_free_rust_str(val.err)
//		return "", errors.New(C.GoString(val.err))
//	} else {
//		defer C.multee_free_rust_str(val.val)
//		return C.GoString(val.val), nil
//	}
//}

func optionalLen(buf *[]byte) C.ulong {
	if buf != nil {
		return C.ulong(len(*buf))
	} else {
		return 0
	}
}
