package multee

import (
	"errors"
	"fmt"
	"runtime"
)

// https://speakerdeck.com/rebeccaskinner/monadic-error-handling-in-go
// https://www.digitalocean.com/community/tutorials/creating-custom-errors-in-go
// https://earthly.dev/blog/golang-errors/

type MulTeeError struct {
	ErrorCode int
	SubCode   int
	Err       error
}

func (r *MulTeeError) Error() string {
	return r.Err.Error()
}

func NewMulTeeError(code int, sub int, msg string) error {
	name := ErrCode(code).String()
	return &MulTeeError{code, sub, errors.New(fmt.Sprintf("%s{%d}: %s", name, sub, msg))}
}

// MulTee is a "box" of keys that exist in a trusted execution environment (such as Intel SGX). These keys can be accessed
// through the SymmetricKeys field which is a map of logical key names to SymmetricKey objects.
type MulTee struct {
	sessionId uint64
	keys      map[string]int
}

// KeyHandle is a handle to key material that exists in an enclave. It can be used to perform crypto operations.
type KeyHandle struct {
	keyIndex int
	ref      *MulTee
}

type HmacKey struct {
	keyIndex int
	ref      *MulTee
}

type SymmetricKey struct {
	keyIndex int
	ref      *MulTee
}

type SigningKey struct {
	keyIndex int
	ref      *MulTee
}

type PublicKey struct {
	keyIndex int
	ref      *MulTee
}

type EncryptionKey struct {
	keyIndex int
	ref      *MulTee
}

// NewMulTee authenticates with a Key Management Service (KMS) and imports keys, specified by the keyNames parameter
func NewMulTee(uri string, keyNames []string, credsZipPath string) (*MulTee, error) {
	kb := new(MulTee)
	kb.keys = make(map[string]int)
	sessionId, err := loadKeys(uri, keyNames, credsZipPath)
	kb.sessionId = sessionId
	if err == nil {
		for i, keyName := range keyNames {
			kb.keys[keyName] = i
		}
		runtime.SetFinalizer(kb, func(k *MulTee) {
			if k != nil {
				k.close()
			}
		})
		return kb, err
	} else {
		kb = nil
	}
	return kb, err
}

// close destroys the enclave and all key material that is stored in it. Any SymmetricKey object that is part of this
// MulTee will no longer function.
func (mulTee *MulTee) close() {
	destroyEnclave(mulTee.sessionId)
	runtime.SetFinalizer(mulTee, nil)
}

func (mulTee *MulTee) GetKey(keyName string) (KeyHandle, error) {

	index, exists := mulTee.keys[keyName]
	handle := KeyHandle{keyIndex: index, ref: mulTee}

	if !exists {
		return handle, NewMulTeeError(ERR_CRYPTO_INVALID_KEY_NAME, 0, "Accessing undeclared key: "+keyName)
	}

	_, err := keyLength(mulTee.sessionId, index)

	return handle, err
}

func (keyHandle *KeyHandle) Symmetric() (SymmetricKey, error) {
	return SymmetricKey{keyIndex: keyHandle.keyIndex, ref: keyHandle.ref}, nil
}

func (keyHandle *KeyHandle) Hmac() (HmacKey, error) {
	return HmacKey{keyIndex: keyHandle.keyIndex, ref: keyHandle.ref}, nil
}

func (keyHandle *KeyHandle) Encryption() (EncryptionKey, error) {
	return EncryptionKey{keyIndex: keyHandle.keyIndex, ref: keyHandle.ref}, nil
}

func (keyHandle *KeyHandle) Signing() (SigningKey, error) {
	return SigningKey{keyIndex: keyHandle.keyIndex, ref: keyHandle.ref}, nil
}
