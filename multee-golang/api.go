package multee

func (key SymmetricKey) EncryptCBC(plaintext []byte, iv ...[]byte) ([]byte, []byte, error) {
	var ref *[]byte
	switch len(iv) {
	case 0:
		ref = nil
	case 1:
		ref = &iv[0]
	default:
		return nil, nil, NewMulTeeError(ERR_API_MISUSE, 0, "Illegal usage of interface")
	}
	return cryptCBC(key.ref.sessionId, key.keyIndex, true, plaintext, ref)
}

func (key SymmetricKey) DecryptCBC(ciphertext []byte, iv []byte) ([]byte, error) {
	plaintext, _, err := cryptCBC(key.ref.sessionId, key.keyIndex, false, ciphertext, &iv)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (key SymmetricKey) Seal(plaintext []byte, aad ...[]byte) ([]byte, []byte, []byte, error) {
	var ref *[]byte
	switch len(aad) {
	case 0:
		ref = nil
	case 1:
		ref = &aad[0]
	default:
		return nil, nil, nil, NewMulTeeError(ERR_API_MISUSE, 0, "Illegal usage of interface")
	}
	return encryptGCM(key.ref.sessionId, key.keyIndex, plaintext, ref)
}

func (key SymmetricKey) Unseal(plaintext []byte, iv []byte, tag []byte, aad ...[]byte) ([]byte, error) {
	var ref *[]byte
	switch len(aad) {
	case 0:
		ref = nil
	case 1:
		ref = &aad[0]
	default:
		return nil, NewMulTeeError(ERR_API_MISUSE, 0, "Illegal usage of interface")
	}
	return decryptGCM(key.ref.sessionId, key.keyIndex, plaintext, iv, tag, ref)
}

// Hmac computes a keyed-hash message authentication code using SHA256. It may be used to simultaneously verify both
// the data integrity and the authenticity of a message. Can be used as a deterministic 1-to-1 proxy for PAN.
func (key HmacKey) HmacSHA256(plaintext []byte) ([]byte, error) {
	return hmacSHA256(key.ref.sessionId, key.keyIndex, plaintext)
}

func (key SigningKey) Sign(plaintext []byte) ([]byte, error) {
	return sign(key.ref.sessionId, key.keyIndex, plaintext)
}

func (key SigningKey) GetPublicKey() PublicKey {
	return PublicKey{keyIndex: key.keyIndex, ref: key.ref}
}

func (key PublicKey) Verify(plaintext []byte, signature []byte) (bool, error) {
	return verify(key.ref.sessionId, key.keyIndex, plaintext, signature)
}
