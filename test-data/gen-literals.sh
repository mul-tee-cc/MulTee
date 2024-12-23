#!/bin/bash

# Prepare literal key store for testing

echo Generating AES-256 key
openssl rand  32 > TestKey.aes


echo Generating HMAC key
openssl rand  32 > HmacKey.hmac


echo Generating RSA-2048 key
openssl genrsa -out tmpfile 2048 2> /dev/null
openssl rsa -in tmpfile -out TestKey.rsa -outform der


# secp256k1 curve is problematic https://github.com/openssl/openssl/issues/15675, has no entry in https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme

echo Generating EC-secp256k1 key
openssl req -x509 -nodes -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 -out /dev/null -keyout tmpfile < /dev/null 2> /dev/null
openssl ec -in tmpfile -out TestKey.ecc -outform der


echo Generating TLS RSA-2048 key
openssl req -x509 -newkey rsa:2048 -nodes -keyout tls-key.pem -out tls-cert.pem -sha256 -days 365 -subj "/CN=multee/emailAddress=authors@multee.cc" 2> /dev/null
openssl rsa -in tls-key.pem -out TlsKey.rsa -outform der


echo Generating TLS ECC key
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout ecc-tls-key.pem -out ecc-tls-cert.pem -sha384 -days 365 -subj "/CN=multee/emailAddress=authors@multee.cc" 2> /dev/null
openssl ec -in ecc-tls-key.pem -out TlsKey.ecc -outform der
#openssl ec -in ecc-tls-key.pem -out TlsKey.ecc -outform der -no_public

#Revisit: object_type, algo, usage
#         ASYM        RSA_PSS   Sign
#         ASYM        RSA_OAEP  Encrypt
#         SYM          AES   Encr
#         SYM          HMAC_SHA256   Mac


echo Generating Manifest
cat <<EOF > MANIFEST.YAML
literals:
  unpinned:
    - name: HmacKey
      key_material_file: HmacKey.hmac
      key_type: 3 # AES???
      object_type: 2 # symmetric key
      usage_mask: 128 # MAC
      key_length: 256
    - name: RsaKey
      key_material_file: TestKey.rsa
      key_type: 4 # RSA
      object_type: 4 # private key
      usage_mask: 15 # sign+verify+encrypt+decrypt
      key_length: 2048
    - name: TestKey
      key_material_file: TestKey.aes
      key_type: 3 # AES
      object_type: 2 # symmetric key
      usage_mask: 12 # encrypt+decrypt
      key_length: 256
    - name: EccKey
      key_material_file: TestKey.ecc
      key_type: 6 # ECDSA
      object_type: 4 # private key
      usage_mask: 3 # sign+verify
      key_length: 256
    - name: TlsKey
      key_material_file: TlsKey.rsa
      key_type: 4 # RSA
      object_type: 4 # private key
      usage_mask: 3 # sign+verify
      key_length: 2048
    - name: EccTlsKey
      key_material_file: TlsKey.ecc
      key_type: 6 # ECC
      object_type: 4 # private key
      usage_mask: 3 # sign+verify
      key_length: 256

EOF


zip -9m literals.zip MANIFEST.YAML TlsKey.rsa TestKey.ecc TestKey.rsa TestKey.aes TlsKey.ecc HmacKey.hmac
rm -f *tls-key.pem *.csr tmpfile MANIFEST.YAML TlsKey.rsa TestKey.ecc TestKey.rsa TestKey.aes TlsKey.ecc HmacKey.hmac
