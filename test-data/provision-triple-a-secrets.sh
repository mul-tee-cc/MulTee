#!/bin/bash

# Prepare Triple-A TLS certificate
# Prepare grant signing key
# Prepare application identity CA
#
# For POC purposes all three are under selfsigned.crt
# To be revisited

set -e

STATE=$(dirname $0)

openssl req -new -newkey rsa:2048 -keyout $STATE/triplea.pkey -sha256 -nodes -out $STATE/triplea.csr -subj "/CN=triple-a-server/emailAddress=authors@multee.cc" 2> /dev/null
openssl x509 -req -days 3650 -in $STATE/triplea.csr -CA $STATE/selfsigned.crt -CAkey $STATE/selfsigned.key -CAcreateserial -out $STATE/triplea.pem -extfile <(printf "subjectAltName=IP:127.0.0.1,IP:127.127.1.1,DNS:localhost,DNS:host.docker.internal\nextendedKeyUsage = serverAuth")
openssl pkcs12 -export -out $STATE/triplea.p12 -in $STATE/triplea.pem -inkey $STATE/triplea.pkey -certfile $STATE/selfsigned.crt -passout pass:'changeit'

cp $STATE/selfsigned.crt $STATE/id-trust-ca.crt

cp $STATE/selfsigned.crt $STATE/grant-signing.crt
cp $STATE/selfsigned.key $STATE/grant-signing.key