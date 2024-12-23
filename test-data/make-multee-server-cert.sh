#!/bin/bash

# Prepare MulTee Server TLS certificate

set -e

STATE=$(dirname $0)

openssl req -new -newkey rsa:2048 -keyout $STATE/multee-server.pkey -sha256 -nodes -out $STATE/multee-server.csr -subj "/CN=multee-server/emailAddress=authors@multee.cc" 2> /dev/null
openssl x509 -req -days 3650 -in $STATE/multee-server.csr -CA $STATE/selfsigned.crt -CAkey $STATE/selfsigned.key -CAcreateserial -out $STATE/multee-server.pem -extfile <(printf "subjectAltName=IP:127.0.0.1,IP:127.127.1.1,DNS:localhost,DNS:host.docker.internal\nextendedKeyUsage = serverAuth")

