#!/bin/bash

# Simulate granting a platform from TOFU "trusted inventory" access to KMS
# I.e. Sign platform generated CSR with key trusted by KMS

set -e

STATE=$(dirname $0)

ID_CREDS=$1

unzip -d /tmp $ID_CREDS MANIFEST.YAML csr.pem
sed -i '/CA:/ d; /cert:/ d' /tmp/MANIFEST.YAML

openssl x509 -req -days 3650 -in /tmp/csr.pem -CA $STATE/selfsigned.crt -CAkey $STATE/selfsigned.key -CAcreateserial -out /tmp/cert.pem -extfile <(echo extendedKeyUsage = clientAuth)

cp $STATE/selfsigned.crt /tmp/ca.pem

sed -i '/pk:/ a\    cert: cert.pem' /tmp/MANIFEST.YAML
sed -i '/^---/ a \CA: ca.pem' /tmp/MANIFEST.YAML
zip -j $ID_CREDS /tmp/cert.pem /tmp/MANIFEST.YAML /tmp/ca.pem
rm -f /tmp/cert.pem /tmp/MANIFEST.YAML /tmp/ca.pem /tmp/csr.pem