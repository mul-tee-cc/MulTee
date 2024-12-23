#!/bin/bash

# Prepare application identity credentials file

set -e

STATE=$(dirname $0)

openssl req -new -newkey rsa:2048 -keyout $STATE/identity.pkey -sha256 -nodes -out $STATE/identity.csr -subj "/CN=multee-client/emailAddress=authors@multee.cc" 2> /dev/null
openssl x509 -req -days 3650 -in $STATE/identity.csr -CA $STATE/selfsigned.crt -CAkey $STATE/selfsigned.key -CAcreateserial -out $STATE/identity.pem -extfile <(printf "extendedKeyUsage = clientAuth")

TMP_D=$(mktemp -d)

cp $STATE/selfsigned.crt $TMP_D/ca.pem
cp $STATE/identity.pkey $TMP_D/identity.key
cp $STATE/identity.pem $TMP_D/identity.pem

cat > $TMP_D/MANIFEST.YAML <<EOF
hostname: test
CA: ca.pem
credentials:
  unpinned:
    cert: identity.pem
    pk: identity.key
EOF

rm -f $STATE/identity.zip
( cd $TMP_D; zip -9m identity.zip ca.pem identity.pem identity.key MANIFEST.YAML > /dev/null; )
mv $TMP_D/identity.zip $STATE/identity.zip

rm -rf $TMP_D

