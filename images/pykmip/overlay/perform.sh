#!/bin/bash

set -e

STATE=/etc/pykmip/state
DB_FILE="$STATE/pykmip.db"

perform_init() {

  if [[ ! -f $DB_FILE ]]; then
    echo "Database does not exist, performing initial setup"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -subj "/CN=root-ca" -keyout $STATE/selfsigned.key -out $STATE/selfsigned.crt
    
    cp $STATE/selfsigned.crt $STATE/ca.pem

    openssl req -new -newkey rsa:2048 -keyout $STATE/internal-client.pkey -sha256 -nodes -out $STATE/internal-client.csr -subj "/CN=acct/emailAddress=authors@multee.cc"
    openssl x509 -req -days 3650 -in $STATE/internal-client.csr -CA $STATE/selfsigned.crt -CAkey $STATE/selfsigned.key -CAcreateserial -out $STATE/internal-client.pem -extfile /etc/pykmip/client-extfile.cnf

    openssl req -new -newkey rsa:2048 -keyout $STATE/server.pkey -sha256 -nodes -out $STATE/server.csr -subj "/CN=kmip-server/emailAddress=authors@multee.cc"
    openssl x509 -req -days 3650 -in $STATE/server.csr -CA $STATE/selfsigned.crt -CAkey $STATE/selfsigned.key -CAcreateserial -out $STATE/server.pem -extfile /etc/pykmip/server-extfile.cnf -extfile <(printf "subjectAltName=IP:127.0.0.1,IP:127.127.1.1,DNS:localhost,DNS:host.docker.internal\nextendedKeyUsage = serverAuth")

    echo "End initial setup"
  else
    echo "Normal startup - database exists"
  fi

  sed -i  '/GCM-SHA/ s/ECDSA/RSA/' /usr/local/lib/python2.7/site-packages/kmip/services/auth.py
  sed -i 's/Test Key/TestKey/' /usr/local/lib/python2.7/site-packages/kmip/demos/units/create.py
  sed -i 's/UsageMaskEnum.ENCRYPT.value/UsageMaskEnum.SIGN.value | UsageMaskEnum.VERIFY.value | UsageMaskEnum.ENCRYPT.value/' /usr/local/lib/python2.7/site-packages/kmip/demos/units/create_key_pair.py
}

perform_start() {

  exec timeout 1800 pykmip-server
  #exec pykmip-server -v DEBUG
}

kmip_op() {
  local FUNC=$1
  shift
#  python3 /usr/local/lib/python3.6/dist-packages/kmip/demos/units/$FUNC "$@"
#  python /usr/lib/python2.7/dist-packages/kmip/demos/units/$FUNC "$@"
  python /usr/local/lib/python2.7/site-packages/kmip/demos/$FUNC "$@"
}

perform_create_aes_key() {
  #kmip_op create.py -a AES -l 256
  kmip_op units/my_create_named.py -a AES -n TestKey -l 256
  kmip_op units/activate.py -i 1
}

perform_create_rsa_key() {
  kmip_op units/create_key_pair.py -a RSA -n RsaKey -l 2048
  kmip_op units/activate.py -i 2
  kmip_op units/activate.py -i 3
}

perform_create_hmac_key() {
  #kmip_op units/create.py -a AES -l 256
  kmip_op units/my_create_named_hmac.py -a AES -n HmacKey -l 256
  kmip_op units/activate.py -i 4
}

perform_create_tls_key() {
  kmip_op units/create_key_pair.py -a RSA -n TlsKey -l 2048
}

comment_1() {
  python /usr/local/lib/python2.7/site-packages/kmip/demos/units/my_create_named_hmac.py -a AES -n HMACKey -l 256
  python /usr/local/lib/python2.7/site-packages/kmip/demos/units/activate.py -i 5
  python /usr/local/lib/python2.7/site-packages/kmip/demos/pie/mac.py -i 5 -a HMAC_SHA256
}

#perform_export_private_key() {
#  sqlite3 $STATE/pykmip.db 'select quote(value) from managed_objects where uid=(select min(uid) from private_keys);' |
#    cut -d\' -f2 |  xxd -r -p | openssl rsa -inform der > /w/kmip-ssl-key.pem
#}

#perform_register_key() {
#  kmip_op register.py -t PRIVATE_KEY -f X_509 "$1"
#}

#perform_export_key() {
#
#  kmip_op get.py -i 1
#}

# python /usr/local/lib/python2.7/site-packages/kmip/demos/units/locate.py  -n RsaKey --object-type PRIVATE_KEY
# python /usr/local/lib/python2.7/site-packages/kmip/demos/units/get.py -i 3

for target in "$@"; do

  perform_$target
done



