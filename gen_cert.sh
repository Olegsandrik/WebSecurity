#!/bin/bash

COMMON_NAME=$1
SERIAL_NUMBER=$2

CERT_DIR="./certs"
CERT_FILE="$CERT_DIR/${COMMON_NAME}.crt"
KEY_FILE="$CERT_DIR/${COMMON_NAME}.key"
CONFIG_FILE="$CERT_DIR/${COMMON_NAME}.cnf"

mkdir -p "$CERT_DIR"

openssl genrsa -out "$KEY_FILE" 2048

cat > "$CONFIG_FILE" <<EOL
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
C  = US
ST = State
L  = City
O  = Organization
OU = Unit
CN = $COMMON_NAME

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOL

openssl req -new -key "$KEY_FILE" -out "${COMMON_NAME}.csr" -config "$CONFIG_FILE"

openssl x509 -req -in "${COMMON_NAME}.csr" -CA rootCA.crt -CAkey rootCA.key \
    -CAcreateserial -out "$CERT_FILE" -days 500 -sha256 -extfile "$CONFIG_FILE" -extensions v3_req

rm "${COMMON_NAME}.csr"
rm "$CONFIG_FILE"

echo "Certificate for $COMMON_NAME generated."
