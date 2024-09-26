#!/bin/bash

ROOT_CERT="rootCA.crt"
ROOT_KEY="rootCA.key"

if [[ -f "$ROOT_CERT" && -f "$ROOT_KEY" ]]; then
    echo "Root certificate and key already exist."
    exit 0
fi


openssl genrsa -out "$ROOT_KEY" 2048

openssl req -x509 -new -nodes -key "$ROOT_KEY" -sha256 -days 1024 \
    -out "$ROOT_CERT" -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=Root CA"

echo "Root certificate and key generated."
