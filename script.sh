#!/usr/bin/env bash

# Helpers

between() {
    local START="$1"
    local END="$2"
    sed -ne "/$START/,/$END/p"
}

keep_x509_extensions() {
    between 'X509v3\sextensions' 'Signature\sAlgorithm:' | head -n -1
}

just_pem() {
    between '-----BEGIN ' '-----END '
}


# PKCS #12

p12_extract_cert() {
    local p12="$1"
    local password="$2"
    openssl pkcs12 -info -in $p12 -nokeys -password "pass:$password" \
            2>/dev/null | just_pem
}

p12_extract_key() {
    local p12="$1"
    local password="$2"
    openssl pkcs12 -info -in $p12 -nodes -nocerts -password "pass:$password" \
            2>/dev/null | just_pem
}

# PKCS #1

key_extract_pub() {
    local key="$1"
    openssl rsa -in "$key" -pubout
}

cert_verify() {
    local ca="$1"
    local cert="$2"
    openssl verify -verbose -CAfile "$ca" "$cert"
}

p12_show_cert() {
    local p12="$1"
    local pw="$2"
    p12_extract_cert "$p12" "$pw" | openssl x509 -text
}

cert_matches_private_key() {
    local cert="$1"
    local key="$2"
    local res="$(diff \
        <(openssl x509 -noout -modulus -in "$cert") \
        <(openssl rsa -noout -modulus -in "$key"))"
    if [[ "$res" = "" ]]; then
        echo "OK"
        exit 0
    else
        echo "FAIL"
        exit 1
    fi
}

# Verify that $1 was used to sign $2
cert_signed_cert() {
    local signer_cert="$1"
    local signed_cert="$2"
    openssl verify -no-CAfile -no-CApath -partial_chain \
            -trusted "$signer_cert" \
            "$signed_cert"
}


# Test a server

p12_connect() {
    local p12="$1"
    local pw="$2"
    local host="$3"
    curl --cert-type P12 --cert "$p12:$pw" "$host"
}

server_chain() {
    local host="$1"
    openssl s_client -connect "$host" -showcerts \
            2>/dev/null </dev/null \
            | sed -n '/-----BEGIN/,/-----END/p'
}

# Info/non machine-readable output

crt_info() {
    openssl x509 -text -noout -in "$1"
}

csr_info() {
    openssl req -text -noout -in "$1"
}

csr_verify_sig() {
    # CSRs are self-signed, verify signature against included public key.
    openssl req -verify -noout -in "$1"
}

is_self_signed() {
    local cert="$1"
    openssl verify -no-CAfile -no-CApath "$cert"
}

# Call make

mk() {
    cd "$(dirname "$0")"
    make "$1"
}

# Meta

help() {
    grep -E '^ *[a-zA-Z0-9_]+\( *\) *{' "$0"
}

DEFAULT=help
CMD="${@:-$DEFAULT}"
# echo cmd: $CMD
$CMD
