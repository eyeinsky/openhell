#!/usr/bin/env bash

set -e

# key: generate

generates_valid_key_rsa() (
    bits="$1"
    if [ -n "$bits" ]; then
        flags="--bits $bits"
    fi
    openssl rsa -in <(./openhell key --rsa $flags) -text -noout \
        | grep -q "Private-Key: ($bits\b.*"
)
generates_valid_key_ed448() (
    openssl pkey -in <(./openhell key --ed448) -text -noout | grep -q ED448
)
generates_valid_key_ed25519() (
    openssl pkey -in <(./openhell key --ed25519) -text -noout | grep -q ED25519
)

# key: inspect

inspect_key_rsa() (
    bits="$1"
    openssl genrsa -out - "$bits" | ./openhell key - | grep -q "RSA $bits bit"
)
inspect_key_ed448() (
    openssl genpkey -algorithm ED448 | ./openhell key - | grep -q "Ed448 private key"
)
inspect_key_ed25519() (
    openssl genpkey -algorithm ED25519 | ./openhell key - | grep -q "Ed25519 private key"
)
inspect_key_ed25519_nohyphen() (
    openssl genpkey -algorithm ED25519 | ./openhell key | grep -q "Ed25519 private key"
)

# - takes bash command or function as first argument and runs it
# - echos failing test on non-zero return code
# - propagates return code itself
test_() (
    $@
    return_code=$?
    [ -n "$DEBUG" ] && echo "command: `$@`, return_code $return_code"
    [ $return_code != 0 ] && echo "FAIL $@" || echo "OK $@"
    return $return_code
)

main() (
    if [ ! -f ./openhell ]; then
        git submodules init
        git submodule update
        stack install --local-bin-path .
    fi

    set +e
    test_ inspect_key_ed448
    test_ inspect_key_ed25519
    test_ inspect_key_ed25519_nohyphen
    test_ inspect_key_rsa 2048
    test_ inspect_key_rsa 4096

    test_ generates_valid_key_rsa
    # test_ generates_valid_key_rsa 4095
    test_ generates_valid_key_rsa 4096
    test_ generates_valid_key_ed448
    test_ generates_valid_key_ed25519
)

main
