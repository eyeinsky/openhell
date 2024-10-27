#!/usr/bin/env bash

set -e

script_dir="$(dirname "$(realpath "$0")")"

. "$script_dir/openssl_helpers.sh"

# key: generate

generates_valid_key_rsa() (
    bits="$1"
    if [ -n "$bits" ]; then
        flags="--bits $bits"
    fi
    openssl rsa -in <(openhell key --rsa $flags) -text -noout \
        | grep -q "Private-Key: ($bits\b.*"
)
generates_valid_key_ed448() (
    openssl pkey -in <(openhell key --ed448) -text -noout | grep -q ED448
)
generates_valid_key_ed25519() (
    openssl pkey -in <(openhell key --ed25519) -text -noout | grep -q ED25519
)

# key: inspect

inspect_key_rsa() (
    bits="$1"
    openssl genrsa -out - "$bits" | openhell key - | grep -q "RSA $bits bit"
)
inspect_key_ed448() (
    openssl genpkey -algorithm ED448 | openhell key - | grep -q "Ed448 private key"
)
inspect_key_ed25519() (
    openssl genpkey -algorithm ED25519 | openhell key - | grep -q "Ed25519 private key"
)
inspect_key_ed25519_nohyphen() (
    openssl genpkey -algorithm ED25519 | openhell key | grep -q "Ed25519 private key"
)

# cert: inspect

certificate_dn () (
    bundle="$1"

    dir="$(mktemp -d)"
    openssl_split_bundle "$bundle" "$dir"

    readarray -t arr < <(openhell cert "$bundle" | jq -r .issuer.commonName)

    openssl_n="$(ls -1 "$dir" |wc -l)"
    openhell_n="${#arr[@]}"

    [ $openssl_n != $openhell_n ] && echo 'Numbers dont match' && exit 1

    for n in $(seq 0 $(($openssl_n - 1))); do
        openhell_issuer="${arr[$n]}"
        openssl_cert="$dir/$n.pem"
        openssl_issuer0="$(openssl x509 -in "$openssl_cert" -noout -issuer)"
        openssl_issuer="$(openssl_dn "$openssl_issuer0" | jq -r .CN)"

        if [ "$openhell_issuer" = "$openssl_issuer" ]; then
            echo "OK: issuer $openhell_issuer"
        else
            echo "FAIL: '$openhell_issuer', '$openssl_issuer', '$openssl_issuer0', '$openssl_cert'"
            return 1
        fi
    done
n
)

# - takes bash command or function as first argument and runs it
# - echos failing test on non-zero return code
# - propagates return code itself
test_() (
    set +e
    echo -n "$@: "
    return_code=''
    {
        if [ -n "$DEBUG" ]; then
            $@
            return_code=$?
        else
            $@ &> /dev/null
            return_code=$?
        fi
    } >&2
    [ $return_code != 0 ] && echo "FAIL" || echo "OK"
    return $return_code
)

main() (
    which openhell || exit 1

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

    test_ certificate_dn /etc/ssl/certs/ca-bundle.crt
)

if [ -z "$*" ]; then
    main
else
    $@
fi
