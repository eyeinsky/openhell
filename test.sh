#!/usr/bin/env bash

# Simple test of if openssl even accepts the generated keys

cabal run -- openhell key --rsa --bits 2048 \
    | openssl rsa -in - -text -noout \
    | grep 'Private-Key'

cabal run -- openhell key --ed448 \
    | openssl pkey -noout -text \
    | grep 'Private-Key'

cabal run -- openhell key --ed25519 \
    | openssl pkey -noout -text \
    | grep 'Private-Key'
