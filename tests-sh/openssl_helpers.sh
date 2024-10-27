#!/usr/bin/env bash


openssl_split_bundle() ( # bundle: path to bundle, dest_dir: where to put certs from bundle
    bundle="$1"
    dest_dir="$2"
    cd "$dest_dir"
    awk 'BEGIN {c=0;} /BEGIN / {c++} { if (c) print > (c - 1) ".pem" }' "$bundle"
)

openssl_dn() ( # convert openssl distinquished name output to JSON
    str="$1"
    echo "{ $(echo "$str" |
        sed -E 's/((O|OU|C|CN|emailAddress|L) =)/\n\1/g' | # split to separate lines
        tail -n +2                                       | # drop "issuer"
        sed -E 's/(.*), $/\1/'                           | # dorp trailing comma
        sed -E 's/(\w+) = ("?)(.*)(\2)$/"\1": "\3"/'     | # json keys
        sed -E 's/\\/\\\\/g'                             | # escape slashes
        paste -s -d',') }"
)
