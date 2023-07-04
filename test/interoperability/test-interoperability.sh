#!/bin/bash

################################################################################
# If not stated otherwise in this file or this component's Licenses.txt file the
# following copyright and licenses apply:
#
# Copyright 2021 Liberty Global B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

set -euo pipefail
#set -x

error() {
  echo -e "\e[31m[test] ERROR: $1\e[39m" >&2
  exit 1
}

log() {
  echo -e "\e[34m[test]\e[39m \e[33m${1}\e[39m"
}


JOSE_UTIL=$(realpath ./jose-util)

ONEMW_PROTECTED_BUNDLE=$(realpath ../../tmp/bundle-image.tar)
JWE_DECRYPTION_KEY=$(realpath ../../examples/keys/test/bundlecrypt-test-key.pem)
JWS_CERTIFICATE=$(realpath ../../examples/keys/test/bundlecrypt-test-cert.pem)

export BUNDLECRYPT_TMPDIR=$(realpath ../../tmp)

test -f "$ONEMW_PROTECTED_BUNDLE" || error "Input ONEMW protected bundle missing"
ONEMW_PROTECTED_BUNDLE=$(realpath "$ONEMW_PROTECTED_BUNDLE")

tmpdir=$(mktemp -d -t test-interop-XXXXXXXXXX)
trap "rm -rf $tmpdir" EXIT

pushd $tmpdir
mkdir extracted-bundle

log "Extracting protected bundle"
tar -xf "$ONEMW_PROTECTED_BUNDLE" -C "./extracted-bundle"

log "Checking protected bundle contents"
test -f ./extracted-bundle/config.json.jwt || error "config.json.jwt missing in extracted bundle"
test -f ./extracted-bundle/rootfs.img      || error "rootfs.img missing in extracted bundle"

log "Decrypting config.json.jwt"
JWE_PAYLOAD=$(
  "$JOSE_UTIL" decrypt \
    --key "$JWE_DECRYPTION_KEY" \
    --in ./extracted-bundle/config.json.jwt
)

log "Verifying the signature of config.json.jwt"
CONFIG_JSON=$(
  "$JOSE_UTIL" verify \
    --key "$JWS_CERTIFICATE" \
    --in <(echo "$JWE_PAYLOAD")
)

log "Verifying the original annotations exist in config.json"
IMAGE_OS=$(       jq -e -r '.annotations."org.opencontainers.image.os"'           <(echo "$CONFIG_JSON"))
[ "$IMAGE_OS" == "linux" ] || error "Invalid image OS"

log "Verifying custom annotations exist in config.json"
IMAGE_KEY=$(        jq -e -r '.annotations."org.rdk.dac.bundle.image.key"'        <(echo "$CONFIG_JSON"))
IMAGE_ROOT_HASH=$(  jq -e -r '.annotations."org.rdk.dac.bundle.image.roothash"'   <(echo "$CONFIG_JSON"))
IMAGE_HASH_OFFSET=$(jq -e -r '.annotations."org.rdk.dac.bundle.image.hashoffset"' <(echo "$CONFIG_JSON"))
IMAGE_SALT=$(       jq -e -r '.annotations."org.rdk.dac.bundle.image.salt"'       <(echo "$CONFIG_JSON"))

log "Verifying rootfs hash"
veritysetup verify \
  --hash-offset="$IMAGE_HASH_OFFSET" \
  ./extracted-bundle/rootfs.img \
  ./extracted-bundle/rootfs.img \
  "$IMAGE_ROOT_HASH"

log "Decrypting rootfs"
echo "$IMAGE_KEY" | base64 -d > ./rootfs.key

if [ -e /sbin/cryptsetup-reencrypt ]; then echo jest; fi
    sudo cryptsetup-reencrypt --decrypt ./extracted-bundle/rootfs.img --key-file ./rootfs.key
else
    sudo cryptsetup reencrypt --decrypt ./extracted-bundle/rootfs.img --key-file ./rootfs.key
fi

log "Extracting rootfs"
unsquashfs -d rootfs ./extracted-bundle/rootfs.img

log "Checking rootfs contents"
test -f ./rootfs/foo || error "foo missing in rootfs"
test -f ./rootfs/bar || error "bar missing in rootfs"

log "SUCCESS!"
