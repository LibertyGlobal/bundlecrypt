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

SCRIPT_DIR="$(dirname $(realpath $BASH_SOURCE))"
TS=$(date '+%s')
COMPOSE="docker-compose --project-name bundlecrypt-demo-inotify"

log() {
  echo -e "\e[34m[demo]\e[39m \e[33m${1}\e[39m"
}

pushd ${SCRIPT_DIR} >/dev/null
mkdir -p tmp

log "Starting Docker Compose services"
$COMPOSE up --build --detach

sleep 5  # let inotifywait start

log "Downloading an example input file for BundleCrypt"
curl \
  --fail \
  --location \
  -o inputs/bundle-${TS}.tgz \
  https://github.com/stagingrdkm/lntpub/raw/ed60366f5aeaaae12367d290318738f1aef1014d/bundle/rpi/rpi-wayland-egl-test.tar.gz
if ! tar --list -f inputs/bundle-${TS}.tgz >/dev/null; then
  echo "ERROR: Something went wrong with downloading the file"
  exit 1
fi

log "Waiting for BundleCrypt to process the file "
while true; do
  if ! curl --silent --fail -o tmp/bundle-${TS}.tgz http://localhost/bundle-${TS}.tgz; then
    echo -n "."
    sleep 1
  else
    echo
    break
  fi
done

log "SUCCESS!"
log "Listing the contents of the output file"
tar --list -f tmp/bundle-${TS}.tgz

log "Stopping Docker Compose services"
$COMPOSE down

log "Removing demo files"
rm -f \
  inputs/bundle-${TS}.tgz \
  outputs/bundle-${TS}.tgz \
  tmp/bundle-${TS}.tgz

log "Done"
