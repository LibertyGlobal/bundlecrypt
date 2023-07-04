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

SCRIPT_DIR="$(dirname $(realpath $BASH_SOURCE))"
TS=$(date '+%s')
COMPOSE="docker-compose --project-name bundlecrypt-demo-rabbitmq"
RABBITMQCTL="docker exec -it bundlecrypt-demo-rabbitmq_rabbitmq_1 rabbitmqctl"
RABBITMQADMIN="docker exec -it bundlecrypt-demo-rabbitmq_rabbitmq_1 rabbitmqadmin"

log() {
  echo -e "\e[34m[demo]\e[39m \e[33m${1}\e[39m"
}

pushd ${SCRIPT_DIR} >/dev/null

log "Removing the target file from S3"
aws s3 rm s3://lgi-onemw-tests/bundlecrypt/bundlecrypt-protected.tgz

log "Waiting for the target file to become unavailable on S3"
aws s3api wait object-not-exists --bucket lgi-onemw-tests --key bundlecrypt/bundlecrypt-protected.tgz

log "Starting Docker Compose services"
$COMPOSE up --build --detach

log "Waiting for RabbitMQ to start"
$RABBITMQCTL wait /tmp/rabbitmq.pid

log "Declaring a queue in RabbitMQ for BundleCrypt"
$RABBITMQADMIN declare queue name=bundlecrypt-requests durable=false

log "Publishing request for BundleCrypt over RabbitMQ"
$RABBITMQADMIN \
  publish \
  routing_key=bundlecrypt-requests \
  payload='{"src-bucket-name": "lgi-onemw-tests", "src-object-name": "bundlecrypt/bundle-raw.tgz", "dst-bucket-name": "lgi-onemw-tests", "dst-object-name": "bundlecrypt/bundlecrypt-protected.tgz"}'

log "Waiting for the target file to become available on S3"
aws s3api wait object-exists --bucket lgi-onemw-tests --key bundlecrypt/bundlecrypt-protected.tgz
log "SUCCESS!"

log "Removing target file from S3"
aws s3 rm s3://lgi-onemw-tests/bundlecrypt/bundlecrypt-protected.tgz

log "Stopping Docker Compose services"
$COMPOSE down

log "Done"
