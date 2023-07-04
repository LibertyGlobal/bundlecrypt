#!/usr/bin/env python3

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

import json
import logging
import pathlib
import tempfile

import boto3
import pika

from bundlecrypt.core import crypt
from bundlecrypt.utils import configure_logging


BUNDLECRYPT_REQUESTS_QUEUE = "bundlecrypt-requests"
BUNDLECRYPT_CONFIG_PATH = pathlib.Path("/configs/config.json")
BUNDLECRYPT_CONFIG_ID = "test"
RABBITMQ_HOST = "rabbitmq"

s3_client = boto3.client('s3')


def download_bundle(bucket_name, object_name, dest_file_name):
    logging.info("Downloading unprotected bundle from S3")
    s3_client.download_file(bucket_name, object_name, str(dest_file_name))


def encrypt_bundle(unprotected_bundle_path, protected_bundle_path):
    logging.info("Encrypting bundle")
    crypt(BUNDLECRYPT_CONFIG_PATH, BUNDLECRYPT_CONFIG_ID, unprotected_bundle_path, protected_bundle_path)


def upload_bundle(src_file_name, bucket_name, object_name):
    logging.info("Uploading protected bundle to S3")
    s3_client.upload_file(str(src_file_name), bucket_name, object_name)


def process_request(body):
    logging.debug(f"Received {body}")
    request = json.loads(body)

    src_bucket_name = request["src-bucket-name"]
    src_object_name = request["src-object-name"]
    dst_bucket_name = request["dst-bucket-name"]
    dst_object_name = request["dst-object-name"]

    with tempfile.NamedTemporaryFile() as unprotected_bundle, tempfile.NamedTemporaryFile() as protected_bundle:
        unprotected_bundle_path = pathlib.Path(unprotected_bundle.name)
        protected_bundle_path = pathlib.Path(protected_bundle.name)

        download_bundle(src_bucket_name, src_object_name, unprotected_bundle_path)
        encrypt_bundle(unprotected_bundle_path, protected_bundle_path)
        upload_bundle(protected_bundle_path, dst_bucket_name, dst_object_name)

    logging.info("Request processed successfully")


def on_message_callback(channel, method, properties, body):
    try:
        process_request(body)
    except Exception:
        logging.exception("Failed to process request")


def bundlecrypt_requests_loop():
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=RABBITMQ_HOST))
    channel = connection.channel()
    channel.queue_declare(queue=BUNDLECRYPT_REQUESTS_QUEUE)
    channel.basic_consume(queue=BUNDLECRYPT_REQUESTS_QUEUE, on_message_callback=on_message_callback, auto_ack=True)
    channel.start_consuming()


def main():
    verbose_logging = False
    configure_logging(verbose_logging)

    bundlecrypt_requests_loop()


if __name__ == '__main__':
    main()
