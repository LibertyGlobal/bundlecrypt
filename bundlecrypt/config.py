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

import importlib.resources
import json
import logging
import pathlib

import cryptography.hazmat.primitives.hashes
import jsonschema
from cryptography.x509 import load_pem_x509_certificate
from jose.utils import base64url_encode

from .exceptions import BundleCryptConfigError
from .keystore import KeyStore


logger = logging.getLogger(__name__)


class BundleCryptConfig:
    @staticmethod
    def parse(config_path: pathlib.Path, config_id: str):
        schema = json.loads(BundleCryptConfig.get_schema())
        config = json.loads(config_path.read_text())

        jsonschema.validate(instance=config, schema=schema)

        key_store = KeyStore(config_path, config["keys"])

        if config_id is not None:
            crypt_configuration = config["cryptConfigurations"].get(config_id)
            if crypt_configuration is None:
                raise BundleCryptConfigError(
                    f"Failed the find '{config_id}' in 'cryptConfigurations' in '{config_path}'"
                )
            logger.debug(f"Crypt configuration: {crypt_configuration}")
            return BundleCryptConfig(config_path, crypt_configuration, key_store)
        else:
            return key_store

    @staticmethod
    def get_schema():
        return importlib.resources.read_text("bundlecrypt", "config-schema.json")

    def __init__(self, config_path, crypt_config, key_store: KeyStore):
        self._config_path = config_path
        self._crypt_config = crypt_config
        self._key_store = key_store

    def get_config_signing_private_key(self):
        key_id = self._crypt_config["config.json"]["jws"]["kid"]
        return self._key_store.get_private_key(key_id)

    def get_config_signing_certificate(self):
        key_id = self._crypt_config["config.json"]["jws"]["kid"]
        return self._key_store.get_cert_or_public_key(key_id)

    def get_config_signing_algorithm(self):
        return self._crypt_config["config.json"]["jws"]["alg"]

    def get_config_signing_key_id(self):
        return self._crypt_config["config.json"]["jws"]["kid"]

    # as per https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.7
    def get_config_signing_certificate_sha1_thumbprint(self):
        certificate_data = self.get_config_signing_certificate()
        certificate = load_pem_x509_certificate(certificate_data.encode())
        fingerprint = certificate.fingerprint(
            cryptography.hazmat.primitives.hashes.SHA1()
        )
        return base64url_encode(fingerprint).decode()

    def get_config_encryption_public_key(self):
        key_id = self._crypt_config["config.json"]["jwe"]["kid"]
        return self._key_store.get_cert_or_public_key(key_id)

    def get_config_encryption_encryption(self):
        return self._crypt_config["config.json"]["jwe"]["enc"]

    def get_config_encryption_algorithm(self):
        return self._crypt_config["config.json"]["jwe"]["alg"]

    def get_config_encryption_key_id(self):
        return self._crypt_config["config.json"]["jwe"]["kid"]

    def should_sign_config(self):
        return self._crypt_config["config.json"]["jws"]["enabled"]

    def should_encrypt_config(self):
        return self._crypt_config["config.json"]["jwe"]["enabled"]

    def should_encrypt_rootfs(self):
        return self._crypt_config["rootfs"]["dm-crypt"]["enabled"]

    def should_add_rootfs_hash(self):
        return self._crypt_config["rootfs"]["dm-verity"]["enabled"]
