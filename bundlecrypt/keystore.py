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

import os
import pathlib

from .exceptions import BundleCryptConfigError


class KeyStore:
    @staticmethod
    def get_root_path():
        return pathlib.Path(os.environ.get("BUNDLECRYPT_KEYSDIR", "/keys"))

    def __init__(self, config_path: pathlib.Path, keys_mapping: dict):
        self._config_path = config_path
        self._keys_mapping = keys_mapping
        self._root_path = KeyStore.get_root_path()
        self._validate()

    def get_private_key(self, key_id: str):
        keys_info = self._get_keys_info(key_id)
        property_name = "key-pem"
        key_filename = keys_info.get(property_name)
        if key_filename is None:
            raise BundleCryptConfigError(
                f"Failed to find '{property_name}' in key definition '{keys_info}' in '{self._config_path}'"
            )
        key_path = self._root_path / key_filename
        return key_path.read_text()

    def get_cert_or_public_key(self, key_id: str):
        keys_info = self._get_keys_info(key_id)
        property_name = "cert-pem" if "cert-pem" in keys_info else "pubkey-pem"
        key_filename = keys_info.get(property_name)
        if key_filename is None:
            raise BundleCryptConfigError(
                f"Failed to find 'cert-pem'/'pubkey-pem' in key definition '{keys_info}' in '{self._config_path}'"
            )
        key_path = self._root_path / key_filename
        return key_path.read_text()

    def _get_keys_info(self, key_id):
        keys_info = self._keys_mapping.get(key_id)
        if keys_info is None:
            raise BundleCryptConfigError(
                f"Failed to find '{key_id}' in 'keys' in '{self._config_path}'"
            )
        return keys_info

    def _validate(self):
        for key_id, key_info in self._keys_mapping.items():
            if "cert-pem" in key_info and "pubkey-pem" in key_info:
                raise BundleCryptConfigError(
                    f"Invalid configuration for key '{key_id}' - if cert-pem is present, pubkey-pem should not be present"
                )
