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

import pytest

from bundlecrypt.config import BundleCryptConfig, BundleCryptConfigError, KeyStore


def test_retrieving_private_key_by_key_id(valid_config_path, keys_path):
    key_store: KeyStore = BundleCryptConfig.parse(valid_config_path, None)
    key_id = "bundlecrypt-test-enc"
    actual_private_key = key_store.get_private_key(key_id)
    expected_private_key = (keys_path / "test" / "bundlecrypt-test-key.pem").read_text()
    assert actual_private_key == expected_private_key


def test_retrieving_private_key_without_key_pem_definition_in_keys_section_fails(
    valid_config_dict, tmp_path
):
    key_id = "bundlecrypt-test-enc"
    del valid_config_dict["keys"][key_id]["key-pem"]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_config_dict))

    key_store: KeyStore = BundleCryptConfig.parse(config_path, None)

    with pytest.raises(
        BundleCryptConfigError, match="^Failed to find 'key-pem' in key definition"
    ):
        key_store.get_private_key(key_id)


def test_retrieving_certificate_by_key_id(valid_config_path, keys_path):
    key_store: KeyStore = BundleCryptConfig.parse(valid_config_path, None)
    actual_certificate = key_store.get_cert_or_public_key("bundlecrypt-test-sign")
    expected_certificate = (
        keys_path / "test" / "bundlecrypt-test-cert.pem"
    ).read_text()
    assert actual_certificate == expected_certificate


def test_retrieving_certificate_without_cert_pem_definition_in_keys_section_fails(
    valid_config_dict, tmp_path
):
    key_id = "bundlecrypt-test-sign"
    del valid_config_dict["keys"][key_id]["cert-pem"]
    assert "pubkey-pem" not in valid_config_dict["keys"][key_id]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_config_dict))

    key_store: KeyStore = BundleCryptConfig.parse(config_path, None)

    with pytest.raises(
        BundleCryptConfigError,
        match="^Failed to find 'cert-pem'/'pubkey-pem' in key definition",
    ):
        key_store.get_cert_or_public_key(key_id)
