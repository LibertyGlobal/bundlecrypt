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

import json.decoder
import pathlib

import jsonschema.exceptions
import pytest

from bundlecrypt.config import BundleCryptConfig, BundleCryptConfigError


def test_parsing_fails_on_invalid_json_on_input(tmp_path):
    config_path: pathlib.Path = tmp_path / "config.json"
    config_path.write_text("x")
    with pytest.raises(json.decoder.JSONDecodeError):
        BundleCryptConfig.parse(config_path, "")


def test_parsing_fails_on_invalid_bundlecrypt_config_on_input(tmp_path):
    config_path: pathlib.Path = tmp_path / "config.json"
    config_path.write_text("{}")
    with pytest.raises(jsonschema.exceptions.ValidationError):
        BundleCryptConfig.parse(config_path, "")


def test_parsing_fails_on_missing_crypt_configuration_in_bundlecrypt_config(
    tmp_path, valid_config_dict
):
    config_id = "xxx"
    assert config_id not in valid_config_dict["cryptConfigurations"]

    config_path: pathlib.Path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_config_dict))

    with pytest.raises(
        BundleCryptConfigError,
        match=f"Failed the find '{config_id}' in 'cryptConfigurations' in '{config_path}'",
    ):
        BundleCryptConfig.parse(config_path, "xxx")


def test_parsing_valid_config_succeeds(valid_config_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    assert isinstance(config, BundleCryptConfig)


def test_retrieving_config_signing_private_key(valid_config_path, keys_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    actual_private_key = config.get_config_signing_private_key()
    expected_private_key = (keys_path / "test" / "bundlecrypt-test-key.pem").read_text()
    assert actual_private_key == expected_private_key


def test_retrieving_config_signing_certificate(valid_config_path, keys_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    actual_certificate = config.get_config_signing_certificate()
    expected_certificate = (
        keys_path / "test" / "bundlecrypt-test-cert.pem"
    ).read_text()
    assert actual_certificate == expected_certificate


def test_retrieving_config_signing_certificate_thumbprint(valid_config_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    thumbprint = config.get_config_signing_certificate_sha1_thumbprint()
    assert thumbprint == "2ujztQzLEz3yBof-D5Xt056FLXM"


def test_retrieving_config_signing_key_id(valid_config_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    key_id = config.get_config_signing_key_id()
    assert key_id == "bundlecrypt-test-sign"


def test_retrieving_config_signing_algorithm(valid_config_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    algorithm = config.get_config_signing_algorithm()
    assert algorithm == "RS256"


def test_retrieving_config_encryption_public_key(valid_config_path, keys_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    actual_public_key = config.get_config_encryption_public_key()
    expected_public_key = (
        keys_path / "test" / "bundlecrypt-test-pubkey.pem"
    ).read_text()
    assert actual_public_key == expected_public_key


def test_retrieving_config_encryption_encryption(valid_config_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    assert config.get_config_encryption_encryption() == "A256CBC-HS512"


def test_retrieving_config_encryption_algorithm(valid_config_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    assert config.get_config_encryption_algorithm() == "RSA-OAEP"


def test_retrieving_config_encryption_key_id(valid_config_path):
    config = BundleCryptConfig.parse(valid_config_path, "test")
    assert config.get_config_encryption_key_id() == "bundlecrypt-test-enc"


def test_retrieving_config_signing_key_without_definition_in_keys_section_fails(
    tmp_path, valid_config_dict
):
    key_id = "bundlecrypt-test-sign"
    del valid_config_dict["keys"][key_id]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_config_dict))

    config = BundleCryptConfig.parse(config_path, "test")
    with pytest.raises(
        BundleCryptConfigError,
        match=f"Failed to find '{key_id}' in 'keys' in '{config_path}'",
    ):
        config.get_config_signing_private_key()


def test_retrieving_config_encryption_key_without_definition_in_keys_section_fails(
    tmp_path, valid_config_dict
):
    key_id = "bundlecrypt-test-enc"
    del valid_config_dict["keys"][key_id]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_config_dict))

    config = BundleCryptConfig.parse(config_path, "test")
    with pytest.raises(
        BundleCryptConfigError,
        match=f"Failed to find '{key_id}' in 'keys' in '{config_path}'",
    ):
        config.get_config_encryption_public_key()


def test_retrieving_a_key_without_pubkey_and_cert_definition_in_keys_section_fails(
    tmp_path, valid_config_dict
):
    key_id = "bundlecrypt-test-enc"
    del valid_config_dict["keys"][key_id]["pubkey-pem"]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_config_dict))

    config = BundleCryptConfig.parse(config_path, "test")
    with pytest.raises(
        BundleCryptConfigError,
        match=f"Failed to find 'cert-pem'/'pubkey-pem' in key definition",
    ):
        config.get_config_encryption_public_key()


def test_parsing_config_with_both_cert_and_pubkey_definitions_fails(
    valid_config_dict, tmp_path
):
    key_id = "bundlecrypt-test-enc"
    assert valid_config_dict["keys"][key_id]["pubkey-pem"] is not None
    # create a fake entry for "cert-pem", so that we now have both: "pubkey-pem" and "cert-pem"
    valid_config_dict["keys"][key_id]["cert-pem"] = valid_config_dict["keys"][key_id][
        "pubkey-pem"
    ]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(valid_config_dict))

    with pytest.raises(
        BundleCryptConfigError,
        match="^Invalid configuration for key 'bundlecrypt-test-enc' - if cert-pem is present, pubkey-pem should not be present",
    ):
        BundleCryptConfig.parse(config_path, "test")


def parse_config(config_dict, tmp_path):
    config_path = tmp_path / "bundlecrypt-config.json"
    config_path.write_text(json.dumps(config_dict))
    return BundleCryptConfig.parse(config_path, "test")


def test_checking_if_bundle_config_should_be_signed(valid_config_dict, tmp_path):
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jws"][
        "enabled"
    ] = True
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_sign_config() is True

    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jws"][
        "enabled"
    ] = False
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_sign_config() is False


def test_checking_if_bundle_config_should_be_encrypted(valid_config_dict, tmp_path):
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jwe"][
        "enabled"
    ] = True
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_encrypt_config() is True

    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jwe"][
        "enabled"
    ] = False
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_encrypt_config() is False


def test_checking_if_rootfs_should_be_signed(valid_config_dict, tmp_path):
    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-verity"][
        "enabled"
    ] = True
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_add_rootfs_hash() is True

    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-verity"][
        "enabled"
    ] = False
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_add_rootfs_hash() is False


def test_checking_if_rootfs_should_be_encrypted(valid_config_dict, tmp_path):
    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-crypt"][
        "enabled"
    ] = True
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_encrypt_rootfs() is True

    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-crypt"][
        "enabled"
    ] = False
    config = parse_config(valid_config_dict, tmp_path)
    assert config.should_encrypt_rootfs() is False
