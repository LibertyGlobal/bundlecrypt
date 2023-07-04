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
import tarfile
from pathlib import Path

import pytest
from jose import jwe, jws
from jose.utils import base64url_encode
from pytest_subprocess.core import FakeProcess

from bundlecrypt.core import (
    add_verity_hash,
    BundleCryptError,
    crypt,
    decrypt,
    decrypt_bundle_config,
    decrypt_rootfs_image,
    encrypt_bundle_config,
    encrypt_rootfs_image,
    protect_bundle_config,
    sign_bundle_config,
    verify_and_extract_bundle_config,
    verify_rootfs_hash,
    unprotect_bundle_config,
)
from bundlecrypt.config import BundleCryptConfig


@pytest.fixture(autouse=True)
def bundlecrypt_tmpdir(monkeypatch, tmp_path):
    bundlecrypt_tmpdir_path = tmp_path / "bundlecrypt-tmpdir"
    monkeypatch.setenv("BUNDLECRYPT_TMPDIR", str(bundlecrypt_tmpdir_path))


@pytest.fixture
def fake_onemw_encrypt_image_tool(fake_process, tmp_path):
    def fake_onemw_encrypt_image(process):
        assert process.args[1] == "rootfs.img"

        # due to an issue in "dmcrypt-rdk" the tool needs to be invoked with the current working directory set
        # to the folder where the "rootfs.img" input file is stored; this is also where the output file should be
        # stored; unfortunately pytest-subprocess' fake_process fixture doesn't pass the current working directory in
        # "process" object passed to the callback; therefore, in order to determine where the output file should be
        # created we search the test case's temp folder for the location of the "rootfs.img" input file
        raw_rootfs_image_path = list(tmp_path.rglob("rootfs.img"))[0]

        encrypted_rootfs_image_path = raw_rootfs_image_path.parent / (
            raw_rootfs_image_path.name + ".enc"
        )
        encrypted_rootfs_image_path.write_bytes(b"\x00" * 4096)
        encrypted_rootfs_image_path.touch()

    command = ["/usr/sbin/dmcrypt-rdk", fake_process.any()]
    fake_process.register_subprocess(command=command, callback=fake_onemw_encrypt_image)
    return command


@pytest.fixture
def fake_cryptsetup_reencrypt_decrypt_tool(fake_process):
    command = ["--decrypt", fake_process.any()]

    if os.path.exists("/sbin/cryptsetup-reencrypt"):
        command.insert(0, "/sbin/cryptsetup-reencrypt")
    else:
        command.insert(0, "/sbin/cryptsetup")
        command.insert(1, "reencrypt")

    if os.getuid() != 0:
        command.insert(0, "sudo")

    fake_process.register_subprocess(command=command)
    return command


@pytest.fixture
def fake_veritysetup_format_tool(fake_process):
    command = ["veritysetup", "format", fake_process.any()]
    salt = "6b96881fd13e449dc1a8b38237a2568f44962e3308f87dcada41ecb748b32926"
    root_hash = "9b5b66ff27171db628ac0a2d600b1d24627500527c8e34489e31b82f367d148a"
    stdout = f"""
blah blah
Salt:            	{salt}
Root hash:      	{root_hash}
blah blah
"""
    fake_process.register_subprocess(command=command, stdout=stdout.encode())
    return command, root_hash, salt


@pytest.fixture
def rootfs_img_path(tmp_path):
    rootfs_img_path = tmp_path / "rootfs.img"
    rootfs_img_path.write_bytes(b"\x00" * 4096)
    return rootfs_img_path


@pytest.fixture
def bundle_config_path(tmp_path):
    bundle_config = {"foo": "bar"}
    bundle_config_path = tmp_path / "dac-bundle-config.json"
    bundle_config_path.write_text(json.dumps(bundle_config))
    return bundle_config_path


# the two "basic" tests below are far from "unit" tests but they nicely test the whole flow


def test_crypt_basic(
    valid_config_pair,
    fixtures_path: Path,
    tmp_path: Path,
    fake_process: FakeProcess,
    fake_onemw_encrypt_image_tool,
):
    config_path, config_id = valid_config_pair
    unprotected_bundle_path = fixtures_path / "bundle-unprotected.tgz"
    protected_bundle_path = tmp_path / "bundle-protected.tgz"

    assert protected_bundle_path.exists() is False

    fake_process.allow_unregistered(True)

    crypt(config_path, config_id, unprotected_bundle_path, protected_bundle_path)

    assert protected_bundle_path.exists() is True
    assert tarfile.is_tarfile(protected_bundle_path) is True

    assert fake_process.call_count(fake_onemw_encrypt_image_tool) == 1


def test_decrypt_basic(
    valid_config_path,
    fixtures_path: Path,
    tmp_path: Path,
    fake_process: FakeProcess,
    fake_cryptsetup_reencrypt_decrypt_tool,
):
    protected_bundle_path = fixtures_path / "bundle-protected.tgz"
    unprotected_bundle_path = tmp_path / "bundle-unprotected.tgz"

    assert unprotected_bundle_path.exists() is False

    fake_process.allow_unregistered(True)

    decrypt(valid_config_path, protected_bundle_path, unprotected_bundle_path)

    assert unprotected_bundle_path.exists() is True
    assert tarfile.is_tarfile(unprotected_bundle_path) is True

    assert fake_process.call_count(fake_cryptsetup_reencrypt_decrypt_tool) == 1


def test_decrypt_bundle_config_fails_when_kid_not_in_header(
    fixtures_path: Path,
):
    # prepare bundle config without 'kid' in header
    key_path = fixtures_path / "keys" / "test" / "bundlecrypt-test-pubkey.pem"
    jwt = jwe.encrypt(
        plaintext=b"foobar", key=key_path.read_text(), algorithm="RSA-OAEP", kid=None
    )

    with pytest.raises(
        BundleCryptError, match="Unable to decrypt bundle config: 'kid' header missing"
    ):
        decrypt_bundle_config(None, jwt)


def test_verify_and_extract_bundle_config_fails_when_kid_not_in_header(valid_config):
    fake_jwt_headers = {"alg": "RS256"}
    fake_jwt_header = base64url_encode(json.dumps(fake_jwt_headers).encode())
    fake_jwt = b".".join([fake_jwt_header, b"", b""])

    with pytest.raises(
        BundleCryptError, match="Unable to verify bundle config: 'kid' header missing"
    ):
        verify_and_extract_bundle_config(valid_config, fake_jwt)


def test_verify_and_extract_bundle_config_fails_when_alg_not_in_header(valid_config):
    fake_jwt_headers = {"kid": "test"}
    fake_jwt_header = base64url_encode(json.dumps(fake_jwt_headers).encode())
    fake_jwt = b".".join([fake_jwt_header, b"", b""])

    with pytest.raises(
        BundleCryptError, match="Unable to verify bundle config: 'alg' header missing"
    ):
        verify_and_extract_bundle_config(valid_config, fake_jwt)


def prepare_config(config_dict, tmp_path):
    config_path = tmp_path / "bundlecrypt-config.json"
    config_path.write_text(json.dumps(config_dict))
    return BundleCryptConfig.parse(config_path, "test")


def test_rootfs_is_encrypted_when_enabled_in_configuration(
    valid_config_dict,
    tmp_path,
    rootfs_img_path,
    fake_process,
    fake_onemw_encrypt_image_tool,
):
    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-crypt"][
        "enabled"
    ] = True
    config = prepare_config(valid_config_dict, tmp_path)

    fake_process.register_subprocess(
        ["openssl", "rand", "-hex", "32"],
        stdout="db7768f7a645da48fb506ba406bc702155f843e0e37cfde909cab0514507bffb",
    )

    new_rootfs_path, encryption_key = encrypt_rootfs_image(
        config, rootfs_img_path, tmp_path
    )

    assert fake_process.call_count(fake_onemw_encrypt_image_tool) == 1
    assert encryption_key is not None


def test_rootfs_encryption_is_skipped_when_disabled_in_configuration(
    valid_config_dict,
    tmp_path,
    rootfs_img_path,
    fake_process,
    fake_onemw_encrypt_image_tool,
):
    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-crypt"][
        "enabled"
    ] = False
    config = prepare_config(valid_config_dict, tmp_path)

    new_rootfs_img_path, encryption_key = encrypt_rootfs_image(
        config, rootfs_img_path, tmp_path
    )

    assert fake_process.call_count(fake_onemw_encrypt_image_tool) == 0
    assert encryption_key is None


def test_rootfs_is_signed_when_enabled_in_configuration(
    valid_config_dict,
    tmp_path,
    rootfs_img_path,
    fake_process,
    fake_veritysetup_format_tool,
):
    (
        expected_verity_command,
        expected_verity_root_hash,
        expected_verity_salt,
    ) = fake_veritysetup_format_tool
    expected_verity_hash_offset = rootfs_img_path.stat().st_size
    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-verity"][
        "enabled"
    ] = True
    config = prepare_config(valid_config_dict, tmp_path)

    verity_salt, verity_root_hash, verity_hash_offset = add_verity_hash(
        config, rootfs_img_path
    )

    assert fake_process.call_count(expected_verity_command) == 1
    assert verity_salt == expected_verity_salt
    assert verity_root_hash == expected_verity_root_hash
    assert verity_hash_offset == expected_verity_hash_offset


def test_rootfs_signing_is_skipped_when_disabled_in_configuration(
    valid_config_dict,
    tmp_path,
    rootfs_img_path,
    fake_process,
    fake_veritysetup_format_tool,
):
    original_rootfs_img_size = rootfs_img_path.stat().st_size
    valid_config_dict["cryptConfigurations"]["test"]["rootfs"]["dm-verity"][
        "enabled"
    ] = False
    config = prepare_config(valid_config_dict, tmp_path)

    verity_salt, verity_root_hash, verity_hash_offset = add_verity_hash(
        config, rootfs_img_path
    )

    assert fake_process.call_count(fake_veritysetup_format_tool[0]) == 0
    assert verity_salt is verity_root_hash is verity_hash_offset is None
    assert rootfs_img_path.stat().st_size == original_rootfs_img_size


def test_bundle_config_is_signed_when_enabled_in_configuration(
    valid_config_dict, tmp_path, bundle_config_path
):
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jws"][
        "enabled"
    ] = True
    bundlecrypt_config = prepare_config(valid_config_dict, tmp_path)

    signed_bundle_config_path, bundle_config_is_signed = sign_bundle_config(
        bundlecrypt_config, bundle_config_path, tmp_path
    )

    assert signed_bundle_config_path.exists() is True
    assert signed_bundle_config_path.suffix == ".jwt"
    assert (
        jws.get_unverified_header(signed_bundle_config_path.read_text())["typ"] == "JWT"
    )
    assert bundle_config_is_signed is True


def test_bundle_config_signing_is_skipped_when_disabled_in_configuration(
    valid_config_dict, tmp_path, bundle_config_path
):
    original_bundle_config = bundle_config_path.read_text()
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jws"][
        "enabled"
    ] = False
    bundlecrypt_config = prepare_config(valid_config_dict, tmp_path)

    new_bundle_config_path, bundle_config_is_signed = sign_bundle_config(
        bundlecrypt_config, bundle_config_path, tmp_path
    )

    assert new_bundle_config_path.exists() is True
    assert new_bundle_config_path.suffix == ".json"
    assert new_bundle_config_path.read_text() == original_bundle_config
    assert bundle_config_is_signed is False


def test_bundle_config_is_encrypted_when_enabled_in_configuration(
    valid_config_dict, tmp_path, bundle_config_path
):
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jwe"][
        "enabled"
    ] = True
    bundlecrypt_config = prepare_config(valid_config_dict, tmp_path)

    new_bundle_config_path = encrypt_bundle_config(
        bundlecrypt_config, bundle_config_path, True, tmp_path
    )

    assert new_bundle_config_path.exists() is True
    assert new_bundle_config_path.suffix == ".jwt"
    assert jwe.get_unverified_header(new_bundle_config_path.read_text())["cty"] == "JWT"


def test_bundle_config_encryption_is_skipped_when_disabled_in_configuration(
    valid_config_dict, tmp_path, bundle_config_path
):
    original_bundle_config = bundle_config_path.read_text()
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jwe"][
        "enabled"
    ] = False
    bundlecrypt_config = prepare_config(valid_config_dict, tmp_path)

    new_bundle_config_path = encrypt_bundle_config(
        bundlecrypt_config, bundle_config_path, False, tmp_path
    )

    assert new_bundle_config_path.exists() is True
    assert new_bundle_config_path.suffix == ".json"
    assert new_bundle_config_path.read_text() == original_bundle_config


def test_bundle_config_is_created_in_output_folder_even_when_signing_and_encryption_is_disabled(
    valid_config_dict, tmp_path, bundle_config_path
):
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jws"][
        "enabled"
    ] = False
    valid_config_dict["cryptConfigurations"]["test"]["config.json"]["jwe"][
        "enabled"
    ] = False
    bundlecrypt_config = prepare_config(valid_config_dict, tmp_path)
    output_path = tmp_path / "output"
    output_path.mkdir()

    new_bundle_config_path = protect_bundle_config(
        bundlecrypt_config, bundle_config_path, output_path
    )

    assert new_bundle_config_path.parent == output_path
    assert new_bundle_config_path.suffix == ".json"


@pytest.fixture
def bundle_config():
    return {"annotations": {"org.opencontainers.image.os": "linux"}}


@pytest.fixture
def signed_bundle_config(bundle_config, keys_path):
    key_path = keys_path / "test" / "bundlecrypt-test-key.pem"
    return jws.sign(
        json.dumps(bundle_config).encode(),
        key=key_path.read_text(),
        headers={"cty": "JWT", "kid": "bundlecrypt-test-sign"},
        algorithm="RS256",
    )


def encrypt_data(data: bytes, key_path, is_nested):
    return jwe.encrypt(
        data,
        key=key_path.read_text(),
        algorithm="RSA-OAEP",
        encryption="A256CBC-HS512",
        cty="JWT" if is_nested else None,
        kid="bundlecrypt-test-enc",
    )


@pytest.fixture
def encrypted_bundle_config(bundle_config, keys_path):
    key_path = keys_path / "test" / "bundlecrypt-test-pubkey.pem"
    return encrypt_data(json.dumps(bundle_config), key_path, is_nested=False)


@pytest.fixture
def signed_and_encrypted_bundle_config(signed_bundle_config, keys_path):
    key_path = keys_path / "test" / "bundlecrypt-test-pubkey.pem"
    return encrypt_data(signed_bundle_config, key_path, is_nested=True)


def test_unprotect_bundle_config_with_signed_and_encrypted_config(
    key_store, tmp_path, signed_and_encrypted_bundle_config
):
    extracted_bundle_path = tmp_path
    extracted_bundle_config_path = extracted_bundle_path / "config.json.jwt"
    extracted_bundle_config_path.write_bytes(signed_and_encrypted_bundle_config)

    actual_bundle_config = unprotect_bundle_config(key_store, extracted_bundle_path)

    assert isinstance(actual_bundle_config, dict)


def test_unprotect_bundle_config_with_signed_config(
    key_store, tmp_path, signed_bundle_config
):
    extracted_bundle_path = tmp_path
    extracted_bundle_config_path = extracted_bundle_path / "config.json.jwt"
    extracted_bundle_config_path.write_text(signed_bundle_config)

    actual_bundle_config = unprotect_bundle_config(key_store, extracted_bundle_path)

    assert isinstance(actual_bundle_config, dict)


def test_unprotect_bundle_config_with_encrypted_config(
    key_store, tmp_path, encrypted_bundle_config
):
    extracted_bundle_path = tmp_path
    extracted_bundle_config_path = extracted_bundle_path / "config.json.jwt"
    extracted_bundle_config_path.write_bytes(encrypted_bundle_config)

    actual_bundle_config = unprotect_bundle_config(key_store, extracted_bundle_path)

    assert isinstance(actual_bundle_config, dict)


def test_unprotect_bundle_config_with_unprotected_config(
    key_store, tmp_path, bundle_config
):
    extracted_bundle_path = tmp_path
    extracted_bundle_config_path = extracted_bundle_path / "config.json"
    extracted_bundle_config_path.write_text(json.dumps(bundle_config))

    actual_bundle_config = unprotect_bundle_config(key_store, extracted_bundle_path)

    assert isinstance(actual_bundle_config, dict)


def test_verify_rootfs_hash_skips_verification_when_hash_offset_not_provided(
    fake_process,
):
    bundle_config = {
        "annotations": {
            "foo": "bar",
            # "org.rdk.dac.bundle.image.hashoffset": 4096,
            "org.rdk.dac.bundle.image.roothash": "hash",
        }
    }
    verify_rootfs_hash(None, bundle_config)
    fake_process.call_count == 0


def test_verify_rootfs_hash_skips_verification_when_root_hash_not_provided(
    fake_process,
):
    bundle_config = {
        "annotations": {
            "foo": "bar",
            "org.rdk.dac.bundle.image.hashoffset": 4096,
            # "org.rdk.dac.bundle.image.roothash": "hash"
        }
    }
    verify_rootfs_hash(None, bundle_config)
    fake_process.call_count == 0


def test_decrypt_rootfs_image_skips_decryption_when_image_key_not_provided(
    fake_process, tmp_path
):
    bundle_config = {
        "annotations": {
            "foo": "bar",
            # "org.rdk.dac.bundle.image.key": "key"
        }
    }
    decrypt_rootfs_image(None, bundle_config, tmp_path)
    fake_process.call_count == 0
