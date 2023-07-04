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

from click.testing import CliRunner

import bundlecrypt.cli
from bundlecrypt.cli import crypt, decrypt


def test_crypt_command(valid_config_pair, tmp_path, monkeypatch):
    valid_config_path, valid_config_id = valid_config_pair
    unprotected_bundle_path = tmp_path / "bundle-unprotected.tgz"
    unprotected_bundle_path.touch()
    protected_bundle_path = tmp_path / "bundle-protected.tgz"

    def crypt_impl_mock(*args):
        assert args[0] == valid_config_path
        assert args[1] == valid_config_id
        assert args[2] == unprotected_bundle_path
        assert args[3] == protected_bundle_path

    monkeypatch.setattr(bundlecrypt.cli, "crypt_impl", crypt_impl_mock)

    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(
            crypt,
            [
                "--config",
                valid_config_path,
                "--id",
                valid_config_id,
                str(unprotected_bundle_path),
                str(protected_bundle_path),
            ],
        )
    assert result.exit_code == 0


def test_decrypt_command(valid_config_path, tmp_path, monkeypatch):
    protected_bundle_path = tmp_path / "bundle-protected.tgz"
    protected_bundle_path.touch()
    unprotected_bundle_path = tmp_path / "bundle-unprotected.tgz"

    def decrypt_impl_mock(*args):
        assert args[0] == valid_config_path
        assert args[1] == protected_bundle_path
        assert args[2] == unprotected_bundle_path

    monkeypatch.setattr(bundlecrypt.cli, "decrypt_impl", decrypt_impl_mock)

    runner = CliRunner()
    with runner.isolated_filesystem(temp_dir=tmp_path):
        result = runner.invoke(
            decrypt,
            [
                "--config",
                valid_config_path,
                str(protected_bundle_path),
                str(unprotected_bundle_path),
            ],
        )
    assert result.exit_code == 0
