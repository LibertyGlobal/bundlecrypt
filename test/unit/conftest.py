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
import pathlib

import pytest

from bundlecrypt.config import BundleCryptConfig
from bundlecrypt.keystore import KeyStore


@pytest.fixture
def fixtures_path(request):
    tests_path = pathlib.Path(request.fspath).parent
    fixtures_path = tests_path / "fixtures"
    return fixtures_path


@pytest.fixture(autouse=True)
def keys_path(fixtures_path, monkeypatch):
    keys_path = fixtures_path / "keys"
    monkeypatch.setenv("BUNDLECRYPT_KEYSDIR", str(keys_path))
    return keys_path


@pytest.fixture
def valid_config_path(fixtures_path):
    config_path = fixtures_path / "bundlecrypt-config.json"
    return config_path


@pytest.fixture
def valid_config_pair(valid_config_path):
    config_id = "test"
    return valid_config_path, config_id


@pytest.fixture
def valid_config(valid_config_pair):
    config_path, config_id = valid_config_pair
    return BundleCryptConfig.parse(config_path, config_id)


@pytest.fixture
def valid_config_dict(valid_config_path):
    return json.loads(valid_config_path.read_text())


@pytest.fixture
def key_store(valid_config_path):
    config = json.loads(valid_config_path.read_text())
    return KeyStore(valid_config_path, config["keys"])
