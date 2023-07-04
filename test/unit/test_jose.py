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

from jose.utils import base64url_decode

from bundlecrypt.jose import JOSE_SECURE_OPS


def decode_jws(token):
    header_segment, payload_segment, signature_segment = token.split(".", maxsplit=2)
    header_data = json.loads(base64url_decode(header_segment.encode()).decode())
    payload_data = base64url_decode(payload_segment.encode())
    return header_data, payload_data, signature_segment


def decode_jwe(token):
    (
        header_segment,
        encrypted_key_segment,
        iv_segment,
        cipher_text_segment,
        auth_tag_segment,
    ) = token.split(b".", 4)
    header_data = base64url_decode(header_segment).decode()
    return header_data


def test_jws_sign(keys_path):
    key_path = keys_path / "test" / "bundlecrypt-test-key.pem"
    expected_payload = b"payload"
    token = JOSE_SECURE_OPS.jws_sign(
        payload=expected_payload,
        key=key_path.read_text(),
        headers={"foo": "bar"},
        algorithm="RS256",
    )

    header, actual_payload, signature = decode_jws(token)

    assert header == {"alg": "RS256", "foo": "bar", "typ": "JWT"}
    assert actual_payload == expected_payload
    assert (
        signature
        == "iGg1vXHr8_wN7WyuG-g4TxS4-cbWi7f9Ze-3k2e60q_oT-HZWsOE-eGSWxNewbU9fUxI4TYS1Ms3INw791KIh-fOjzqeIcyUsQYKibCJaSNnSKfUR8zvnaLjxqD-T3uqFKHjYEK8cfDMz8cujbaXg_sMtEs5NzioXZSZTHKNuTCG7foi2apRzY9mpaVy_srzE_-7NERddH9NWqB85SaGVXUz4DJqTNI2bo2qGTf2hJyY2-z5RLUSkiG7glE_GZyMfIQn04Ar-fTmNlEg5pG0kr99XLqlOfasi1Yb3v4exf3hNJButh-6Lc93yIuEgYpd-e_oRiv0tMdh-MwiLwwS-_rF0HPPXLv4N1GT09-wj95o7A56TsBEZSax-T4vcig8LUbU0fqas18hsiq54UKfrpEIC3sLB5VijyE-r6yOgw9NbcDY_fQ_KyKIz480yJEHuEBApk6ZcjIrXzg06xngSSg2NV7V7EIsvgvk-n3nNwIpQAZxH7XJ0w2Pxl0X_sr5_naO3HiwyQXTFSwqZYS-aTKvObtMHwmPxdcx5zYFpVtNxx0CVstiu48iH1mRsymRew7labznmaqNpTaycG4H_2TOtmHxjPmdFWAb61HwwrGUHd7GuJx2iI1S7ARcSrZ3UfgsO30p_-YAwVuL84F2G6XGiir1yzihfggmOxWbsDM"
    )


def test_jwe_decrypt(fixtures_path, keys_path):
    token = fixtures_path / "jose" / "jwe-token.txt"
    private_key_path = keys_path / "test" / "bundlecrypt-test-key.pem"

    payload = JOSE_SECURE_OPS.jwe_decrypt(
        token=token.read_text(), key=private_key_path.read_text()
    )

    assert payload == b"payload"
