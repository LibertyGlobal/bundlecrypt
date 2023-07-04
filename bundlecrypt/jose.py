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

from jose import jwe, jws


# This class provides JSON Object Signing and Encryption (JOSE) implementation of operations which deal with private key
# material. Currently it relies on having the private keys in memory, but the idea is that it could be integrated with
# a HSM at some point, so that private keys would not be accessible outside of HSM. When that happens, cryptographic
# operations will need to be delegated to the HSM, but the rest like base64url transformations for JWS/JWE Compact
# Serialization will still need to be implemented here.
class JOSESecureOperations:
    def jws_sign(self, payload: bytes, key: str, headers: dict, algorithm: str):
        return jws.sign(
            payload=payload,
            key=key,
            headers=headers,
            algorithm=algorithm,
        )

    def jwe_decrypt(self, token: str, key: str):
        return jwe.decrypt(jwe_str=token, key=key)


JOSE_SECURE_OPS = JOSESecureOperations()
