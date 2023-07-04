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
import os
import pathlib
import re
import shutil
import tempfile
from base64 import b64decode as base64_decode, b64encode as base64_encode

import jose.constants
from jose import jwe, jws
from jose.utils import base64url_decode

from .config import BundleCryptConfig, KeyStore
from .exceptions import BundleCryptError
from .jose import JOSE_SECURE_OPS
from .utils import get_tmpdir_root, run


logger = logging.getLogger(__name__)

# python-jose's backends other than "cryptography" don't support the RSA-OAEP algorithm
# so let's check if we're using the right backend
EXPECTED_ALGORITHMS = {"RSA-OAEP"}
assert EXPECTED_ALGORITHMS.issubset(jose.constants.ALGORITHMS.SUPPORTED)

MKSQUASHFS_OPTS = []

# based on appmodules-signer-docker/templates/tools/am-signing/sign_appmodule.py:
# - https://bitbucket.upc.biz/projects/SIGN/repos/appmodules-signer-docker/browse/templates/tools/am-signing/sign_appmodule.py?until=35012cf8777e3a13555a1c915898a91cd82aeb29&untilPath=templates%2Ftools%2Fam-signing%2Fsign_appmodule.py#90
# - https://bitbucket.upc.biz/projects/SIGN/repos/appmodules-signer-docker/browse/templates/tools/am-signing/sign_appmodule.py?until=35012cf8777e3a13555a1c915898a91cd82aeb29&untilPath=templates%2Ftools%2Fam-signing%2Fsign_appmodule.py#271
ROOTFS_IMAGE_ENCRYPTION_KEY_LENGTH = 32
ROOTFS_IMAGE_ENCRYPTION_ITER_TIME_MS = 1
ROOTFS_IMAGE_ENCRYPTION_CIPHER = "aes-xts-plain64"
ROOTFS_IMAGE_ENCRYPTION_HASH = "sha256"


def extract_bundle(bundle, tmpdir_path):
    extracted_bundle_path = tmpdir_path / "extracted-bundle"
    logger.info(f"Extracting bundle to {extracted_bundle_path}")
    os.makedirs(extracted_bundle_path)
    run(["tar", "-xf", bundle, "-C", extracted_bundle_path])
    return extracted_bundle_path


def remove_permissions_other(extracted_bundle_path):
    logger.info(
        f"Removing file permissions for 'other' users from {extracted_bundle_path}"
    )
    run(["chmod", "-R", "o-rwx", extracted_bundle_path])


def create_rootfs_image(rootfs_path, tmpdir_path, uid, gid):
    rootfs_img_path = tmpdir_path / "rootfs.img"
    logger.info("Creating rootfs image")
    args = ["mksquashfs", rootfs_path, rootfs_img_path, *MKSQUASHFS_OPTS]
    if uid is not None:
        args.append("-force-uid")
        args.append(str(uid))
    if gid is not None:
        args.append("-force-gid")
        args.append(str(gid))
    run(args)
    return rootfs_img_path


def generate_random_key(key_path):
    logger.info("Generating random key for rootfs image encryption")
    completed_process = run(
        [
            "openssl",
            "rand",
            "-hex",
            str(ROOTFS_IMAGE_ENCRYPTION_KEY_LENGTH),
        ],
        capture_output=True,
    )
    key_bytes = completed_process.stdout
    key_bytes = key_bytes.rstrip(
        b"\n"
    )  # a newline is added by openssl to the output but it's not part of the key

    # ONEM-19437: dmcrypt-rdk fails randomly with 255 exit code without any log
    # see https://gerrit.onemw.net/c/sign/appmodules-signer-docker/+/76484
    assert b"\n" not in key_bytes

    key_path.write_bytes(key_bytes)
    return key_bytes


def encrypt_rootfs_image(bundlecrypt_config, rootfs_img_path, tmpdir_path):
    if not bundlecrypt_config.should_encrypt_rootfs():
        logger.warning("Encrypting rootfs is disabled in configuration, skipping...")
        return rootfs_img_path, None

    key_path = tmpdir_path / "rootfs.key"
    key_bytes = generate_random_key(key_path)

    logger.info("Encrypting rootfs image")

    encrypted_rootfs_img_path = rootfs_img_path.parent / (
        rootfs_img_path.name + ".enc"  # dmcrypt-rdk adds ".enc" suffix
    )

    with open(key_path) as key_file:
        run(
            [
                "/usr/sbin/dmcrypt-rdk",
                rootfs_img_path.name,
                str(ROOTFS_IMAGE_ENCRYPTION_ITER_TIME_MS),
                ROOTFS_IMAGE_ENCRYPTION_CIPHER,
                ROOTFS_IMAGE_ENCRYPTION_HASH,
                "reduced",
            ],
            cwd=str(rootfs_img_path.parent),
            stdin=key_file,
        )

    encrypted_rootfs_img_path = encrypted_rootfs_img_path.rename(
        encrypted_rootfs_img_path.parent
        / "rootfs.img"  # as expected to be named in OCI Bundle Image
    )
    return encrypted_rootfs_img_path, key_bytes


# based on https://bitbucket.upc.biz/projects/SIGN/repos/appmodules-signer-docker/browse/templates/tools/am-signing/sign_appmodule.py#298
def add_verity_hash(bundlecrypt_config, image_path):
    if not bundlecrypt_config.should_add_rootfs_hash():
        logger.warning(
            "Rootfs authentication is disabled in configuration, skipping..."
        )
        return None, None, None

    logger.info(f"Adding hash to rootfs image")
    hash_offset = image_path.stat().st_size
    completed_process = run(
        [
            "veritysetup",
            "format",
            image_path,
            image_path,
            f"--hash-offset={hash_offset}",
        ],
        capture_output=True,
    )
    stdout = completed_process.stdout.decode()

    salt = re.search(r"^Salt:\s*(\w+)$", stdout, re.MULTILINE).group(1)
    root_hash = re.search(r"^Root hash:\s*(\w+)$", stdout, re.MULTILINE).group(1)
    logger.debug(f"Got dm-verity salt: {salt}, root hash: {root_hash}")
    return salt, root_hash, hash_offset


def add_annotations_to_config(
    bundle_config_path,
    rootfs_encryption_key_bytes,
    verity_salt,
    verity_root_hash,
    verity_hash_offset,
):
    bundlecrypt_annotations = {}

    if rootfs_encryption_key_bytes is not None:
        bundlecrypt_annotations["org.rdk.dac.bundle.image.key"] = base64_encode(
            rootfs_encryption_key_bytes
        ).decode()

    if verity_root_hash is not None:
        assert verity_hash_offset is not None
        assert verity_salt is not None
        bundlecrypt_annotations["org.rdk.dac.bundle.image.roothash"] = verity_root_hash
        bundlecrypt_annotations[
            "org.rdk.dac.bundle.image.hashoffset"
        ] = str(verity_hash_offset)
        bundlecrypt_annotations["org.rdk.dac.bundle.image.salt"] = verity_salt

    logger.info(f"Adding bundlecrypt annotations to config.json")

    bundle_config = json.loads(bundle_config_path.read_text())
    annotations = bundle_config.setdefault("annotations", {})
    annotations.update(bundlecrypt_annotations)
    bundle_config_path.write_text(json.dumps(bundle_config))


def extract_and_dump_jws_header(token):
    if isinstance(token, str):
        token = token.encode("utf-8")
    header_segment, signing_input, crypto_segment = token.split(b".", 2)
    header_data = base64url_decode(header_segment).decode()
    logger.debug(f"JWS header: {header_data}")
    return json.loads(header_data)


def sign_bundle_config(bundlecrypt_config, bundle_config_path, tmpdir_path):
    if not bundlecrypt_config.should_sign_config():
        logger.warning("Signing config.json is disabled in configuration, skipping...")
        return bundle_config_path, False

    key_id = bundlecrypt_config.get_config_signing_key_id()

    logger.info(f"Signing config.json using '{key_id}' key")

    signed_bundle_config = JOSE_SECURE_OPS.jws_sign(
        payload=bundle_config_path.read_bytes(),
        key=bundlecrypt_config.get_config_signing_private_key(),
        headers={
            "kid": key_id,
            "x5t": bundlecrypt_config.get_config_signing_certificate_sha1_thumbprint(),
        },
        algorithm=bundlecrypt_config.get_config_signing_algorithm(),
    )

    extract_and_dump_jws_header(signed_bundle_config)

    signed_bundle_config_path = tmpdir_path / "config.json.jwt"
    logger.debug(f"Saving signed bundle config to {signed_bundle_config_path}")
    signed_bundle_config_path.write_text(signed_bundle_config)
    return signed_bundle_config_path, True


def extract_and_dump_jwe_header(token):
    (
        header_segment,
        encrypted_key_segment,
        iv_segment,
        cipher_text_segment,
        auth_tag_segment,
    ) = token.split(b".", 4)
    header_data = base64url_decode(header_segment).decode()
    logger.debug(f"JWE header: {header_data}")
    return json.loads(header_data)


def encrypt_bundle_config(
    bundlecrypt_config, bundle_config_path, bundle_config_is_signed, tmpdir_path
):
    if not bundlecrypt_config.should_encrypt_config():
        logger.warning(
            "Encrypting config.json is disabled in configuration, skipping..."
        )
        return bundle_config_path

    key_id = bundlecrypt_config.get_config_encryption_key_id()

    logger.info(f"Encrypting config.json using '{key_id}' key")

    encrypted_bundle_config = jwe.encrypt(
        plaintext=bundle_config_path.read_bytes(),
        key=bundlecrypt_config.get_config_encryption_public_key(),
        encryption=bundlecrypt_config.get_config_encryption_encryption(),
        algorithm=bundlecrypt_config.get_config_encryption_algorithm(),
        cty="JWT"
        if bundle_config_is_signed
        else None,  # as per https://wikiprojects.upc.biz/display/CTOM/DAC+Security
        kid=key_id,
    )

    extract_and_dump_jwe_header(encrypted_bundle_config)

    encrypted_bundle_config_path = tmpdir_path / "config.json.jwt"
    logger.debug(f"Saving encrypted bundle config to {encrypted_bundle_config_path}")
    encrypted_bundle_config_path.write_bytes(encrypted_bundle_config)
    return encrypted_bundle_config_path


def protect_bundle_config(bundlecrypt_config, bundle_config_path, tmpdir_path):
    bundle_config_path, bundle_config_is_signed = sign_bundle_config(
        bundlecrypt_config, bundle_config_path, tmpdir_path
    )

    bundle_config_path = encrypt_bundle_config(
        bundlecrypt_config, bundle_config_path, bundle_config_is_signed, tmpdir_path
    )

    # if no JWS/JWE has been applied, we need to move the source bundle config to a folder which will be used as
    # the root folder when creating the protected DAC bundle image
    if bundle_config_path.suffix != ".jwt":
        shutil.move(str(bundle_config_path), str(tmpdir_path))
        bundle_config_path = tmpdir_path / bundle_config_path.name

    return bundle_config_path


def extract_public_annotations(bundle_config_path, tmpdir_path):
    """
    Extract the annotations starting with 'public.' into un-encrypted file
    'annotations.json'. Return the path to the file. None
    if no file created (i.e. when no such annotations extracted).
    """
    public_annotations_path = tmpdir_path / "annotations.json"
    public_annotations = {}
    bundle_config = json.loads(bundle_config_path.read_text())
    if bundle_config.get('annotations'):
        for key, value in bundle_config['annotations'].items():
            if key.startswith("public."):
                public_annotations[key] = value
    if len(public_annotations) > 0:
        public_annotations_path.write_text(json.dumps({
            'annotations': public_annotations
        }))
        return public_annotations_path
    else:
        return None


def create_bundle_image(
    artifacts_root_path,
    encrypted_rootfs_image_name,
    encrypted_bundle_config_name,
    public_annotations_name,
    protected_bundle_path,
):
    logger.info(f"Creating bundle image in {protected_bundle_path}")
    args = [
        "tar",
        "-czf",
        protected_bundle_path,
        "-C",
        artifacts_root_path,
        encrypted_rootfs_image_name,
        encrypted_bundle_config_name,
    ]
    if public_annotations_name:
        args.append(public_annotations_name)
    run(args)


def decrypt_bundle_config(key_store: KeyStore, encrypted_bundle_config: bytes):
    jwe_header = extract_and_dump_jwe_header(encrypted_bundle_config)
    key_id = jwe_header.get("kid")
    if key_id is None:
        raise BundleCryptError("Unable to decrypt bundle config: 'kid' header missing")

    logger.info(f"Decrypting config.json using '{key_id}' key from JWE header")

    return JOSE_SECURE_OPS.jwe_decrypt(
        token=encrypted_bundle_config.decode(),
        key=key_store.get_private_key(key_id),
    )


def verify_and_extract_bundle_config(key_store: KeyStore, bundle_config_jws):
    jws_header = extract_and_dump_jws_header(bundle_config_jws)
    key_id = jws_header.get("kid")
    if key_id is None:
        raise BundleCryptError("Unable to verify bundle config: 'kid' header missing")
    algorithm = jws_header.get("alg")
    if algorithm is None:
        raise BundleCryptError("Unable to verify bundle config: 'alg' header missing")

    logger.info(f"Verifying config.json signature using '{key_id}' from JWS header")

    return jws.verify(
        token=bundle_config_jws,
        key=key_store.get_cert_or_public_key(key_id),
        algorithms=algorithm,
    )


def unprotect_bundle_config(key_store, extracted_bundle_path):
    # bundle config may be encrypted, signed, both or unprotected... we need to detect that and act accordingly...

    bundle_config_path = extracted_bundle_path / "config.json.jwt"
    if bundle_config_path.exists():
        jwt_token = bundle_config_path.read_bytes()
        jwt_segments = jwt_token.split(b".", maxsplit=1)
        jwt_headers = json.loads(base64url_decode(jwt_segments[0]))

        if "enc" in jwt_headers:
            data = decrypt_bundle_config(key_store, jwt_token)
            is_jws = jwt_headers.get("cty") == "JWT"
        else:
            logger.warning("Skipping bundle config decryption")
            data = jwt_token
            is_jws = True

        if is_jws:
            jwt_token = data
            bundle_config = verify_and_extract_bundle_config(key_store, jwt_token)
        else:
            logger.warning("Skipping bundle config signature verification")
            bundle_config = data.decode()
    else:
        logger.warning(
            "Bundle config is not JWT - skipping decryption and signature verification"
        )
        bundle_config_path = extracted_bundle_path / "config.json"
        bundle_config = bundle_config_path.read_text()

    return json.loads(bundle_config)


def verify_rootfs_hash(rootfs_image_path, bundle_config):
    hash_offset = bundle_config["annotations"].get(
        "org.rdk.dac.bundle.image.hashoffset"
    )
    rootfs_hash = bundle_config["annotations"].get("org.rdk.dac.bundle.image.roothash")

    if not (hash_offset and rootfs_hash):
        logger.warning(
            "Hash offset or rootfs hash missing in annotations - skipping rootfs hash verification"
        )
        return

    logger.info("Verifying rootfs image hash")
    run(
        [
            "veritysetup",
            "verify",
            f"--hash-offset={hash_offset}",
            rootfs_image_path,
            rootfs_image_path,
            rootfs_hash,
        ]
    )


def decrypt_rootfs_image(encrypted_rootfs_image_path, bundle_config, tmpdir_path):
    image_key_base64 = bundle_config["annotations"].get("org.rdk.dac.bundle.image.key")

    if not image_key_base64:
        logger.warning("Image key missing in annotations - skipping rootfs decryption")
        return encrypted_rootfs_image_path

    image_key_bytes = base64_decode(image_key_base64.encode())
    image_key_path = tmpdir_path / "rootfs.key"
    logger.debug(f"Saving rootfs image key to {image_key_path}")
    image_key_path.write_bytes(image_key_bytes)

    command = [
        "--decrypt",
        encrypted_rootfs_image_path,
        "--key-file",
        image_key_path,
    ]

    if os.path.exists("/sbin/cryptsetup-reencrypt"):
        command.insert(0, "/sbin/cryptsetup-reencrypt")
    else:
        command.insert(0, "/sbin/cryptsetup")
        command.insert(1, "reencrypt")

    logger.info(f"Decrypting rootfs image using: {command[0]}")

    if os.getuid() != 0:
        command.insert(0, "sudo")

    run(command)

    return encrypted_rootfs_image_path


def extract_rootfs_image(rootfs_image_path, tmpdir_path):
    extracted_rootfs_path = tmpdir_path / "rootfs"
    logger.info(f"Extracting rootfs image")
    run(["unsquashfs", "-dest", extracted_rootfs_path, rootfs_image_path])
    return extracted_rootfs_path


def remove_annotations_from_config(bundle_config):
    annotations = bundle_config["annotations"]
    annotations.pop("org.rdk.dac.bundle.image.key", None)
    annotations.pop("org.rdk.dac.bundle.image.roothash", None)
    annotations.pop("org.rdk.dac.bundle.image.hashoffset", None)
    annotations.pop("org.rdk.dac.bundle.image.salt", None)
    return bundle_config


def create_bundle_raw(
    artifacts_root_path, extracted_rootfs_path, bundle_config, unprotected_bundle_path
):
    # artifacts root will be our root for creating a 'tar' archive below,
    # here we make sure the extracted rootfs folder is a direct child
    assert extracted_rootfs_path.parent == artifacts_root_path

    bundle_config_path = artifacts_root_path / "config.json"
    logger.debug(f"Saving bundle config in {bundle_config_path}")
    bundle_config_path.write_text(json.dumps(bundle_config))

    logger.info(f"Creating bundle in {unprotected_bundle_path}")
    run(
        [
            "tar",
            "-cf",
            unprotected_bundle_path,
            "-C",
            artifacts_root_path,
            bundle_config_path.name,
            extracted_rootfs_path.name,
        ]
    )


def crypt(
    bundlecrypt_config_path,
    bundlecrypt_config_id,
    unprotected_bundle_path,
    protected_bundle_image_path,
    uid=None,
    gid=None,
    remove_other_permissions=False,
):
    bundlecrypt_config = BundleCryptConfig.parse(
        bundlecrypt_config_path, bundlecrypt_config_id
    )

    tmpdir_root = get_tmpdir_root()
    with tempfile.TemporaryDirectory(dir=tmpdir_root) as tmpdir_name:
        tmpdir_path = pathlib.Path(tmpdir_name)

        extracted_bundle_path = extract_bundle(unprotected_bundle_path, tmpdir_path)

        if remove_other_permissions:
            remove_permissions_other(extracted_bundle_path)

        rootfs_image_path = create_rootfs_image(
            extracted_bundle_path / "rootfs", tmpdir_path, uid, gid
        )
        encrypted_rootfs_image_path, rootfs_encryption_key_bytes = encrypt_rootfs_image(
            bundlecrypt_config, rootfs_image_path, tmpdir_path
        )

        verity_salt, verity_root_hash, verity_hash_offset = add_verity_hash(
            bundlecrypt_config, encrypted_rootfs_image_path
        )

        bundle_config_path = extracted_bundle_path / "config.json"

        add_annotations_to_config(
            bundle_config_path,
            rootfs_encryption_key_bytes,
            verity_salt,
            verity_root_hash,
            verity_hash_offset,
        )

        public_annotations_path = extract_public_annotations(
            bundle_config_path, tmpdir_path
        )

        bundle_config_path = protect_bundle_config(
            bundlecrypt_config, bundle_config_path, tmpdir_path
        )

        create_bundle_image(
            tmpdir_path,
            encrypted_rootfs_image_path.name,
            bundle_config_path.name,
            public_annotations_path.name if public_annotations_path else None,
            protected_bundle_image_path,
        )
    logger.info("Success!")


def decrypt(
    bundlecrypt_config_path,
    protected_bundle_image_path,
    unprotected_bundle_path,
):
    key_store: KeyStore = BundleCryptConfig.parse(
        bundlecrypt_config_path, config_id=None
    )

    tmpdir_root = get_tmpdir_root()
    with tempfile.TemporaryDirectory(dir=tmpdir_root) as tmpdir_name:
        tmpdir_path = pathlib.Path(tmpdir_name)

        extracted_bundle_path = extract_bundle(protected_bundle_image_path, tmpdir_path)

        encrypted_rootfs_image_path = extracted_bundle_path / "rootfs.img"

        bundle_config = unprotect_bundle_config(key_store, extracted_bundle_path)

        verify_rootfs_hash(encrypted_rootfs_image_path, bundle_config)

        rootfs_image_path = decrypt_rootfs_image(
            encrypted_rootfs_image_path, bundle_config, tmpdir_path
        )

        extracted_rootfs_path = extract_rootfs_image(rootfs_image_path, tmpdir_path)

        bundle_config = remove_annotations_from_config(bundle_config)

        create_bundle_raw(
            tmpdir_path, extracted_rootfs_path, bundle_config, unprotected_bundle_path
        )
    logger.info("Success!")
