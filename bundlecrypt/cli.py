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

import pathlib

import click

from .core import crypt as crypt_impl, decrypt as decrypt_impl
from .utils import configure_logging


@click.group()
def cli():
    pass  # pragma: no cover


@cli.command()
@click.option(
    "--config",
    "bundlecrypt_config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    help="path to bundlecrypt config file",
)
@click.option(
    "--id",
    "bundlecrypt_config_id",
    required=True,
    help="bundlecrypt configuration identifier",
)
@click.argument(
    "unprotected-bundle-path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.argument(
    "protected-bundle-image-path",
    type=click.Path(dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--verbose",
    "verbose_logging",
    default=False,
    help="enable verbose logging",
    is_flag=True,
)
@click.option(
    "--remove-other-permissions",
    "remove_other_permissions",
    default=False,
    help="remove file permissions for 'other' users on files and dirs",
    is_flag=True,
)
@click.option(
    "--uid",
    "uid",
    type=int,
    help="force uid for files in encrypted filesystem",
)
@click.option(
    "--gid",
    "gid",
    type=int,
    help="force gid for files in encrypted filesystem",
)
def crypt(
    bundlecrypt_config_path,
    bundlecrypt_config_id,
    unprotected_bundle_path,
    protected_bundle_image_path,
    verbose_logging,
    uid,
    gid,
    remove_other_permissions
):
    configure_logging(verbose_logging)

    crypt_impl(
        bundlecrypt_config_path,
        bundlecrypt_config_id,
        unprotected_bundle_path,
        protected_bundle_image_path,
        uid,
        gid,
        remove_other_permissions
    )


@cli.command()
@click.option(
    "--config",
    "bundlecrypt_config_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    help="path to bundlecrypt config file",
)
@click.argument(
    "protected-bundle-image-path",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
)
@click.argument(
    "unprotected-bundle-path",
    type=click.Path(dir_okay=False, path_type=pathlib.Path),
)
@click.option(
    "--verbose",
    "verbose_logging",
    default=False,
    help="enable verbose logging",
    is_flag=True,
)
def decrypt(
    bundlecrypt_config_path,
    protected_bundle_image_path,
    unprotected_bundle_path,
    verbose_logging,
):
    configure_logging(verbose_logging)

    decrypt_impl(
        bundlecrypt_config_path,
        protected_bundle_image_path,
        unprotected_bundle_path,
    )


if __name__ == "__main__":
    cli()  # pragma: no cover
