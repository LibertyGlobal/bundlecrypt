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

import logging
import os
import pathlib
import subprocess

import coloredlogs


logger = logging.getLogger(__name__)


def configure_logging(verbose_logging):
    coloredlogs.install(level=logging.DEBUG if verbose_logging else logging.INFO)


def get_tmpdir_root():
    tmpdir_root = pathlib.Path(os.environ.get("BUNDLECRYPT_TMPDIR", "/tmp"))
    tmpdir_root.mkdir(parents=True, exist_ok=True)
    return tmpdir_root


def run(args, **subprocess_opts):
    logger.debug(f"Executing {args}")

    # so the idea for logging here is:
    # - if verbose logging is enabled (log level is DEBUG) then don't capture output (pass-through to console or
    #   whatever is attached to stdout/stder)
    # - otherwise capture output and log it only in case of an error

    if not logger.isEnabledFor(logging.DEBUG):
        subprocess_opts["capture_output"] = True

    try:
        completed_process = subprocess.run(args, check=True, **subprocess_opts)
    except subprocess.CalledProcessError as error:
        logger.error(error)
        if error.stdout is not None:
            logger.error(f"Process stdout:\n{error.stdout.decode()}")
        if error.stderr is not None:
            logger.error(f"Process stderr:\n{error.stderr.decode()}")
        raise

    return completed_process
