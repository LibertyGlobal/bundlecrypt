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

from subprocess import CalledProcessError

import pytest
from pytest_subprocess import FakeProcess

from bundlecrypt.utils import run


def test_run_logs_stdout_and_stderr_to_log(fake_process: FakeProcess, caplog):
    fake_process.register_subprocess(
        ["ls"], returncode=1, stdout="some stdout message", stderr="some stderr message"
    )

    with pytest.raises(CalledProcessError):
        run(["ls"])

    assert "Command '['ls']' returned non-zero exit status 1." in caplog.messages
    assert "Process stdout:\nsome stdout message" in caplog.messages
    assert "Process stderr:\nsome stderr message" in caplog.messages
