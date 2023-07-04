#!/bin/bash

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

set -euo pipefail

ONEMW_LOOP_DEVICES_FOR_CRYPTSETUP=4
ONEMW_LOOP_DEVICES_RESERVE=4

log_cmd() {
    (
        set -x
        "$@"
    )
}

fix_loop_devices() {
    local expected_free=$((ONEMW_LOOP_DEVICES_FOR_CRYPTSETUP + ONEMW_LOOP_DEVICES_RESERVE))
    local used total actual_free

    used=$(losetup --all | wc -l)
    total=$(find /dev/ -maxdepth 1 -name 'loop[0-9]*' | wc -l)
    actual_free=$((total - used))

    if [[ $actual_free -lt $expected_free ]]; then
        echo "[ONEM-19693] creating loop devices for cryptsetup (expected free: $expected_free, actual free: $actual_free)"

        local major minor

        # ensure we have at least one loop device, otherwise we won't be able to determine the major...
        log_cmd sudo losetup -f >/dev/null

        major=$(grep -E '^\s+[0-9]+ loop$' /proc/devices | awk '{ print $1 }')
        for minor in $(seq $total $((total + expected_free - actual_free - 1))); do
            if [ -e /dev/loop$minor ]; then
                continue
            fi
            log_cmd sudo mknod /dev/loop$minor b $major $minor
            log_cmd sudo chown --reference=/dev/loop0 /dev/loop$minor
            log_cmd sudo chmod --reference=/dev/loop0 /dev/loop$minor
        done
    fi
}

fix_loop_devices
