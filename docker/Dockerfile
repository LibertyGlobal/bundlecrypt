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

FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
        && apt-get install -y --no-install-recommends \
            cryptsetup-bin \
            python3.8 \
            python3.8-distutils \
            python3.8-venv \
            openssl \
            squashfs-tools \
            build-essential \
            cmake

COPY dmcrypt-rdk/ /tmp/dmcrypt-rdk/

RUN mkdir -p /tmp/dmcrypt-rdk/.build/

RUN (cd /tmp/dmcrypt-rdk/.build \
     && cmake \
        -DCPACK_GENERATOR=DEB \
        -DCMAKE_INSTALL_PREFIX:PATH=/usr \
        -DVERSION=1.0 \
        .. \
     && cmake --build . --target package)

RUN apt remove -y build-essential cmake

RUN apt-get update \
        && apt install -y /tmp/dmcrypt-rdk/.build/dmcrypt-rdk_1.0_amd64.deb

COPY docker/entrypoint.sh /

RUN python3.8 -m venv /venv
RUN /venv/bin/pip install --upgrade pip pip-tools

COPY requirements.txt /usr/local/src/bundlecrypt/requirements.txt
RUN /venv/bin/pip-sync /usr/local/src/bundlecrypt/requirements.txt

COPY setup.py /usr/local/src/bundlecrypt/setup.py
COPY bundlecrypt /usr/local/src/bundlecrypt/bundlecrypt
RUN cd /usr/local/src/bundlecrypt && /venv/bin/pip install .

CMD ["bundlecrypt"]
ENTRYPOINT ["/entrypoint.sh"]
