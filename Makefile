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

INTERACTIVE := $(shell [ -t 0 ] && echo --interactive)

.PHONY: venv

venv: fix-loop-devices
	python3 -m venv venv
	. venv/bin/activate \
		&& pip install --upgrade pip pip-tools \
		&& pip-sync requirements.txt dev-requirements.txt \
		&& pip install -e '.' \

image:
	make -C docker image

dmcrypt-rdk:
	make -C docker dmcrypt-rdk

demo-inotify: image fix-loop-devices
	./demos/demo-inotify/run-demo.sh

demo-rabbitmq: image fix-loop-devices
	./demos/demo-rabbitmq/run-demo.sh

test-unit:
	venv/bin/pytest --cov bundlecrypt --cov-report term-missing --cov-fail-under 95 test/unit

test-unit-cov-report:
	venv/bin/pytest --cov bundlecrypt --cov-report html test/unit
	if which sensible-browser >/dev/null; then \
	    sensible-browser htmlcov/index.html; \
	fi

test-interop: test-encrypt
	make -C test/interoperability

CONFIG_PATH ?= /configs/config.json
CONFIG_ID ?= test
VERBOSE ?= --verbose
ENCRYPT_INPUT_FILE ?= /examples/bundle.tgz
ENCRYPT_OUTPUT_FILE ?= /out/bundle-image.tar
DOCKER_CMD ?= $(shell which podman || which docker)

test-encrypt: image fix-loop-devices
	mkdir -p $(PWD)/tmp
	$(DOCKER_CMD) run \
		$(INTERACTIVE) \
		--tty \
		--rm \
		--privileged \
		-v $(PWD)/examples/configs:/configs \
		-v $(PWD)/examples/keys:/keys \
		-v $(PWD)/examples:/examples \
		-v $(PWD)/tmp:/out \
		bundlecrypt:latest \
		bundlecrypt crypt \
			--config $(CONFIG_PATH) \
			--id $(CONFIG_ID) \
			--remove-other-permissions \
			--uid 252 \
			--gid 252 \
			$(VERBOSE) \
			$(ENCRYPT_INPUT_FILE) \
			$(ENCRYPT_OUTPUT_FILE)

# output file from test-encrypt is the input file for test-decrypt
test-decrypt: image fix-loop-devices
	mkdir -p $(PWD)/tmp
	$(DOCKER_CMD) run \
		$(INTERACTIVE) \
		--tty \
		--rm \
		--privileged \
		-v $(PWD)/examples/configs:/configs \
		-v $(PWD)/examples/keys:/keys \
		-v $(PWD)/examples:/examples \
		-v $(PWD)/tmp:/out \
		bundlecrypt:latest \
		bundlecrypt decrypt \
			--config $(CONFIG_PATH) \
			$(VERBOSE) \
			$(ENCRYPT_OUTPUT_FILE) \
			/out/bundle-raw.tar

ONEMW_CONFIGURATIONS = $(shell jq '.cryptConfigurations | keys[]' -r examples/configs/onemw.json | sort)
ONEMW_CONFIGURATIONS_TARGETS = $(addprefix test-encrypt-onemw-configuration-,$(ONEMW_CONFIGURATIONS))

$(ONEMW_CONFIGURATIONS_TARGETS):
	make test-encrypt CONFIG_PATH=/configs/onemw.json CONFIG_ID=$(subst test-encrypt-onemw-configuration-,,$@)

test-encrypt-onemw-configurations: $(ONEMW_CONFIGURATIONS_TARGETS)

black:
	venv/bin/black setup.py bundlecrypt test/

black-check:
	venv/bin/black --check setup.py bundlecrypt test/

test: test-unit test-interop test-encrypt test-decrypt

pr: test black-check

update-reproducible-reqs:
	python3.8 -m venv venv-update-reproducible-requirements
	venv-update-reproducible-requirements/bin/pip install \
		--upgrade \
		pip-tools pip
	venv-update-reproducible-requirements/bin/pip-compile \
		--generate-hashes \
		--allow-unsafe \
		requirements.in \
		-o requirements.txt
	venv-update-reproducible-requirements/bin/pip-compile \
		--generate-hashes \
		--allow-unsafe \
		dev-requirements.in \
		-o dev-requirements.txt

fix-loop-devices:
	./scripts/fix-loop-devices.sh
