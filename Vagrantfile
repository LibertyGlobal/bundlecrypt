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

Vagrant.configure("2") do |config|
  config.vm.box = "fedora/34-cloud-base"

  config.vm.hostname = "bundlecrypt"
  config.vm.define "bundlecrypt"

  if Vagrant.has_plugin?("vagrant-vbguest")
    config.vbguest.auto_update = false
  end

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "2048"
    vb.cpus = "4"
  end

  # docker setup
  config.vm.provision "shell", reset: true, inline: <<-SHELL
    dnf -y install dnf-plugins-core
    dnf config-manager \
      --add-repo \
      https://download.docker.com/linux/fedora/docker-ce.repo
    dnf -y install docker-ce docker-ce-cli containerd.io
    systemctl enable docker
    systemctl start docker
    usermod -aG docker vagrant
  SHELL

  # bundlecrypt build/installation/demo requirements
  config.vm.provision "shell", inline: <<-SHELL
    dnf -y install git make jq awscli docker-compose
  SHELL

  # AWS credentials are needed to fetch dmcrypt-rdk from S3
  config.vm.provision "file", source: "~/.aws", destination: ".aws"

  # bundlecrypt test
  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    cd /vagrant
    git clean -dfx
    make fix-loop-devices test-encrypt test-decrypt
  SHELL
end
