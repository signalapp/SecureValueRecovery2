#!/bin/bash
set -eux -o pipefail

apt-get update
apt-get install -y \
      gpg \
      gnupg2 \
      wget \
      software-properties-common \
      debian-archive-keyring \
## apt-get install
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/22.04/prod jammy main" | tee /etc/apt/sources.list.d/msprod.list
echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" | tee /etc/apt/sources.list.d/sgx.list

wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | apt-key add -

apt-get update
apt-get -y install \
    libsgx-ae-epid=2.25.100.3-jammy1 \
    libsgx-ae-id-enclave=1.22.100.3-jammy1 \
    libsgx-ae-le=2.25.100.3-jammy1 \
    libsgx-ae-pce=2.25.100.3-jammy1 \
    libsgx-ae-qe3=1.22.100.3-jammy1 \
    libsgx-ae-qve=1.22.100.3-jammy1 \
    libsgx-aesm-ecdsa-plugin=2.25.100.3-jammy1 \
    libsgx-aesm-epid-plugin=2.25.100.3-jammy1 \
    libsgx-aesm-launch-plugin=2.25.100.3-jammy1 \
    libsgx-aesm-pce-plugin=2.25.100.3-jammy1 \
    libsgx-aesm-quote-ex-plugin=2.25.100.3-jammy1 \
    libsgx-dcap-default-qpl=1.22.100.3-jammy1 \
    libsgx-dcap-default-qpl-dev=1.22.100.3-jammy1 \
    libsgx-dcap-ql=1.22.100.3-jammy1 \
    libsgx-dcap-ql-dev=1.22.100.3-jammy1 \
    libsgx-dcap-quote-verify=1.22.100.3-jammy1 \
    libsgx-enclave-common=2.25.100.3-jammy1 \
    libsgx-headers=2.25.100.3-jammy1 \
    libsgx-launch=2.25.100.3-jammy1 \
    libsgx-pce-logic=1.22.100.3-jammy1 \
    libsgx-qe3-logic=1.22.100.3-jammy1 \
    libsgx-quote-ex=2.25.100.3-jammy1 \
    libsgx-urts=2.25.100.3-jammy1 \
    sgx-aesm-service=2.25.100.3-jammy1 \
## apt-get install

apt-get clean
