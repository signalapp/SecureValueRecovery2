#!/bin/bash

# Most of this comes from https://learn.microsoft.com/en-us/azure/virtual-machines/linux/create-upload-generic

set -euxo pipefail

apt-get install -y hyperv-daemons

# TODO: generate new SSH host keys.

# Fix network interface name.
sed -i 's/enp0s2/eth0/g' /etc/network/interfaces

# Allow dhclient to do some things it only does on Azure.
cat >> /etc/apparmor.d/local/sbin.dhclient <<EOF
/{,usr/}bin/true pux,
capability sys_module,
EOF

cat >> /etc/initramfs-tools/modules <<EOF
# Azure cloud modules
hv_vmbus
hv_storvsc
hv_netvsc
EOF
#mkfifo /dev/shm/wait && cat /dev/shm/wait
