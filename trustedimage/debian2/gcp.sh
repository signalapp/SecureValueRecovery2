#!/bin/bash

cat >> /etc/initramfs-tools/modules <<EOF
# GCP cloud modules
gve
nvme
EOF
