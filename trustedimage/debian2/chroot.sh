#!/bin/bash
# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# This script is called within the (writable) new disk /dev/vdb2.
set -ex

# TODO: eventually disallow SSH.  For now, lock it down.
mkdir /home/svr3/.ssh
cp /dev/shm/debian2/id_rsa.pub /home/svr3/.ssh/authorized_keys
sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication no/;
        s/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# We only care about our root filesystem being created, and that'll all be done
# with kernel command-line arguments and initramfs scripts.
rm /etc/fstab

### Fix up initramfs
# Don't try to resume from hibernation from a swap partition that no longer exists.
rm /etc/initramfs-tools/conf.d/resume
# Pass in our scripts to set up dm-verity stuff.
cp -v /dev/shm/debian2/initramfs_hook.sh /etc/initramfs-tools/hooks/
cp -v /dev/shm/debian2/initramfs_local-top.sh /etc/initramfs-tools/scripts/local-top/
cp -v /dev/shm/debian2/initramfs_local-bottom.sh /etc/initramfs-tools/scripts/local-bottom/
# Regenerate our initramfs.
update-initramfs -u

# Remove the non-standard Debian directory from /boot/EFI, which requires
# a pointer in UEFI vars.  Clouds won't have our UEFI vars, so instead use
# the '--removable' flag to put our boot stuff where anyone can find it.
rm /boot/EFI/debian -rfv
grub-install --efi-directory /boot --boot-directory /boot --modules tpm --removable

# Rewrite our grub config to use dm-verity as a root device.
cat >> /etc/default/grub << EOF
GRUB_DEVICE="/dev/mapper/verity"
GRUB_DISABLE_LINUX_UUID="true"
GRUB_DISABLE_LINUX_PARTUUID="true"
GRUB_CMDLINE_LINUX_DEFAULT="panic=-1"
GRUB_CMDLINE_LINUX="svr3verity=VERITYHASH"
EOF
grub-mkconfig -o /boot/grub/grub.cfg
