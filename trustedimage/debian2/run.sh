#!/bin/bash
# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# Our goal with this script is to set up the currently unformatted
# /dev/vdb (our `disk_additional_size` disk) to be a dm-verity-protected
# disk that allows our trust chain up to Grub to continue into userspace.

set -ex

# Make the partitions we need in the new disk for UEFI secure-boot booting.
parted --script /dev/vdb mklabel gpt
parted --script --align=optimal /dev/vdb mkpart ESP fat32 1MB 512MB
parted --script --align=optimal /dev/vdb mkpart ROOT 512MB 2000MB
parted --script --align=optimal /dev/vdb mkpart HASH 2000MB 100%
parted --script /dev/vdb set 1 boot on

# Make the necessary filesystems.
mkfs.fat -F 32 /dev/vdb1
mkfs.ext2 /dev/vdb2

# Mount the new filesystems onto directories we can write to.
mkdir -p /mnt/newroot
mount -t ext2 /dev/vdb2 /mnt/newroot
mount --mkdir /dev/vdb1 /mnt/newroot/boot

# Copy over all the files from this disk to the new one; this disk is bootable
# so soon that one will be too :D
rsync -ax / /mnt/newroot/
rsync -ax /boot/efi/ /mnt/newroot/boot/

# Mount in necessary subsystems so when we chroot we can do whatever we want.
mount -t proc /proc /mnt/newroot/proc
mount --rbind /sys /mnt/newroot/sys
mount --rbind /dev /mnt/newroot/dev

# Do some stuff from within the new disk
chroot /mnt/newroot /dev/shm/debian2/chroot.sh

# Now mark the new disk's vdb2 partition as read-only and set up dm-verity
# using vdb3 as a hash partition.
mount -o remount,ro /dev/vdb2 /mnt/newroot
veritysetup format /dev/vdb2 /dev/vdb3 2>&1 | tee /tmp/verity
HASH=`awk '/^Root/ {print $3}' /tmp/verity`

# /mnt/newroot is read-only, but /mnt/newroot/boot is not, and its grub config
# currently has a placeholder `VERITYHASH` for our root hash.  Fill it in.
sed -i "s#VERITYHASH#$HASH#" /mnt/newroot/boot/grub/grub.cfg
