#!/bin/bash
# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
#
# This script is called within the (writable) new disk /dev/vdb2.
set -euxo pipefail

# TODO: eventually disallow SSH.  For now, lock it down.
mkdir /home/svr3/.ssh
cp /dev/shm/debian2/id_rsa.pub /home/svr3/.ssh/authorized_keys
sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication no/;
        s/.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# We only care about our root filesystem being created, and that'll all be done
# with kernel command-line arguments and initramfs scripts.
# However, some things (dhclient) still expect the file to exist, so make
# it be empty.
echo "# emptied by SVR3 debian2/chroot.sh" > /etc/fstab

### Fix up initramfs
# Don't try to resume from hibernation from a swap partition that no longer exists.
rm /etc/initramfs-tools/conf.d/resume
# Pass in our scripts to set up dm-verity stuff.
cp -v /dev/shm/debian2/initramfs_hook.sh /etc/initramfs-tools/hooks/
cp -v /dev/shm/debian2/initramfs_local-top.sh /etc/initramfs-tools/scripts/local-top/
cp -v /dev/shm/debian2/initramfs_local-bottom.sh /etc/initramfs-tools/scripts/local-bottom/

/dev/shm/debian2/azure.sh
/dev/shm/debian2/gcp.sh

# Regenerate our initramfs.
update-initramfs -u

# We're forced to make our VM image "generalized" currently, because Terraform
# doesn't support specialized images (https://github.com/hashicorp/terraform-provider-azurerm/issues/22968).
# Luckily, Azure provides us a method for being generalized without using
# their complex walinuxagent code, described at https://learn.microsoft.com/en-us/azure/virtual-machines/linux/no-agent.
cp /dev/shm/debian2/azure-provisioning.sh /usr/sbin/azure-provisioning.sh
cp /dev/shm/debian2/azure-provisioning.service /etc/systemd/system/
systemctl enable azure-provisioning.service

# Remove the non-standard Debian directory from /boot/EFI, which requires
# a pointer in UEFI vars.  Clouds won't have our UEFI vars, so instead use
# the '--removable' flag to put our boot stuff where anyone can find it.
rm /boot/EFI/debian -rfv
grub-install --efi-directory /boot --boot-directory /boot --modules tpm --removable

# Rewrite our grub config to use dm-verity as a root device.
AZURE_CMDLINE="console=ttyS0 earlyprintk=ttyS0 net.ifnames=0"
cat >> /etc/default/grub << EOF
GRUB_DEVICE="/dev/mapper/verity"
GRUB_DISABLE_LINUX_UUID="true"
GRUB_DISABLE_LINUX_PARTUUID="true"
GRUB_CMDLINE_LINUX_DEFAULT="panic=-1"
GRUB_CMDLINE_LINUX="svr3verity=VERITYHASH loadpin.enabled $AZURE_CMDLINE"
EOF
grub-mkconfig -o /boot/grub/grub.cfg

# Remove SSH host keys and request that they be regenerated
rm -fv /etc/ssh/ssh_host_*key*
cp -v /dev/shm/debian2/generate_ssh_keys.service /etc/systemd/system/
systemctl enable generate_ssh_keys.service

# Set SVR3 to start up
cp -v /dev/shm/debian2/svr3.service /etc/systemd/system/
systemctl enable svr3.service

# Copy binaries.
chmod a+x /dev/shm/debian2/svr3{,test}
cp -v /dev/shm/debian2/svr3{,test} /usr/bin
