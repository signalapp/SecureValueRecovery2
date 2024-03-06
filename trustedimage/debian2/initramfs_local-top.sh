#!/bin/sh
# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
PREREQ=""
prereqs()
{
  echo "$PREREQ"
}

case $1 in
prereqs)
  prereqs
  exit 0
  ;;
esac

. /scripts/functions
# Begin real processing below this line

# Set up /dev/mapper/verity to be a dm-verity integrity-checked
# device with the root hash $svr3verity given in the kernel command
# line.  Our kernel command line then references /dev/mapper/verity
# as our root partition, so we'll mount it as /root in initramfs.
# We do some other tricks to it in local-bottom before `pivot_root`
# is called to pivot into it.
log_begin_msg "Creating verity device mapping with veritysetup"

for device in vda vdb sda sdb nvme0n1p; do
  if ! [ -e /dev/${device}3 ]; then
    continue
  fi
  if ! /sbin/veritysetup open /dev/${device}2 verity /dev/${device}3 $svr3verity --panic-on-corruption; then
    log_failure_msg "veritysetup failed for ${device}"
    exit 1  # Halt boot process
  else
    log_end_msg
    exit 0
  fi
done
log_failure_msg "device not found in devices `ls /dev/`"
exit 1
