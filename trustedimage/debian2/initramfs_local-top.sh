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
if ! /sbin/veritysetup open /dev/vda2 verity /dev/vda3 $svr3verity --panic-on-corruption; then
  log_failure_msg "veritysetup failed"
  exit 1  # Halt boot process
fi
log_end_msg
