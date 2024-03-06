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

. /usr/share/initramfs-tools/hook-functions
# Begin real processing below this line

# Set up the important modules we want
force_load dm_verity
force_load overlay

# We'll use this in local-top to set up our dm-verity device.
copy_exec /usr/sbin/veritysetup /sbin/veritysetup
