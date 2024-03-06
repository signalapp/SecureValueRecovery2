#!/bin/sh
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

# We want to pretend that our disk is writable so that small amounts of
# writes necessary for normal operation can go through.  To do this,
# we use the /dev/ram0 ramdisk created by our 'hook' script's module
# inclusion of `brd` as a writable overlay on top of our (read-only,
# currently-mounted-at-root) dm-verity partition.

# Set up ramdisk for overlay.
mkdir /ram_disk
mount -t tmpfs tmpfs -o size=100M /ram_disk
mkdir /ram_disk/work
mkdir /ram_disk/root

# When we're done, /root needs to be our actual root, so move the
# dm-verity device from there to a new place.
mkdir /verity
mount --move /root /verity

# Now, create an overlay.  Any files that try to write will be copied
# from lower->upper (via work), then be writable there.
mount -t overlay overlay -o upperdir=/ram_disk/root,workdir=/ram_disk/work,lowerdir=/verity /root || panic "Overlay failed"
