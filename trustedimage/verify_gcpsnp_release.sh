#!/bin/bash

set -euo pipefail

cd $(dirname $0)/../enclave/releases/gcpsnp
RELEASE=$1
ARCHIVE=$PWD/$RELEASE.tar.gz
EVENTLOG=$PWD/$RELEASE.eventlog

if [ ! -f $ARCHIVE ]; then
  echo "Missing $ARCHIVE"
  exit 1
fi
if [ ! -f $EVENTLOG ]; then
  echo "Missing $EVENTLOG"
  exit 1
fi

echo "=== Preparing Disk ==="
DIR="$(mktemp -d)"
echo "Using temporary directory $DIR"
DELETE_DIR=y
function Clean1 {
  if [ "${DELETE_DIR,,}" != "n" ]; then
    echo "Cleaning up directory $DIR"
    rm -rf $DIR
  else
    echo "Leaving directory $DIR"
  fi
}
trap Clean1 EXIT

IMAGE=$DIR/disk.raw
echo "Extracting disk image into $IMAGE"
mkdir -p $DIR
pushd $DIR >/dev/null
tar xzf $ARCHIVE
popd

echo "Finding unused loop device"
LOOP_DEVICE="$(sudo losetup -f)"
echo "Setting up disk loop device $LOOP_DEVICE"
sudo losetup -Pr $LOOP_DEVICE $IMAGE

UMOUNT=y
ROOT=$DIR/root
BOOT=$ROOT/boot
mkdir -p $ROOT
echo "Mounting / at $ROOT and /boot at $BOOT"
sudo mount -o ro ${LOOP_DEVICE}p2 $ROOT
sudo mount -o ro ${LOOP_DEVICE}p1 $BOOT

function Clean2 {
  if [ "${UMOUNT,,}" != "n" ]; then
    echo "Umounting $BOOT and $ROOT"
    sudo umount -l $BOOT
    sudo umount -l $ROOT
  else
    echo "Leaving root directory mounted for further investigation:"
    echo "  ${LOOP_DEVICE}p2 at $ROOT"
    echo "  ${LOOP_DEVICE}p1 at $BOOT"
    echo "When finished, run:"
    echo "  sudo umount -l $BOOT"
    echo "  sudo umount -l $ROOT"
  fi
  echo "Detaching loop device $LOOP_DEVICE"
  sudo losetup -d $LOOP_DEVICE
  Clean1
}
trap Clean2 EXIT

echo
echo "=== PCRS: ==="
tpm2_eventlog $EVENTLOG | yq '.pcrs.sha256' | sed 's/0x//'

echo
echo "=== Checking PCR9 file digests ==="
PCR9_FILES=$DIR/pcr9
echo "Extracting file digests into $PCR9_FILES"
tpm2_eventlog $EVENTLOG | \
    yq -r '.events[] | select(.PCRIndex == 9) | {"E": .Event.String, "D": .Digests[1].Digest} | .D + "  " + .E' | \
    sed "s/(.*)//; s#  #  $BOOT#" | \
    tee $PCR9_FILES
echo "Checking PCR9 file digests match"
sha256sum -c $PCR9_FILES

echo
echo "=== Checking PCR8 Verity hash is in kernel commandline and matches ==="
echo "Extracting PCR8 verity hash"
VERITYHASH="$(tpm2_eventlog $EVENTLOG | \
    yq -r '.events[] | select(.PCRIndex == 8) | select(.Event.String | test("kernel_cmdline:")) | .Event.String | capture("svr3verity=(?<hash>[^ ]*)") | .hash')"

echo "Verifying dm-verity with root hash $VERITYHASH"
sudo veritysetup verify ${LOOP_DEVICE}p2 ${LOOP_DEVICE}p3 $VERITYHASH
echo "Verity verified"

echo
echo "=== Hashing relevant binaries ==="
function CompareSHA256 {
    if [ ! -f "$1" ]; then
        echo "$1 not found"
        return 1
    fi

    local sha1=$(sha256sum "$1" | awk '{ print $1 }')
    local sha2=$(sha256sum "$2" | awk '{ print $1 }')

    if [ "$sha1" == "$sha2" ]; then
        echo "Checksums match for locally built binary $1 and release disk binary $2"
        return 0
    else
        echo "Checksum verification FAILED"
                echo "Locally built binary $1 has checksum $sha1"
                echo "Release disk binary $2 has checksum $sha2"
        return 1
    fi
}

pushd "../../../trustedimage/debian2"
CompareSHA256 "initramfs_hook.sh"              "$ROOT/etc/initramfs-tools/hooks/initramfs_hook.sh"
CompareSHA256 "initramfs_local-top.sh"         "$ROOT/etc/initramfs-tools/scripts/local-top/initramfs_local-top.sh"
CompareSHA256 "initramfs_local-bottom.sh"      "$ROOT/etc/initramfs-tools/scripts/local-bottom/initramfs_local-bottom.sh"
CompareSHA256 "svr3"                           "$ROOT/usr/bin/svr3"
popd
pushd ../../.. >/dev/null
CompareSHA256 "enclave/build/enclave.gcpsnp"   "$ROOT/usr/bin/enclave.gcpsnp"
CompareSHA256 "enclave/build/enclave.azuresnp" "$ROOT/usr/bin/enclave.azuresnp"
CompareSHA256 "host/cmd/svr3gcp/svr3gcp"       "$ROOT/usr/bin/svr3gcp"
popd >/dev/null

echo
echo "=== Diff ==="
LOCAL_IMAGE="$(realpath ../../../trustedimage/build/debian2.out/disk.raw-1)"
if [ ! -f $LOCAL_IMAGE ]; then
  echo "No local image at $LOCAL_IMAGE, skipping diff"
  echo "Generate image by running 'make build/debian2.out' in the trustedimage/ directory"
else
  echo "Finding unused loop device"
  LOOP2_DEVICE="$(sudo losetup -f)"
  echo "Setting up disk loop device $LOOP2_DEVICE"
  sudo losetup -Pr $LOOP2_DEVICE $LOCAL_IMAGE
  mkdir -p $DIR/local
  echo "Mounting locally-generated drive to $DIR/local"
  sudo mount ${LOOP2_DEVICE}p2 $DIR/local
  sudo mount ${LOOP2_DEVICE}p1 $DIR/local/boot

  function Clean3 {
    if [ "${UMOUNT,,}" != "n" ]; then
      echo "Umounting /local"
      sudo umount -l $DIR/local/boot
      sudo umount -l $DIR/local
    else
      echo "Leaving local directory mounted for further investigation:"
      echo "  ${LOOP2_DEVICE}p2 at $DIR/local"
      echo "  ${LOOP2_DEVICE}p1 at $DIR/local/boot"
      echo "When finished, run:"
      echo "  sudo umount -l $DIR/local"
      echo "  sudo umount -l $DIR/local/boot"
    fi

    echo "Detaching loop device $LOOP2_DEVICE"
    sudo losetup -d $LOOP2_DEVICE
    Clean2
  }
  trap Clean3 EXIT

  echo "Running diff against locally generated drive (local/) and release root drive (root/)"
  pushd $DIR >/dev/null
  sudo diff --brief --recursive --no-dereference local/ root/ && echo "*** No differences found ***" || echo "^^^ Differences ^^^"
  popd
fi

echo
echo "=== Complete ==="
if [ "${DELETE_DIR,,}" == "y" ]; then
  echo -n "Delete temporary directory $DIR (including disk image)? [Y/n]: "
  read DELETE_DIR
fi
if [ "${DELETE_DIR,,}" == "n" ]; then
  echo -n "Umount filesystems mounted under $DIR? [Y/n]: "
  read UMOUNT
fi
