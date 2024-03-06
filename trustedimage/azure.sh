#!/bin/bash
# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only
# 
# Most of this pulled from
# * https://learn.microsoft.com/en-us/azure/virtual-machines/linux/create-upload-generic
# * https://learn.microsoft.com/en-us/azure/virtual-machines/linux/disks-upload-vhd-to-managed-disk-cli
# * https://learn.microsoft.com/en-us/azure/virtual-machines/linux/debian-create-upload-vhd
set -euxo pipefail

# Pull in local configuration information for where to put this in Azure.
# See ./azure_config.example for an example of this.
if [ ! -f ./azure_config ]; then
  echo "Must have created file './azure_config' with $AZ_... variables"
  exit 1
fi
source ./azure_config
FROM="build/debian2.out/disk.raw-1"  # Local disk image to build from
TO="build/azure.vhd"            # Local VHD file to create
MB=$((1024*1024))
VERSION="$1"

# Make sure the image gallery exists
if ! az sig show \
    -g $AZ_RESOURCE_GROUP \
    --gallery-name $AZ_SHARED_IMAGE_GALLERY \
    >/dev/null; then
  echo "Image gallery '$AZ_SHARED_IMAGE_GALLERY' in resource group '$AZ_RESOURCE_GROUP' not found"
  exit 1
fi
if ! az sig image-definition show \
    -g $AZ_RESOURCE_GROUP \
    --gallery-name $AZ_SHARED_IMAGE_GALLERY \
    --gallery-image-definition $AZ_IMAGE_DEFINITION \
    >/dev/null; then
  echo "Image definition '$AZ_IMAGE_DEFINITION' in gallery '$AZ_SHARED_IMAGE_GALLERY' in resource group '$AZ_RESOURCE_GROUP' not found"
  exit 1
fi

./azure_copy_blob.sh "../host/main" "host-$VERSION"

# Azure requires disk images to be on 1MB boundaries.  Make sure this is the case
SIZE=$(qemu-img info -f raw --output json $FROM | jq '."virtual-size"')
ROUNDED_SIZE=$(((($SIZE+$MB-1)/$MB)*$MB))
if [ "$SIZE" -ne "$ROUNDED_SIZE" ]; then
  echo "Not MB-aligned"
  exit 1
fi

# Convert to a VHD and get the VHD size (will be 512B larger than disk image size)
qemu-img convert -f raw -o subformat=fixed,force_size -O vpc $FROM $TO
ACTUAL_SIZE=$(wc -c $TO | cut -f1 -d\ )

# Get SAS token for uploading blob.
# Note:  We upload a storage blob, not a managed disk.  Managed disks are
#   rejected when we request confidential computing be enabled in the
#   image definition, while blobs are accepted.
AZ_BLOB=image-$VERSION
AZ_BLOB_URL="$(./azure_copy_blob.sh "$TO" "$AZ_BLOB")"

function rm_blob() {
  # Whether we succeed in creating an image or fail in our endeavours, we
  # don't need the blob anymore, so try to delete it.  But don't worry
  # if this attempt fails; it's just a nice-to-have.
  az storage blob delete --account-name $AZ_STORAGE_ACCOUNT --container-name $AZ_STORAGE_CONTAINER --name $AZ_BLOB
}
trap rm_blob EXIT

# Actually create the Azure image.
AZ_STORAGE_ACCOUNT_ID="$(az storage account show --name $AZ_STORAGE_ACCOUNT --resource-group $AZ_RESOURCE_GROUP | jq -r .id)"
# Note that the $AZ_TARGET_REGIONS variable is not quoted - this is on purpose.
# For some reason, azure thought it'd be a good idea for that flag to take multiple
# separate arguments, so '--target-regions region1 region2 region3' is correct
# and '--target-regions "region1 region2 region3"' is not, as it's treated as a
# single region with spaces in the name.
az sig image-version create \
    -g $AZ_RESOURCE_GROUP \
    --gallery-name $AZ_SHARED_IMAGE_GALLERY \
    --gallery-image-definition $AZ_IMAGE_DEFINITION \
    --gallery-image-version $VERSION \
    --location $AZ_LOCATION \
    --replica-count 1 \
    --os-vhd-storage-account "$AZ_STORAGE_ACCOUNT_ID" \
    --os-vhd-uri "$AZ_BLOB_URL" \
    --target-regions $AZ_TARGET_REGIONS

echo $VERSION > build/azure_version
