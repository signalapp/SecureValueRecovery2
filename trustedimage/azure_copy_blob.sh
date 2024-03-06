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
  echo "Must have created file './azure_config' with $AZ_... variables" 1>&2
  exit 1
fi
source ./azure_config

# Get SAS token for uploading blob.
# Note:  We upload a storage blob, not a managed disk.  Managed disks are
#   rejected when we request confidential computing be enabled in the
#   image definition, while blobs are accepted.
FILE="$1"
AZ_BLOB="$2"
AZ_CONNECTION_STRING="$(az storage account show-connection-string \
    --name $AZ_STORAGE_ACCOUNT \
    --resource-group $AZ_RESOURCE_GROUP \
    --output tsv)"
AZ_SAS_EXPIRY="$(date -u -d "30 minutes" '+%Y-%m-%dT%H:%MZ')"
AZ_SAS_TOKEN="$(az storage blob generate-sas --account-name $AZ_STORAGE_ACCOUNT --container-name $AZ_STORAGE_ACCOUNT --name $AZ_BLOB --permissions crw --expiry $AZ_SAS_EXPIRY --connection-string "$AZ_CONNECTION_STRING" --output tsv)"
AZ_BLOB_URL="$(az storage blob url --account-name $AZ_STORAGE_ACCOUNT --container-name $AZ_STORAGE_CONTAINER --name $AZ_BLOB --connection-string "$AZ_CONNECTION_STRING" --output tsv)"

if [ ! -z "$AZ_JUMPHOST" ]; then
  # Rsync up to the target host, then run azcopy from the directory
  # we just uploaded it to.
  rsync --progress --compress --inplace -e ssh -L $(which azcopy) $FILE $AZ_JUMPHOST:./ 1>&2
  ssh $AZ_JUMPHOST "./azcopy copy $(basename $FILE) \"${AZ_BLOB_URL}?${AZ_SAS_TOKEN}\"" 1>&2
else
  # Just run the azcopy command locally.
  azcopy copy $FILE \"${AZ_BLOB_URL}?${AZ_SAS_TOKEN}\" 1>&2
fi
echo $AZ_BLOB_URL
