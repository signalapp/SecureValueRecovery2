#/bin/bash

set -exo pipefail

if ! source ./gcp_config; then
  echo 1>&2 "Must create ./gcp_config file (see ./gcp_config.example)"
  exit 1
fi

FROM=build/debian2.out/disk.raw-1
VERSION="$1"
VERSION_DASH="$(echo $VERSION | sed 's/\./-/g')"
# Note:  to give access, create a service account with "Storage Object User"
# and "Storage Insights Collector Service" (for storage.buckets.get) roles.
# Then, go to the "Permissions" tab of that user and add the
# "Service Account Token Creator" role to the user that's running this script.
BLOB=gs://$GCP_BUCKET/image-$VERSION.tar.gz
function rm_blob() {
  # Whether we succeed in creating an image or fail in our endeavours, we
  # don't need the blob anymore, so try to delete it.  But don't worry
  # if this attempt fails; it's just a nice-to-have.
  gcloud storage rm $BLOB
}
trap rm_blob EXIT
if [ -z "$GCP_JUMPHOST" ]; then
  tar --transform="s/$(basename $FROM)/disk.raw/" --format=oldgnu -cvf - -C $(dirname $FROM) $(basename $FROM) | pv -f | pigz >gcp.tar.gz
  gcloud storage cp $FROM $BLOB
else
  rsync -e ssh --progress --compress --inplace $FROM $GCP_JUMPHOST:./disk.raw
	ssh $GCP_JUMPHOST "tar --format=oldgnu -cvf - disk.raw | pv -f | pigz --fast >gcp.tar.gz"
  ACCESS_TOKEN="$(gcloud auth print-access-token --lifetime=900 --impersonate-service-account $GCP_SERVICE_ACCOUNT)"
  ssh $GCP_JUMPHOST "CLOUDSDK_AUTH_ACCESS_TOKEN=$ACCESS_TOKEN gcloud storage cp gcp.tar.gz $BLOB"
fi
gcloud compute images create svr3-$VERSION_DASH --source-uri $BLOB --guest-os-features=SEV_SNP_CAPABLE,UEFI_COMPATIBLE
echo $VERSION > build/gcp_version
