Generate and build AMD-SEV-SNP attestable VM disk images for GCP or Azure

## Dependencies

To run build and upload disk images, you'll need
- [packer](https://developer.hashicorp.com/packer/tutorials/docker-get-started/get-started-install-cli)
- [gcloud](https://cloud.google.com/sdk/docs/install-sdk) (to make GCP disk images)
- [az](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (to make Azure disk images)

Then you'll also need to install the `qemu` plugin for packer, run
```
packer init template.pkr.hcl
```

Finally, you'll have to configure credentials and projects for the cloud provider you want to build
disk images on. See azure_config.example or gcp_config.example.

## Building

`make build/gcp_version` will create a GCP disk image 
`make build/azure_version` will create an Azure disk image 
`make` will default to the GCP version
