# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only

# Builds our first image, which is just a default Debian image
# with some pre-installed packages etc. to make things easier for
# us.  Most of the work here is done in the `debian1/preseed.txt`
# file.  Packer serves that up via HTTP and passes it to the Debian
# installer for an "unattended install".

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
  }
}

source "qemu" "debian1" {
  format         = "raw"
  headless       = "false"
  communicator   = "ssh"
  disk_interface = "virtio"
  disk_size      = "5G"
  memory         = 4096 # Using the default amount of memory will crash, we need more.


  # Use UEFI so our install can be more easily modified for secure-boot.
  efi_boot          = "true"
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.ms.fd"
  efi_firmware_vars = "/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
  machine_type      = "q35"

  accelerator      = "kvm"
  http_directory   = "debian1"
  iso_checksum     = "64d727dd5785ae5fcfd3ae8ffbede5f40cca96f1580aaa2820e8b99dae989d94"
  iso_url          = "https://cdimage.debian.org/mirror/cdimage/archive/12.4.0/amd64/iso-cd/debian-12.4.0-amd64-netinst.iso"
  net_device       = "virtio-net"
  output_directory = "build/debian1.out"
  shutdown_command = "sudo shutdown -h now"
  ssh_password     = "svr3"
  ssh_timeout      = "15m"
  ssh_username     = "svr3"
  vm_name          = "disk.raw"


  # Our 'boot_command' does all the actual work here.
  boot_key_interval = "10ms"
  boot_wait         = "2s"
  boot_command      = [
    # These steps interact with the MSFT UEFI firmware and tell it
    # "don't boot into the UEFI shell, we actually want to boot to our disk".
    # It appears that as of 2024/02/16, the firmware may have updated
    # to no longer require this.
    #   "<enter>",
    #   "bcfg boot rm 0<enter>",
    #   "bcfg boot rm 0<enter>",
    #   "reset<enter>",
    #   "<wait5>",
    #
    # Now we're in the Debian installer UI.  We select "advanced", then
    # tell it to use a preseed, then once it's ready, we give it the URL
    # we're serving up over HTTP for the 'debian1/preseed.txt' file.
    "<down><down><enter><wait>", 
    "<down><down><down><down><down><enter><wait45>",
    "http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.txt<enter>"
  ]
}

# a build block invokes sources and runs provisioning steps on them. The
# documentation for build blocks can be found here:
# https://www.packer.io/docs/templates/hcl_templates/blocks/build
build {
  sources = ["source.qemu.debian1"]
}
