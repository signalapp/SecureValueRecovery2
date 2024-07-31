# Copyright 2024 Signal Messenger, LLC
# SPDX-License-Identifier: AGPL-3.0-only

# Do the second phase of image creation, where we actually create the new,
# secure disk image.  The additional disk will be set up as our secure one.
# This could be done in 'debian1', but that takes a long time and by
# splitting them up, we can iterate much faster on these scripts.

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
  }
}

source "qemu" "debian2" {
  format               = "raw"
  headless             = "false"
  communicator         = "ssh"
  disk_size            = "5G"
  disk_additional_size = ["3G"]
  memory               = 4096

  # Use UEFI again, but this time use the vars we got from 'debian1',
  # since they tell us how to boot to the OS we just set up.
  efi_boot          = "true"
  efi_firmware_code = "/usr/share/OVMF/OVMF_CODE_4M.ms.fd"
  efi_firmware_vars = "build/debian1.out/efivars.fd"
  machine_type      = "q35"

  accelerator      = "kvm"
  disk_interface   = "virtio"
  net_device       = "virtio-net"
  output_directory = "build/debian2.out"
  shutdown_command = "sudo shutdown -h now"
  ssh_password     = "svr3" # Super secret, don't tell anyone.
  ssh_timeout      = "5m"
  ssh_username     = "svr3"
  vm_name          = "disk.raw"

  # We start from the disk image that 'debian1' created.  Because
  # we just created it, we ignore checksumming.
  iso_checksum = "none"
  iso_url      = "build/debian1.out/disk.raw"
  disk_image   = true
}

build {
  sources = ["source.qemu.debian2"]

  # Write up a bunch of scripts for us to use into /dev/shm/debian2/...
  # We use /dev/shm since it's accessible even when we `chroot` halfway
  # through our install process.
  provisioner "file" {
    destination = "/dev/shm"
    source      = "debian2"
  }

  # Call the first of our scripts.  It does everything else.
  provisioner "shell" {
    inline = ["sudo /dev/shm/debian2/run.sh"]
  }

}
