// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

// During the private preview of GCP Confidential VMs with AMD SEV-SNP
// integration, they're not filling in the VCEK/ASK certificates via
// SNP_SET_EXT_CONFIG.  This script pulls them via the `go-sev-guest`
// library and dumps them to a file that's accessible to the enclave
// process.  These certs are long-lived, so should only need to be pulled
// once.  This avoids us having to do HTTPS GET calls directly from
// the enclave C++ code.
//
// Note:  these are pulled from AMD, as described in https://www.amd.com/system/files/TechDocs/57230.pdf
package main

import (
	"flag"
	"log"
	"os"

	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/proto"

	pb "github.com/signalapp/svr2/proto"
)

var (
	outputFilename = flag.String("out", "endorsements.pb", "File to write endorsements to")
)

func main() {
	flag.Parse()
	dev, err := client.OpenDevice()
	if err != nil {
		log.Fatalf("OpenDevice: %v", err)
	}
	report, err := client.GetReport(dev, [64]byte{})
	if err != nil {
		log.Fatalf("GetReport: %v", err)
	}
	attestation, err := verify.GetAttestationFromReport(report, &verify.Options{})
	if err != nil {
		log.Fatalf("GetAttestationFromReport: %v", err)
	}
	out := &pb.SevSnpEndorsements{}
	out.VcekDer = attestation.CertificateChain.VcekCert
	out.AskDer = attestation.CertificateChain.AskCert
	out.ArkDer = attestation.CertificateChain.ArkCert
	data, err := proto.Marshal(out)
	if err != nil {
		log.Fatalf("proto.Marshal: %v", err)
	}
	if f, err := os.Create(*outputFilename); err != nil {
		log.Fatalf("os.Create: %v", err)
	} else if _, err := f.Write(data); err != nil {
		log.Fatalf("f.Write: %v", err)
	} else if err := f.Close(); err != nil {
		log.Fatalf("f.Close: %v", err)
	}
	log.Println("Success")
}
