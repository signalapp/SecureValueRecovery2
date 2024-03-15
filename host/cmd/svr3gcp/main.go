// Copyright 2023 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"reflect"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"

	pb "github.com/signalapp/svr2/proto"
)

var (
	evidenceOutput     = flag.String("evidence_output", "", "File to write evidence protobuf to")
	endorsementsOutput = flag.String("endorsements_output", "", "File to write endorsements protobuf to")
	nonceHex           = flag.String("nonce_hex", "0000000000000000000000000000000000000000000000000000000000000000", "Nonce value as hex, must be 32b")
	debug              = flag.Bool("debug", true, "If true, log")
)

func logf(fmt string, args ...interface{}) {
	if *debug {
		log.Printf(fmt, args...)
	}
}

func Run() error {
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil {
		return fmt.Errorf("nonce hex: %w", err)
	} else if len(nonce) != 32 {
		return fmt.Errorf("nonce must be 32B as hex")
	}
	evidence := pb.ASNPEvidence{}
	endorsements := pb.ASNPEndorsements{}

	logf("Opening TPM")
	rw, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		return fmt.Errorf("tpm2.OpenTPM(/dev/tpmrm0): %w", err)
	}
	defer rw.Close()

	logf("Generating GceAttestationKeyRSA key")
	gceAK, err := client.GceAttestationKeyRSA(rw)
	if err != nil {
		return fmt.Errorf("client.GceAttestationKeyRSA: %w", err)
	}
	defer gceAK.Close()

	logf("Quoting")
	quote, err := gceAK.Quote(tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},
	}, nonce)
	if err != nil {
		return fmt.Errorf("gceAK.Quote: %w", err)
	}
	logf("Quote:\n\tmsg: %x\n\tsig: %x", quote.Quote, quote.RawSig)
	evidence.Msg = quote.Quote
	evidence.Sig = quote.RawSig
	for i := uint32(0); i < 24; i++ {
		logf("\tPCR[%02d]: %x", i, quote.Pcrs.Pcrs[i])
		evidence.Pcrs = append(evidence.Pcrs, quote.Pcrs.Pcrs[i]...)
	}

	logf("Getting cert")
	cert := gceAK.Cert()
	if cert == nil {
		return fmt.Errorf("no AK cert on this GCE machine")
	}
	certPub := cert.PublicKey
	if certPub == nil {
		return fmt.Errorf("no public key on AK Cert")
	}
	logf("Comparing cert")
	if !reflect.DeepEqual(certPub, gceAK.PublicKey()) {
		return fmt.Errorf("cert and generated keys do not match")
	}
	logf("Cert: %x", cert.Raw)
	evidence.AkcertDer = cert.Raw

	if *evidenceOutput != "" {
		if buf, err := proto.Marshal(&evidence); err != nil {
			return fmt.Errorf("marshal(evidence): %w", err)
		} else if f, err := os.Create(*evidenceOutput); err != nil {
			return fmt.Errorf("open(%q): %w", *evidenceOutput, err)
		} else if _, err := f.Write(buf); err != nil {
			return fmt.Errorf("write(%q): %w", *evidenceOutput, err)
		} else if err := f.Close(); err != nil {
			return fmt.Errorf("close(%q): %w", *evidenceOutput, err)
		}
	}

	if *endorsementsOutput != "" {
		logf("Cert issuer: %q", cert.IssuingCertificateURL)
		if len(cert.IssuingCertificateURL) < 1 {
			return fmt.Errorf("no cert.IssuingCertificateURL")
		}
		resp, err := http.Get(cert.IssuingCertificateURL[0])
		if err != nil {
			return fmt.Errorf("cert retrieval of %q failed: %w", cert.IssuingCertificateURL[0], err)
		}
		certIssuerData, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading cert issuer body: %w", err)
		}
		endorsements.IntermediateDer = certIssuerData
		if buf, err := proto.Marshal(&endorsements); err != nil {
			return fmt.Errorf("marshal(endorsements): %w", err)
		} else if f, err := os.Create(*endorsementsOutput); err != nil {
			return fmt.Errorf("open(%q): %w", *endorsementsOutput, err)
		} else if _, err := f.Write(buf); err != nil {
			return fmt.Errorf("write(%q): %w", *endorsementsOutput, err)
		} else if err := f.Close(); err != nil {
			return fmt.Errorf("close(%q): %w", *endorsementsOutput, err)
		}
	}
	return nil
}

func main() {
	flag.Parse()
	if err := Run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Success")
}
