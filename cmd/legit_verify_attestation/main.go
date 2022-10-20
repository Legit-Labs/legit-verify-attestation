package main

import (
	"context"
	"flag"
	"io/ioutil"
	"log"
	"os"

	"github.com/legit-labs/legit-attestation/pkg/legit_verify_attestation"
)

const (
	skipSigVerification = "SKIP_ATTESTATION_SIGNATURE_VERIFICATION"
	outputPayload       = "OUTPUT_PAYLOAD"
)

func shouldSkipVerification() bool {
	return os.Getenv(skipSigVerification) == "1"
}

func shouldOutputPayload() bool {
	return os.Getenv(outputPayload) == "1"
}

var (
	keyPath          string
	attestationPath  string
	attestationStdin bool
)

func main() {
	flag.StringVar(&keyPath, "key", "", "The path of the public key")
	flag.StringVar(&attestationPath, "attestation-path", "", "The path of the attestation document")
	flag.BoolVar(&attestationStdin, "attestation-stdin", false, "Read the attestation from stdin (overwrites -attestation-path if provided)")

	flag.Parse()

	if keyPath == "" {
		log.Panicf("please provide a public key path")
	} else if !attestationStdin && attestationPath == "" {
		log.Panicf("please provide an attestation path (or set -attestation-stdin to read it from stdin)")
	}

	var attestation []byte
	var err error
	if attestationStdin {
		if attestation, err = ioutil.ReadAll(os.Stdin); err != nil {
			log.Panicf("failed to read payload from stdin: %v", err)
		}
	} else {
		attestation, err = os.ReadFile(attestationPath)
		if err != nil {
			log.Panicf("failed to open payload at %v: %v", attestationPath, err)
		}
	}

	shouldSkip := shouldSkipVerification()
	payload, err := legit_verify_attestation.ExtractPayload(context.Background(), keyPath, attestation, shouldSkip)
	if err != nil {
		log.Panicf("attestation verification failed: %v", err)
	}

	if !shouldSkip {
		log.Printf("attestation was verified successfully against the public key.")
	}

	if shouldOutputPayload() {
		_, err := os.Stdout.Write(payload)
		if err != nil {
			log.Printf("failed to print payload: %v", err)
		}
	}
}
