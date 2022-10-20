package legit_verify_attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/in-toto/in-toto-golang/in_toto"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

const (
	skipVerification      = true
	doNotSkipVerification = false
)

func attestationToEnvelope(attestation []byte) (*dsselib.Envelope, error) {
	var env dsselib.Envelope

	if err := json.Unmarshal(attestation, &env); err != nil {
		return nil, err
	}

	return &env, nil
}

func verifySig(ctx context.Context, envelope *dsselib.Envelope, keyRef string) error {
	sv, err := signature.PublicKeyFromKeyRef(ctx, keyRef)
	if err != nil {
		return fmt.Errorf("Failed to load pub key: %v\n", err)
	}

	dssev, err := dsselib.NewEnvelopeVerifier(&dsse.VerifierAdapter{SignatureVerifier: sv})
	if err != nil {
		return err
	}
	_, err = dssev.Verify(envelope)
	if err != nil {
		return fmt.Errorf("failed verify: %v\n", err)
	}

	return nil
}

func ExtractPayload(ctx context.Context, keyRef string, attestation []byte, skipSigVerification bool) ([]byte, error) {
	envelope, err := attestationToEnvelope(attestation)
	if err != nil {
		return nil, err
	}

	if !skipSigVerification {
		err = verifySig(ctx, envelope, keyRef)
		if err != nil {
			return nil, err
		}
	}

	decoded, err := base64.StdEncoding.DecodeString(string(envelope.Payload))
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	return decoded, nil
}

func VerifiedPayload(ctx context.Context, keyRef string, attestation []byte) ([]byte, error) {
	return ExtractPayload(ctx, keyRef, attestation, doNotSkipVerification)
}
func UnverifiedPayload(ctx context.Context, keyRef string, attestation []byte) ([]byte, error) {
	return ExtractPayload(ctx, keyRef, attestation, skipVerification)
}

func ExtractTypedPayload[T any](ctx context.Context, keyRef string, attestation []byte, skipSigVerification bool) (*T, error) {
	payloadBytes, err := ExtractPayload(ctx, keyRef, attestation, skipSigVerification)
	if err != nil {
		return nil, err
	}

	var payload T
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal predicate: %v", err)
	}

	return &payload, nil
}

func VerifiedTypedPayload[T any](ctx context.Context, keyRef string, attestation []byte) (*T, error) {
	return ExtractTypedPayload[T](ctx, keyRef, attestation, doNotSkipVerification)
}
func UnverifiedTypedPayload[T any](ctx context.Context, keyRef string, attestation []byte) (*T, error) {
	return ExtractTypedPayload[T](ctx, keyRef, attestation, skipVerification)
}

func VerifyDigests(subjects []in_toto.Subject, digests ...string) error {
	checks := len(digests)
	actual := len(subjects)

	if actual < checks {
		return fmt.Errorf("failed to verify digests: not enough digests (%v < %v)", actual, checks)
	} else if checks < actual {
		log.Printf("note: you only checked %v out of %v digests", checks, actual)
	}

	// create a map to accept unordered list of digests (and avoid n^2 iteration)
	actualMapped := make(map[string]bool, actual)
	for _, d := range subjects {
		sha := d.Digest["sha256"]
		actualMapped[sha] = true
	}

	for _, d := range digests {
		if _, ok := actualMapped[d]; !ok {
			return fmt.Errorf("expected digest %v does not exist in subject: %v", d, actualMapped)
		}
	}

	return nil
}
