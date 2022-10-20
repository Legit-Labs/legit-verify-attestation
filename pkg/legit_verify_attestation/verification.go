package legit_verify_attestation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

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

func ExtractTypedPayload[T any](ctx context.Context, keyRef string, attestation []byte, digest string, skipSigVerification bool) (*T, error) {
	payloadBytes, err := ExtractPayload(ctx, keyRef, attestation, skipSigVerification)
	if err != nil {
		return nil, err
	}

	var payload T
	err = json.Unmarshal(payloadBytes, &payload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal predicate: %v", err)
	}

	header, ok := any(payload).(in_toto.StatementHeader)
	if !ok {
		return nil, fmt.Errorf("The payload does not contain a statement header: %T", payload)
	}

	statementDigest := header.Subject[0].Digest["sha256"]
	if statementDigest != digest {
		return nil, fmt.Errorf("expected digest %v does not match actual: %v", digest, statementDigest)
	}

	return &payload, nil
}

func VerifiedTypedPayload[T any](ctx context.Context, keyRef string, attestation []byte, digest string) (*T, error) {
	return ExtractTypedPayload[T](ctx, keyRef, attestation, digest, doNotSkipVerification)
}
func UnverifiedTypedPayload[T any](ctx context.Context, keyRef string, attestation []byte, digest string) (*T, error) {
	return ExtractTypedPayload[T](ctx, keyRef, attestation, digest, skipVerification)
}
