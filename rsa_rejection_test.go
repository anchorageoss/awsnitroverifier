//go:build !selectTest || isolatedTest

package nitroverifier

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// TestUnsupportedKeyTypeRejection verifies that non-ECDSA key types are rejected.
// AWS Nitro Enclaves attestation documents exclusively use ECDSA (ES384) as specified
// in the AWS documentation and COSE RFC 8152.
func TestUnsupportedKeyTypeRejection(t *testing.T) {
	// Generate a fake RSA certificate (RSA is not supported by AWS Nitro)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Create a minimal attestation document with unsupported certificate
	doc := map[string]interface{}{
		"module_id":   "test-module",
		"timestamp":   uint64(time.Now().Unix() * 1000),
		"digest":      "SHA384",
		"pcrs":        map[uint][]byte{},
		"certificate": derBytes,
		"cabundle":    [][]byte{derBytes},
	}

	payload, _ := cbor.Marshal(doc)

	// Create minimal COSE Sign1 structure
	protectedHeaders := map[int]interface{}{1: -35} // ES384
	protectedHeadersBytes, _ := cbor.Marshal(protectedHeaders)

	coseSign1 := []interface{}{
		protectedHeadersBytes,
		map[string]interface{}{},
		payload,
		[]byte{0, 0, 0, 0}, // Fake signature
	}

	attestationBytes, _ := cbor.Marshal(coseSign1)
	attestationBase64 := base64.StdEncoding.EncodeToString(attestationBytes)

	// Attempt to validate
	verifier := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	result, err := verifier.Validate(attestationBase64)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}

	// Should have validation errors
	if result.Valid {
		t.Error("Expected validation to fail for unsupported key type")
	}

	// Check for unsupported key type error
	foundKeyTypeError := false
	for _, err := range result.Errors {
		if strings.Contains(err.Error(), "unsupported public key type") && strings.Contains(err.Error(), "ECDSA") {
			foundKeyTypeError = true
			t.Logf("✓ Unsupported key type properly rejected: %v", err)
			break
		}
	}

	if !foundKeyTypeError {
		t.Errorf("Expected error about unsupported key type, got errors: %v", result.Errors)
	}
}
