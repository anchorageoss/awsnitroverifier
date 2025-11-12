//go:build !selectTest || isolatedTest

package nitroverifier

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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

	// Attempt to validate
	verifier := NewVerifier(AWSNitroVerifierOptions{
		SkipTimestampCheck: true,
	})

	result, err := verifier.Validate(attestationBytes)
	if err != nil {
		t.Fatalf("Unexpected fatal error: %v", err)
	}

	// Should have validation errors
	if result.Valid {
		t.Error("Expected validation to fail for unsupported RSA key type")
	} else {
		t.Log("✓ Unsupported RSA key type properly rejected")
	}

	// AWS Nitro only supports ECDSA keys, not RSA
	if result.ChainValidated {
		t.Error("Chain should not validate with RSA certificate")
	}
}
