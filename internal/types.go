package internal

import (
	"crypto/x509"
	"fmt"
	"time"
)

// COSESign1 represents the COSE_Sign1 structure as defined in RFC 8152 Section 4.2
// (https://datatracker.ietf.org/doc/html/rfc8152#section-4.2)
//
// COSE_Sign1 = [
//
//	protected headers: bstr,
//	unprotected headers: {},
//	payload: bstr,
//	signature: bstr
//
// ]
//
// AWS Nitro attestation documents are wrapped in this COSE_Sign1 structure.
type COSESign1 struct {
	ProtectedHeaders   []byte
	UnprotectedHeaders interface{}
	Payload            []byte
	Signature          []byte
}

// AttestationDocument represents a parsed AWS Nitro attestation document
type AttestationDocument struct {
	ModuleID    string          `cbor:"module_id"`
	Timestamp   uint64          `cbor:"timestamp"`
	Digest      string          `cbor:"digest"`
	PCRs        map[uint][]byte `cbor:"pcrs"`
	Certificate []byte          `cbor:"certificate"`
	CABundle    [][]byte        `cbor:"cabundle"`
	PublicKey   []byte          `cbor:"public_key,omitempty"`
	UserData    []byte          `cbor:"user_data,omitempty"`
	Nonce       []byte          `cbor:"nonce,omitempty"`
}

// Validate checks for the presence of required fields in the attestation document
func (a *AttestationDocument) Validate() error {
	if a.ModuleID == "" {
		return fmt.Errorf("attestation document missing required field: module_id")
	}
	if a.Timestamp == 0 {
		return fmt.Errorf("attestation document missing required field: timestamp")
	}
	if len(a.Certificate) == 0 {
		return fmt.Errorf("attestation document missing required field: certificate")
	}
	if len(a.CABundle) == 0 {
		return fmt.Errorf("attestation document missing required field: cabundle")
	}
	return nil
}

// CertificateInfo contains extracted certificate information
type CertificateInfo struct {
	NotBefore    time.Time
	NotAfter     time.Time
	Subject      string
	Issuer       string
	SerialNumber string
	Certificate  *x509.Certificate // The parsed certificate
}

// PCRValidationResult represents the result of a single PCR validation
// This mirrors the public API type in the nitroverifier package
type PCRValidationResult struct {
	Index    uint
	Expected []byte
	Actual   []byte
	Valid    bool
	Error    error
}

// PCRRule defines a validation rule for a PCR value
// This mirrors the public API type in the nitroverifier package
type PCRRule struct {
	Index uint
	Value []byte
}

// AWSNitroVerifierOptions configures the AWS Nitro verifier behavior
type AWSNitroVerifierOptions struct {
	// SkipTimestampCheck skips certificate timestamp validation
	SkipTimestampCheck bool

	// CurrentTime overrides the current time for certificate validation
	CurrentTime time.Time

	// PCRRules defines expected PCR values to validate
	PCRRules []PCRRule

	// ExpectedCertificateCNs enables certificate Common Name (CN) validation for the entire chain
	ExpectedCertificateCNs []string
}