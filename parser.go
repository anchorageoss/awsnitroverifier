package awsnitroverifier

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// parseCOSESign1 parses the COSE_Sign1 wrapper structure as defined in RFC 8152.
// See https://datatracker.ietf.org/doc/html/rfc8152#section-4.2
func parseCOSESign1(data []byte) (*coseSign1, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("COSE_Sign1 data is empty")
	}

	var coseArray []interface{}
	if err := cbor.Unmarshal(data, &coseArray); err != nil {
		return nil, fmt.Errorf("failed to unmarshal COSE_Sign1: %w", err)
	}

	if len(coseArray) != 4 {
		return nil, fmt.Errorf("invalid COSE_Sign1 structure: expected 4 elements, got %d", len(coseArray))
	}

	protectedHeaders, ok := coseArray[0].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid protected headers type")
	}

	payload, ok := coseArray[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid payload type")
	}

	signature, ok := coseArray[3].([]byte)
	if !ok {
		return nil, fmt.Errorf("invalid signature type")
	}

	return &coseSign1{
		ProtectedHeaders:   protectedHeaders,
		UnprotectedHeaders: coseArray[1],
		Payload:            payload,
		Signature:          signature,
	}, nil
}

// parseAttestationDocument parses the raw CBOR attestation document
func parseAttestationDocument(data []byte) (*AttestationDocument, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("attestation document data is empty")
	}
	if len(data) > 16*1024*1024 { // 16 MB limit
		return nil, fmt.Errorf("attestation document data exceeds maximum size")
	}

	var doc AttestationDocument

	// Configure CBOR decoder with security limits to prevent resource exhaustion attacks:
	// - MaxNestedLevels: 32 is sufficient for legitimate attestation documents
	// - MaxArrayElements/MaxMapPairs: 128 covers typical PCR count and cert chain depth
	decMode, err := cbor.DecOptions{
		MaxNestedLevels:  32,
		MaxArrayElements: 128,
		MaxMapPairs:      128,
	}.DecMode()
	if err != nil {
		return nil, fmt.Errorf("failed to create CBOR decoder: %w", err)
	}

	decoder := decMode.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode CBOR: %w", err)
	}

	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("attestation document validation failed: %w", err)
	}

	return &doc, nil
}

// extractCertificateInfo parses a DER-encoded certificate and extracts key information
func extractCertificateInfo(certDER []byte) (*certificateInfo, error) {
	if len(certDER) == 0 {
		return nil, fmt.Errorf("certificate data is empty")
	}
	if len(certDER) > 10*1024 { // 10 KB limit for a single certificate
		return nil, fmt.Errorf("certificate data exceeds maximum size")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &certificateInfo{
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		Certificate:  cert,
	}, nil
}

// validateCertificateTimestamp checks if a certificate is valid at the given time
func validateCertificateTimestamp(certInfo *certificateInfo, checkTime time.Time) error {
	if certInfo == nil {
		return fmt.Errorf("certificate info is nil")
	}

	if checkTime.IsZero() {
		return fmt.Errorf("check time is zero")
	}

	if checkTime.Before(certInfo.NotBefore) {
		return fmt.Errorf("certificate not yet valid: %v < %v", checkTime, certInfo.NotBefore)
	}
	if checkTime.After(certInfo.NotAfter) {
		return fmt.Errorf("certificate expired: %v > %v", checkTime, certInfo.NotAfter)
	}
	return nil
}
