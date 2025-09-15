package nitroverifier

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ParseAttestationDocument parses the raw CBOR attestation document
func ParseAttestationDocument(data []byte) (*AttestationDocument, error) {
	var doc AttestationDocument

	decoder := cbor.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode CBOR: %w", err)
	}

	return &doc, nil
}

// ParseCertificate extracts certificate information from DER-encoded certificate
func ParseCertificate(certDER []byte) (*CertificateInfo, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &CertificateInfo{
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
	}, nil
}

// ParseCertificateChain parses a certificate chain from DER-encoded certificates
func ParseCertificateChain(certs [][]byte) ([]*x509.Certificate, error) {
	chain := make([]*x509.Certificate, 0, len(certs))

	for i, certDER := range certs {
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate %d: %w", i, err)
		}
		chain = append(chain, cert)
	}

	return chain, nil
}

// ValidateCertificateTimestamp checks if the certificate is valid at the given time
func ValidateCertificateTimestamp(certInfo *CertificateInfo, checkTime time.Time) error {
	if checkTime.Before(certInfo.NotBefore) {
		return fmt.Errorf("certificate not yet valid: current time %v is before NotBefore %v",
			checkTime, certInfo.NotBefore)
	}

	if checkTime.After(certInfo.NotAfter) {
		return fmt.Errorf("certificate has expired: current time %v is after NotAfter %v",
			checkTime, certInfo.NotAfter)
	}

	return nil
}

// DecodePEMCertificate decodes a PEM-encoded certificate
func DecodePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("PEM block is not a certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from PEM block: %w", err)
	}
	return cert, nil
}
