package awsnitroverifier

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// DecodePEMCertificate decodes a single PEM certificate block and parses it.
// Returns an error if there are multiple PEM blocks or trailing non-whitespace data.
// This ensures that multi-certificate PEM files don't silently ignore additional certificates.
func decodePEMCertificate(pemData []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate")
	}

	// Check for trailing data or additional PEM blocks
	if len(rest) > 0 {
		// Check if the remaining data contains another PEM block or non-whitespace content
		nextBlock, _ := pem.Decode(rest)
		if nextBlock != nil {
			return nil, fmt.Errorf("multiple PEM blocks found, expected exactly one certificate")
		}
		// Check for non-whitespace trailing data
		for _, b := range rest {
			if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
				return nil, fmt.Errorf("trailing data found after PEM certificate")
			}
		}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// parseCertificateChain parses a chain of DER-encoded certificates
func parseCertificateChain(certs [][]byte) ([]*x509.Certificate, error) {
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
