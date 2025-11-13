package awsnitroverifier

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/anchorageoss/awsnitroverifier/internal"
)

// embeddedAWSNitroRootCertificate returns the parsed AWS Nitro root certificate from embedded PEM data.
// This function panics if the embedded certificate cannot be parsed, as this indicates a build-time error.
func embeddedAWSNitroRootCertificate() *x509.Certificate {
	pemBlock := []byte(internal.AWSNitroRootPEM)
	cert, err := decodePEMCertificate(pemBlock)
	if err != nil {
		panic(fmt.Errorf("failed to parse embedded AWS Nitro root certificate: %w", err))
	}
	return cert
}

// verifyAWSNitroRootCertificate verifies that a certificate matches the AWS Nitro root
func verifyAWSNitroRootCertificate(cert *x509.Certificate) error {
	// Calculate fingerprint
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := hex.EncodeToString(fingerprint[:])

	if fingerprintHex != internal.AWSNitroRootFingerprint {
		return fmt.Errorf("certificate fingerprint mismatch: expected %s, got %s",
			internal.AWSNitroRootFingerprint, fingerprintHex)
	}

	// Verify subject
	expectedSubject := "CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US"
	if cert.Subject.String() != expectedSubject {
		return fmt.Errorf("certificate subject mismatch: expected %s, got %s",
			expectedSubject, cert.Subject.String())
	}

	// Verify it's self-signed
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return fmt.Errorf("root certificate is not self-signed: %w", err)
	}

	return nil
}

// verifyCertificateChain verifies the certificate chain against AWS Nitro root CA.
//
// This function validates that:
// 1. The first certificate in caBundle is the AWS Nitro root CA
// 2. The targetCert can be verified through the chain of intermediates back to the root
// 3. All certificates in the chain have valid signatures
// 4. Certificate timestamps are valid (unless opts.SkipTimestampCheck is true)
//
// Parameters:
//   - targetCert: The leaf certificate to verify (must be pre-parsed using x509.ParseCertificate)
//   - caBundle: Array of DER-encoded certificates [root, intermediate1, intermediate2, ...]
//   - opts: Optional validation options (nil uses defaults: no timestamp skip, no CN validation)
func verifyCertificateChain(targetCert *x509.Certificate, caBundle [][]byte, opts *AWSNitroVerifierOptions) error {
	if targetCert == nil {
		return fmt.Errorf("target certificate is nil")
	}

	if len(caBundle) == 0 {
		return fmt.Errorf("CA bundle is empty")
	}

	// Parse CA bundle
	caCerts, err := parseCertificateChain(caBundle)
	if err != nil {
		return fmt.Errorf("failed to parse CA bundle: %w", err)
	}

	// First certificate in bundle should be the root
	rootCert := caCerts[0]

	// Verify it's the AWS Nitro root
	if err := verifyAWSNitroRootCertificate(rootCert); err != nil {
		return fmt.Errorf("first certificate in CA bundle is not AWS Nitro root: %w", err)
	}

	// Build certificate pool
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	for i := 1; i < len(caCerts); i++ {
		intermediates.AddCert(caCerts[i])
	}

	// Verify the chain
	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	// Skip time validation if requested (for expired certificates)
	if opts != nil && opts.SkipTimestampCheck {
		verifyOpts.CurrentTime = targetCert.NotBefore.Add(time.Second) // Set time to 1 second after cert became valid
	}

	chains, err := targetCert.Verify(verifyOpts)
	if err != nil {
		return fmt.Errorf("certificate chain verification failed: %w", err)
	}

	if len(chains) == 0 {
		return fmt.Errorf("no valid certificate chains found")
	}

	return nil
}

// extractCertificateChainInfo extracts information about the certificate chain
func extractCertificateChainInfo(caBundle [][]byte) ([]internal.CertificateInfo, error) {
	caCerts, err := parseCertificateChain(caBundle)
	if err != nil {
		return nil, err
	}

	var chainInfo []internal.CertificateInfo
	for _, cert := range caCerts {
		info := internal.CertificateInfo{
			Subject:      cert.Subject.String(),
			Issuer:       cert.Issuer.String(),
			SerialNumber: cert.SerialNumber.String(),
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
		}
		chainInfo = append(chainInfo, info)
	}

	return chainInfo, nil
}

// calculateCertificateFingerprint calculates SHA-256 fingerprint of a certificate
func calculateCertificateFingerprint(cert *x509.Certificate) string {
	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:])
}
