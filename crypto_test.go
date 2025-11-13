package awsnitroverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Embed real AWS Nitro certificate chain from testdata
// This chain contains: leaf cert -> intermediate CA -> zonal CA -> regional CA -> AWS Nitro root
//
//go:embed testdata/aws_turnkey_valid_cert_chain.pem
var realAWSCertChainPEM []byte

// Test constants - clearly marked as fake/test data to prevent confusion with real AWS certificates
const (
	fakeTestMarker = "FAKE-TEST"

	// FAKE/TEST certificate subjects - "FAKE-TEST-ONLY" prefix makes it impossible to confuse with real AWS certs
	testRootCN         = "FAKE-TEST-ONLY-aws.nitro-enclaves"
	testRootOU         = "FAKE-TEST-AWS"
	testRootOrg        = "FAKE-TEST-Amazon"
	testIntermediateCN = "FAKE-TEST-intermediate.nitro-enclaves"
	testLeafCN         = "FAKE-TEST-leaf.nitro-enclaves"

	// Real AWS Nitro root subject components for safety checks
	realAWSNitroRootCN = "aws.nitro-enclaves"
)

// ============================================================================
// Basic Validation Tests - Real AWS Nitro Root Certificate
// ============================================================================

func TestAWSNitroRootCertificate(t *testing.T) {
	t.Run("success case", func(t *testing.T) {
		cert := embeddedAWSNitroRootCertificate()
		require.NotNil(t, cert)
		require.Contains(t, cert.Subject.String(), realAWSNitroRootCN)
	})

	t.Run("embedded certificate should be valid", func(t *testing.T) {
		// This test ensures the embedded PEM certificate is properly formatted
		cert := embeddedAWSNitroRootCertificate()
		require.NotNil(t, cert)

		// Verify it's the expected AWS Nitro root
		fingerprint := calculateCertificateFingerprint(cert)
		require.Equal(t, awsNitroRootFingerprint, fingerprint)

		// Verify certificate properties
		require.True(t, cert.IsCA, "AWS Nitro root should be a CA certificate")
		require.Contains(t, cert.Subject.String(), realAWSNitroRootCN)
		require.Equal(t, cert.Subject.String(), cert.Issuer.String(), "Root certificate should be self-signed")
	})
}

func TestVerifyAWSNitroRootCertificate(t *testing.T) {
	realRoot := embeddedAWSNitroRootCertificate()

	// Create fake certificate for negative test
	fakeTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(999),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{testRootOrg},
			OrganizationalUnit: []string{testRootOU},
			CommonName:         testRootCN,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	fakeCert, _, _ := generateFakeTestCertificate(t, fakeTemplate, nil, nil)

	tests := []struct {
		name        string
		cert        *x509.Certificate
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid AWS Nitro root certificate",
			cert:    realRoot,
			wantErr: false,
		},
		{
			name:        "invalid certificate - wrong fingerprint",
			cert:        fakeCert,
			wantErr:     true,
			errContains: "certificate fingerprint mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyAWSNitroRootCertificate(tt.cert)
			assertErrorMatch(t, err, tt.wantErr, tt.errContains)
		})
	}
}

func TestCalculateCertificateFingerprint(t *testing.T) {
	cert := embeddedAWSNitroRootCertificate()

	fingerprint := calculateCertificateFingerprint(cert)
	require.NotEmpty(t, fingerprint)
	require.Equal(t, awsNitroRootFingerprint, fingerprint)
}

// ============================================================================
// Test Certificate Generation Helpers
// ============================================================================

// generateFakeTestCertificate creates a CLEARLY FAKE test certificate
// SECURITY: All test certificates contain "FAKE-TEST-ONLY" markers to prevent confusion with real certificates
func generateFakeTestCertificate(t *testing.T, template *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()

	// SECURITY CHECK: Verify test certificate subjects contain "FAKE-TEST" markers
	require.Contains(t, template.Subject.CommonName, fakeTestMarker,
		"SECURITY: Test certificate MUST contain 'FAKE-TEST' in CommonName to prevent confusion with real certificates")

	// SECURITY CHECK: Ensure the subject does NOT match real AWS Nitro certificate patterns
	require.NotEqual(t, realAWSNitroRootCN, template.Subject.CommonName,
		"SECURITY: Test certificate MUST NOT use real AWS Nitro root CN")
	require.NotContains(t, template.Subject.String(), "CN=aws.nitro-enclaves,OU=AWS,O=Amazon,C=US",
		"SECURITY: Test certificate MUST NOT match real AWS Nitro root subject")

	// Generate key pair using P-384 (same curve as AWS Nitro)
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	// If no parent, create self-signed certificate
	if parent == nil {
		parent = template
		parentKey = privateKey
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// SECURITY CHECK: Final verification that generated cert has fake markers
	require.Contains(t, cert.Subject.String(), fakeTestMarker,
		"SECURITY: Generated certificate MUST contain 'FAKE-TEST' marker in subject")

	return cert, privateKey, certDER
}

// createFakeTestChain creates a CLEARLY FAKE certificate chain for testing
// Returns: targetCertDER, caBundle, targetCert
func createFakeTestChain(t *testing.T) ([]byte, [][]byte, *x509.Certificate) {
	t.Helper()

	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(365 * 24 * time.Hour)

	// Create FAKE test root certificate
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{testRootOrg},
			OrganizationalUnit: []string{testRootOU},
			CommonName:         testRootCN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	rootCert, rootKey, rootDER := generateFakeTestCertificate(t, rootTemplate, nil, nil)

	// SECURITY CHECK: Verify root fingerprint is NOT the real AWS Nitro fingerprint
	testFingerprint := calculateCertificateFingerprint(rootCert)
	require.NotEqual(t, awsNitroRootFingerprint, testFingerprint,
		"SECURITY: Test root certificate fingerprint MUST NOT match real AWS Nitro root fingerprint")

	// Create FAKE intermediate certificate
	intermediateTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{testRootOrg},
			CommonName:   testIntermediateCN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	intermediateCert, intermediateKey, intermediateDER := generateFakeTestCertificate(t, intermediateTemplate, rootCert, rootKey)

	// Create FAKE leaf/target certificate
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{testRootOrg},
			CommonName:   testLeafCN,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCert, _, leafDER := generateFakeTestCertificate(t, leafTemplate, intermediateCert, intermediateKey)

	// Build CA bundle: [root, intermediate]
	caBundle := [][]byte{rootDER, intermediateDER}

	return leafDER, caBundle, leafCert
}

// createExpiredFakeTestChain creates a FAKE certificate chain with expired leaf
func createExpiredFakeTestChain(t *testing.T) ([]byte, [][]byte, *x509.Certificate) {
	t.Helper()

	notBefore := time.Now().Add(-365 * 24 * time.Hour)
	notAfter := time.Now().Add(-1 * 24 * time.Hour) // Expired yesterday

	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{testRootOrg},
			OrganizationalUnit: []string{testRootOU},
			CommonName:         testRootCN,
		},
		NotBefore:             notBefore,
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	rootCert, rootKey, rootDER := generateFakeTestCertificate(t, rootTemplate, nil, nil)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{testRootOrg},
			CommonName:   "FAKE-TEST-expired.nitro-enclaves",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter, // Expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCert, _, leafDER := generateFakeTestCertificate(t, leafTemplate, rootCert, rootKey)
	caBundle := [][]byte{rootDER}

	return leafDER, caBundle, leafCert
}

// ============================================================================
// Real AWS Certificate Chain Test Helpers
// ============================================================================

// parseRealAWSCertChain parses the embedded real AWS Nitro certificate chain
// Returns: all certificates in chain order [leaf, root, intermediate3, intermediate2, intermediate1]
func parseRealAWSCertChain(t *testing.T) []*x509.Certificate {
	t.Helper()

	var certs []*x509.Certificate
	remaining := realAWSCertChainPEM

	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			t.Fatalf("Expected CERTIFICATE block, got %s", block.Type)
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)
		certs = append(certs, cert)

		remaining = rest
	}

	require.Len(t, certs, 5, "Expected 5 certificates in the chain")
	return certs
}

// getRealAWSLeafCert returns the leaf certificate from the real chain
func getRealAWSLeafCert(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	certs := parseRealAWSCertChain(t)
	return certs[0], certs[0].Raw
}

// getRealAWSCABundle returns the CA bundle (root + intermediates) from the real chain
// Returns DER-encoded certificates in the order: [root, intermediate3, intermediate2, intermediate1]
func getRealAWSCABundle(t *testing.T) [][]byte {
	t.Helper()
	certs := parseRealAWSCertChain(t)

	// Chain structure: [leaf(0), root(1), intermediate3(2), intermediate2(3), intermediate1(4)]
	// CA Bundle should be: [root, intermediate3, intermediate2, intermediate1]
	return [][]byte{
		certs[1].Raw, // AWS Nitro root
		certs[2].Raw, // Regional intermediate
		certs[3].Raw, // Zonal intermediate
		certs[4].Raw, // Instance intermediate
	}
}

// ============================================================================
// Common Test Helper Functions
// ============================================================================

// buildVerifyOptions builds x509.VerifyOptions from a CA bundle
// Returns configured VerifyOptions with roots and intermediates from the bundle
func buildVerifyOptions(t *testing.T, caBundle [][]byte, currentTime time.Time) x509.VerifyOptions {
	t.Helper()

	caCerts, err := parseCertificateChain(caBundle)
	require.NoError(t, err)

	roots := x509.NewCertPool()
	roots.AddCert(caCerts[0]) // First cert is root

	intermediates := x509.NewCertPool()
	for i := 1; i < len(caCerts); i++ {
		intermediates.AddCert(caCerts[i])
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if !currentTime.IsZero() {
		opts.CurrentTime = currentTime
	}

	return opts
}

// reverseBundle reverses a byte slice bundle
func reverseBundle(bundle [][]byte) [][]byte {
	reversed := make([][]byte, len(bundle))
	for i := 0; i < len(bundle); i++ {
		reversed[i] = bundle[len(bundle)-1-i]
	}
	return reversed
}

// assertErrorMatch checks error status and optional error message content
func assertErrorMatch(t *testing.T, err error, wantErr bool, errContains string) {
	t.Helper()

	if wantErr {
		require.Error(t, err)
		if errContains != "" {
			require.Contains(t, err.Error(), errContains)
		}
	} else {
		require.NoError(t, err)
	}
}

// assertCertificateInfo validates that a CertificateInfo has all required fields populated
func assertCertificateInfo(t *testing.T, info certificateInfo, description string) {
	t.Helper()

	require.NotEmpty(t, info.Subject, "%s: subject should not be empty", description)
	require.NotEmpty(t, info.Issuer, "%s: issuer should not be empty", description)
	require.NotEmpty(t, info.SerialNumber, "%s: serial number should not be empty", description)
	require.False(t, info.NotBefore.IsZero(), "%s: NotBefore should not be zero", description)
	require.False(t, info.NotAfter.IsZero(), "%s: NotAfter should not be zero", description)
}

// ============================================================================
// Table-Driven Tests: Real AWS Nitro Certificate Chain
// ============================================================================

func TestRealAWSCertChain(t *testing.T) {
	// Parse the real certificate chain once for all subtests
	certs := parseRealAWSCertChain(t)
	leafCert, leafDER := getRealAWSLeafCert(t)
	caBundle := getRealAWSCABundle(t)

	t.Run("chain structure validation", func(t *testing.T) {
		require.Len(t, certs, 5, "Expected 5 certificates: leaf + root + 3 intermediates")

		// Leaf certificate
		require.False(t, certs[0].IsCA, "Leaf certificate should not be CA")
		require.Contains(t, certs[0].Subject.String(), "i-03e84b45794")

		// Root certificate
		require.True(t, certs[1].IsCA, "Root certificate should be CA")
		require.Contains(t, certs[1].Subject.String(), realAWSNitroRootCN)
		require.Equal(t, certs[1].Subject.String(), certs[1].Issuer.String(), "Root should be self-signed")

		// All intermediates should be CAs
		for i := 2; i < len(certs); i++ {
			require.True(t, certs[i].IsCA, "Intermediate certificate %d should be CA", i-1)
		}
	})

	t.Run("root certificate verification", func(t *testing.T) {
		rootCert := certs[1] // Second cert is the AWS Nitro root

		err := verifyAWSNitroRootCertificate(rootCert)
		require.NoError(t, err, "Root certificate should be valid AWS Nitro root")

		fingerprint := calculateCertificateFingerprint(rootCert)
		require.Equal(t, awsNitroRootFingerprint, fingerprint,
			"Root fingerprint should match expected AWS Nitro root")
	})

	t.Run("successful verification at valid time", func(t *testing.T) {
		// Set clock to a time when certificates were valid (May 5, 2025, 23:00 UTC)
		validTime := time.Date(2025, 5, 5, 23, 0, 0, 0, time.UTC)
		opts := buildVerifyOptions(t, caBundle, validTime)

		chains, err := leafCert.Verify(opts)
		require.NoError(t, err, "Certificate chain should verify at valid time")
		require.NotEmpty(t, chains, "Should find valid certificate chains")
	})

	t.Run("verification fails with expired certificates", func(t *testing.T) {
		// Current time is after certificate expiration (October 2025)
		// Set clock to a time after certificate expiration (November 1, 2025, 00:00 UTC)
		expiredTime := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
		opts := buildVerifyOptions(t, caBundle, expiredTime)
		_, err := leafCert.Verify(opts)
		require.Error(t, err)
		require.Contains(t, err.Error(), "certificate has expired")
	})

	t.Run("successful verification with skipTimestamp", func(t *testing.T) {
		// skipTimestamp should allow verification of expired certificates
		err := verifyCertificateChain(leafCert, caBundle, &AWSNitroVerifierOptions{SkipTimestampCheck: true})
		require.NoError(t, err, "Should verify with skipTimestamp despite expiration")
	})

	t.Run("successful verification from DER bytes", func(t *testing.T) {
		// Parse certificate from DER bytes and verify
		cert, err := x509.ParseCertificate(leafDER)
		require.NoError(t, err)

		err = verifyCertificateChain(cert, caBundle, &AWSNitroVerifierOptions{SkipTimestampCheck: true})
		require.NoError(t, err, "Chain should verify with parsed certificate")
	})

	t.Run("extractCertificateChainInfo", func(t *testing.T) {
		chainInfo, err := extractCertificateChainInfo(caBundle)
		require.NoError(t, err)
		require.Len(t, chainInfo, 4, "Expected 4 certificates in CA bundle")

		// Verify root certificate info
		require.Contains(t, chainInfo[0].Subject, realAWSNitroRootCN)
		require.Contains(t, chainInfo[0].Issuer, realAWSNitroRootCN) // Self-signed root
		require.NotEmpty(t, chainInfo[0].SerialNumber)

		// Verify all intermediates have proper structure
		for i := 1; i < len(chainInfo); i++ {
			assertCertificateInfo(t, chainInfo[i], "Intermediate "+string(rune('0'+i)))
		}
	})

	t.Run("wrong order fails", func(t *testing.T) {
		reversedBundle := reverseBundle(caBundle)
		err := verifyCertificateChain(leafCert, reversedBundle, nil)
		assertErrorMatch(t, err, true, "first certificate in CA bundle is not AWS Nitro root")
	})

	t.Run("missing intermediate fails", func(t *testing.T) {
		// Remove one intermediate (keep only root and first intermediate)
		incompleteBundle := [][]byte{caBundle[0], caBundle[1]}
		err := verifyCertificateChain(leafCert, incompleteBundle, nil)
		assertErrorMatch(t, err, true, "certificate chain verification failed")
	})

	t.Run("only root fails", func(t *testing.T) {
		rootOnlyBundle := [][]byte{caBundle[0]}
		err := verifyCertificateChain(leafCert, rootOnlyBundle, nil)
		assertErrorMatch(t, err, true, "certificate chain verification failed")
	})
}

// ============================================================================
// Table-Driven Tests: decodePEMCertificate
// ============================================================================

func TestDecodePEMCertificate(t *testing.T) {
	tests := []struct {
		name        string
		pemData     []byte
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cert *x509.Certificate)
	}{
		{
			name:    "valid AWS Nitro root certificate",
			pemData: []byte(awsNitroRootPEM),
			wantErr: false,
			validate: func(t *testing.T, cert *x509.Certificate) {
				require.NotNil(t, cert)
				require.Contains(t, cert.Subject.String(), realAWSNitroRootCN)
			},
		},
		{
			name:        "invalid PEM - not PEM format",
			pemData:     []byte("not a valid PEM block"),
			wantErr:     true,
			errContains: "failed to parse PEM block",
		},
		{
			name: "invalid PEM - wrong block type (private key)",
			pemData: []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END PRIVATE KEY-----`),
			wantErr:     true,
			errContains: "PEM block is not a certificate",
		},
		{
			name: "invalid PEM - malformed certificate data",
			pemData: []byte(`-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----`),
			wantErr:     true,
			errContains: "failed to parse certificate",
		},
		{
			name:        "empty PEM data",
			pemData:     []byte(""),
			wantErr:     true,
			errContains: "failed to parse PEM block",
		},
		{
			name: "multiple PEM blocks - should fail",
			pemData: []byte(`-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`),
			wantErr:     true,
			errContains: "multiple PEM blocks found",
		},
		{
			name: "trailing non-whitespace data - should fail",
			pemData: []byte(`-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----
some trailing data that should cause an error`),
			wantErr:     true,
			errContains: "trailing data found after PEM certificate",
		},
		{
			name: "trailing whitespace only - should pass",
			pemData: []byte(`-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----

	`),
			wantErr: false,
			validate: func(t *testing.T, cert *x509.Certificate) {
				require.NotNil(t, cert)
				require.Contains(t, cert.Subject.String(), realAWSNitroRootCN)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := decodePEMCertificate(tt.pemData)

			assertErrorMatch(t, err, tt.wantErr, tt.errContains)
			if tt.wantErr {
				require.Nil(t, cert)
			} else {
				require.NotNil(t, cert)
				if tt.validate != nil {
					tt.validate(t, cert)
				}
			}
		})
	}
}

// ============================================================================
// Table-Driven Tests: parseCertificateChain
// ============================================================================

func TestParseCertificateChain(t *testing.T) {
	// Setup test data
	_, validCABundle, _ := createFakeTestChain(t)

	tests := []struct {
		name        string
		certs       [][]byte
		wantErr     bool
		errContains string
		wantLen     int
		validate    func(t *testing.T, certs []*x509.Certificate)
	}{
		{
			name:    "valid certificate chain",
			certs:   validCABundle,
			wantErr: false,
			wantLen: 2,
			validate: func(t *testing.T, certs []*x509.Certificate) {
				require.True(t, certs[0].IsCA)
				require.True(t, certs[1].IsCA)
				// Verify all certs have FAKE-TEST markers
				for _, cert := range certs {
					require.Contains(t, cert.Subject.String(), fakeTestMarker)
				}
			},
		},
		{
			name:    "empty certificate chain",
			certs:   [][]byte{},
			wantErr: false,
			wantLen: 0,
		},
		{
			name: "invalid certificate in chain",
			certs: [][]byte{
				[]byte("not a valid certificate"),
			},
			wantErr:     true,
			errContains: "failed to parse certificate 0",
		},
		{
			name:        "partially invalid chain",
			certs:       append(validCABundle, []byte("invalid certificate")),
			wantErr:     true,
			errContains: "failed to parse certificate 2",
		},
		{
			name: "nil certificate in chain",
			certs: [][]byte{
				validCABundle[0],
				nil,
			},
			wantErr:     true,
			errContains: "failed to parse certificate 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certs, err := parseCertificateChain(tt.certs)

			assertErrorMatch(t, err, tt.wantErr, tt.errContains)
			if tt.wantErr {
				require.Nil(t, certs)
			} else {
				require.Len(t, certs, tt.wantLen)
				if tt.validate != nil {
					tt.validate(t, certs)
				}
			}
		})
	}
}

// ============================================================================
// Table-Driven Tests: verifyCertificateChain
// ============================================================================

func TestVerifyCertificateChain(t *testing.T) {
	// Setup test data
	leafDER, validCABundle, validLeafCert := createFakeTestChain(t)
	_, expiredCABundle, expiredLeafCert := createExpiredFakeTestChain(t)

	tests := []struct {
		name        string
		targetCert  *x509.Certificate
		caBundle    [][]byte
		opts        *AWSNitroVerifierOptions
		wantErr     bool
		errContains string
	}{
		{
			name:        "rejects non-AWS root (SECURITY TEST)",
			targetCert:  validLeafCert,
			caBundle:    validCABundle,
			opts:        nil,
			wantErr:     true,
			errContains: "first certificate in CA bundle is not AWS Nitro root",
		},
		{
			name:        "empty CA bundle",
			targetCert:  validLeafCert,
			caBundle:    [][]byte{},
			opts:        nil,
			wantErr:     true,
			errContains: "CA bundle is empty",
		},
		{
			name:       "invalid CA bundle - unparseable",
			targetCert: validLeafCert,
			caBundle: [][]byte{
				[]byte("invalid certificate data"),
			},
			opts:        nil,
			wantErr:     true,
			errContains: "failed to parse CA bundle",
		},
		{
			name:        "wrong order - intermediate before root",
			targetCert:  validLeafCert,
			caBundle:    [][]byte{validCABundle[1], validCABundle[0]}, // Reversed
			opts:        nil,
			wantErr:     true,
			errContains: "first certificate in CA bundle is not AWS Nitro root",
		},
		{
			name: "missing intermediate certificate",
			targetCert: func() *x509.Certificate {
				cert, err := x509.ParseCertificate(leafDER)
				require.NoError(t, err)
				return cert
			}(),
			caBundle:    [][]byte{validCABundle[0]}, // Only root, missing intermediate
			opts:        nil,
			wantErr:     true,
			errContains: "first certificate in CA bundle is not AWS Nitro root",
		},
		{
			name:        "expired certificate without skipTimestamp",
			targetCert:  expiredLeafCert,
			caBundle:    expiredCABundle,
			opts:        nil,
			wantErr:     true,
			errContains: "first certificate in CA bundle is not AWS Nitro root",
		},
		{
			name:        "expired certificate with skipTimestamp",
			targetCert:  expiredLeafCert,
			caBundle:    expiredCABundle,
			opts:        &AWSNitroVerifierOptions{SkipTimestampCheck: true},
			wantErr:     true,
			errContains: "first certificate in CA bundle is not AWS Nitro root",
		},
		{
			name:        "nil target certificate",
			targetCert:  nil,
			caBundle:    validCABundle,
			opts:        nil,
			wantErr:     true,
			errContains: "target certificate is nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyCertificateChain(tt.targetCert, tt.caBundle, tt.opts)
			assertErrorMatch(t, err, tt.wantErr, tt.errContains)
		})
	}
}

// ============================================================================
// Table-Driven Tests: extractCertificateChainInfo
// ===========================================================================

func TestExtractCertificateChainInfo(t *testing.T) {
	// Setup test data
	_, validCABundle, _ := createFakeTestChain(t)

	tests := []struct {
		name        string
		caBundle    [][]byte
		wantErr     bool
		errContains string
		wantLen     int
		validate    func(t *testing.T, chainInfo []certificateInfo)
	}{
		{
			name:     "valid certificate chain",
			caBundle: validCABundle,
			wantErr:  false,
			wantLen:  2,
			validate: func(t *testing.T, chainInfo []certificateInfo) {
				// Check root certificate info
				assertCertificateInfo(t, chainInfo[0], "root certificate")
				require.Contains(t, chainInfo[0].Subject, testRootCN)
				require.Contains(t, chainInfo[0].Subject, fakeTestMarker)
				require.Contains(t, chainInfo[0].Issuer, testRootCN) // Self-signed

				// Check intermediate certificate info
				assertCertificateInfo(t, chainInfo[1], "intermediate certificate")
				require.Contains(t, chainInfo[1].Subject, testIntermediateCN)
				require.Contains(t, chainInfo[1].Subject, fakeTestMarker)
			},
		},
		{
			name: "invalid bundle - unparseable certificate",
			caBundle: [][]byte{
				[]byte("not a certificate"),
			},
			wantErr: true,
		},
		{
			name:     "empty bundle",
			caBundle: [][]byte{},
			wantErr:  false,
			wantLen:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chainInfo, err := extractCertificateChainInfo(tt.caBundle)

			assertErrorMatch(t, err, tt.wantErr, tt.errContains)
			if tt.wantErr {
				require.Nil(t, chainInfo)
			} else {
				require.Len(t, chainInfo, tt.wantLen)
				if tt.validate != nil {
					tt.validate(t, chainInfo)
				}
			}
		})
	}
}

// ============================================================================
// Table-Driven Tests: VerifyAWSNitroRootCertificate
// ============================================================================

func TestVerifyAWSNitroRootCertificate_EdgeCases(t *testing.T) {
	// Get real AWS Nitro root for valid test case
	realRoot := embeddedAWSNitroRootCertificate()

	// Create fake test certificate with wrong fingerprint
	fakeRootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{testRootOrg},
			OrganizationalUnit: []string{testRootOU},
			CommonName:         testRootCN,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	fakeCert, _, _ := generateFakeTestCertificate(t, fakeRootTemplate, nil, nil)

	tests := []struct {
		name        string
		cert        *x509.Certificate
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid AWS Nitro root certificate",
			cert:    realRoot,
			wantErr: false,
		},
		{
			name:        "fake certificate - wrong fingerprint (SECURITY TEST)",
			cert:        fakeCert,
			wantErr:     true,
			errContains: "certificate fingerprint mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyAWSNitroRootCertificate(tt.cert)
			assertErrorMatch(t, err, tt.wantErr, tt.errContains)
		})
	}
}

func TestVerifyAWSNitroRootCertificate_SubjectValidation(t *testing.T) {
	// Get real AWS Nitro root
	realRoot := embeddedAWSNitroRootCertificate()

	// Create a modified certificate with real fingerprint but manipulated subject
	// This reaches the subject validation path by passing fingerprint check
	certWithWrongSubject := &x509.Certificate{}
	*certWithWrongSubject = *realRoot // Copy all fields
	certWithWrongSubject.Subject = pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"WrongOrg"},
		OrganizationalUnit: []string{"WrongOU"},
		CommonName:         "wrong.subject",
	}
	// Keep Raw bytes same to pass fingerprint check
	certWithWrongSubject.Raw = realRoot.Raw

	// This should fail at subject check (after passing fingerprint)
	err := verifyAWSNitroRootCertificate(certWithWrongSubject)
	require.Error(t, err)
	require.Contains(t, err.Error(), "certificate subject mismatch")
}

func TestVerifyAWSNitroRootCertificate_SelfSignedValidation(t *testing.T) {
	// Get real AWS Nitro root
	realRoot := embeddedAWSNitroRootCertificate()

	// Create a fake parent certificate
	fakeParentTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{testRootOrg},
			OrganizationalUnit: []string{testRootOU},
			CommonName:         testRootCN + "-parent",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(730 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	fakeParent, _, fakeParentDER := generateFakeTestCertificate(t, fakeParentTemplate, nil, nil)

	// Create a modified certificate with real fingerprint and subject but different signature
	// This reaches the self-signed validation path by passing fingerprint and subject checks
	certNotSelfSigned := &x509.Certificate{}
	*certNotSelfSigned = *realRoot // Copy all fields including subject
	// Keep Raw bytes same to pass fingerprint check
	certNotSelfSigned.Raw = realRoot.Raw
	// Modify signature-related fields to make CheckSignatureFrom fail
	certNotSelfSigned.Signature = fakeParent.Signature
	certNotSelfSigned.PublicKey = fakeParent.PublicKey
	certNotSelfSigned.RawSubjectPublicKeyInfo = fakeParentDER[len(fakeParentDER)-100:] // Use different public key bytes

	// This should fail at self-signed check (after passing fingerprint and subject)
	err := verifyAWSNitroRootCertificate(certNotSelfSigned)
	require.Error(t, err)
	require.Contains(t, err.Error(), "root certificate is not self-signed")
}

// ============================================================================
// Security Safety Tests
// ============================================================================

func TestSafetyCheckTestCertificatesCannotMatchRealAWS(t *testing.T) {
	// This critical test ensures our test certificate generation is safe
	_, caBundle, _ := createFakeTestChain(t)

	// Parse the test root
	certs, err := parseCertificateChain(caBundle)
	require.NoError(t, err)
	testRoot := certs[0]

	// Get real AWS root
	realRoot := embeddedAWSNitroRootCertificate()

	// SECURITY: Verify fingerprints are different
	testFingerprint := calculateCertificateFingerprint(testRoot)
	realFingerprint := calculateCertificateFingerprint(realRoot)
	require.NotEqual(t, realFingerprint, testFingerprint,
		"SECURITY: Test certificate fingerprint MUST differ from real AWS Nitro root")
	require.NotEqual(t, awsNitroRootFingerprint, testFingerprint,
		"SECURITY: Test certificate fingerprint MUST NOT match AWS Nitro constant")

	// SECURITY: Verify subjects are different
	require.NotEqual(t, realRoot.Subject.String(), testRoot.Subject.String(),
		"SECURITY: Test certificate subject MUST differ from real AWS Nitro root")
	require.Contains(t, testRoot.Subject.String(), fakeTestMarker,
		"SECURITY: Test certificate subject MUST contain FAKE-TEST marker")

	// SECURITY: Verify test cert fails AWS verification
	err = verifyAWSNitroRootCertificate(testRoot)
	require.Error(t, err, "SECURITY: Test certificate MUST fail AWS Nitro root verification")

	// SECURITY: Verify all certificates in chain have FAKE-TEST markers
	for i, cert := range certs {
		require.Contains(t, cert.Subject.String(), "FAKE-TEST",
			"SECURITY: Certificate %d MUST contain FAKE-TEST marker", i)
	}
}

// ============================================================================
// Certificate Validity Period Documentation Tests
// ============================================================================

func TestAWSNitroCertificateValidityPeriods(t *testing.T) {
	// This test documents the actual validity periods of AWS Nitro certificates
	// using real AWS Nitro attestation data from Turnkey
	certs := parseRealAWSCertChain(t)

	// Leaf certificate (attestation certificate)
	leafCert := certs[0]
	leafDuration := leafCert.NotAfter.Sub(leafCert.NotBefore)

	t.Logf("=== Leaf Certificate (Attestation) ===")
	t.Logf("NotBefore: %s", leafCert.NotBefore.Format(time.RFC3339))
	t.Logf("NotAfter:  %s", leafCert.NotAfter.Format(time.RFC3339))
	t.Logf("Duration:  %s (%.1f hours)", leafDuration, leafDuration.Hours())

	// Root certificate
	rootCert := certs[1]
	rootDuration := rootCert.NotAfter.Sub(rootCert.NotBefore)

	t.Logf("\n=== Root Certificate ===")
	t.Logf("NotBefore: %s", rootCert.NotBefore.Format(time.RFC3339))
	t.Logf("NotAfter:  %s", rootCert.NotAfter.Format(time.RFC3339))
	t.Logf("Duration:  %s (%.1f years)", rootDuration, rootDuration.Hours()/24/365.25)

	// Intermediate certificates
	for i := 2; i < len(certs); i++ {
		intermediateCert := certs[i]
		intermediateDuration := intermediateCert.NotAfter.Sub(intermediateCert.NotBefore)

		t.Logf("\n=== Intermediate Certificate %d ===", i-1)
		t.Logf("Subject:   %s", intermediateCert.Subject.CommonName)
		t.Logf("NotBefore: %s", intermediateCert.NotBefore.Format(time.RFC3339))
		t.Logf("NotAfter:  %s", intermediateCert.NotAfter.Format(time.RFC3339))
		t.Logf("Duration:  %s (%.1f days)", intermediateDuration, intermediateDuration.Hours()/24)
	}

	// Verify leaf certificate duration matches AWS documentation (~3 hours)
	require.InDelta(t, 3.0, leafDuration.Hours(), 0.1,
		"Leaf certificate should have ~3 hours validity (AWS documentation)")

	// Verify root certificate duration matches AWS documentation (30 years)
	require.InDelta(t, 30.0, rootDuration.Hours()/24/365.25, 0.5,
		"Root certificate should have ~30 years validity (AWS documentation)")
}

// ============================================================================
// Complex Chain Tests
// ============================================================================

func TestVerifyCertificateChainMultipleIntermediates(t *testing.T) {
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := time.Now().Add(365 * 24 * time.Hour)

	// Create FAKE root
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{testRootOrg},
			OrganizationalUnit: []string{testRootOU},
			CommonName:         testRootCN,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            3,
	}

	rootCert, rootKey, rootDER := generateFakeTestCertificate(t, rootTemplate, nil, nil)

	// Create first FAKE intermediate
	intermediate1Template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{testRootOrg},
			CommonName:   "FAKE-TEST-intermediate1.nitro-enclaves",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	intermediate1Cert, intermediate1Key, intermediate1DER := generateFakeTestCertificate(t, intermediate1Template, rootCert, rootKey)

	// Create second FAKE intermediate
	intermediate2Template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{testRootOrg},
			CommonName:   "FAKE-TEST-intermediate2.nitro-enclaves",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter.Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	intermediate2Cert, intermediate2Key, intermediate2DER := generateFakeTestCertificate(t, intermediate2Template, intermediate1Cert, intermediate1Key)

	// Create FAKE leaf
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{testRootOrg},
			CommonName:   "FAKE-TEST-leaf-multi.nitro-enclaves",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	leafCert, _, _ := generateFakeTestCertificate(t, leafTemplate, intermediate2Cert, intermediate2Key)

	// Build CA bundle: [root, intermediate1, intermediate2]
	caBundle := [][]byte{rootDER, intermediate1DER, intermediate2DER}

	err := verifyCertificateChain(leafCert, caBundle, nil)
	require.Error(t, err, "FAKE test certificates MUST be rejected")
	require.Contains(t, err.Error(), "first certificate in CA bundle is not AWS Nitro root")
}
