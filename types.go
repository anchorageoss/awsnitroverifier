package nitroverifier

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

// ValidationResult contains the result of attestation validation
type ValidationResult struct {
	Valid            bool
	Document         *AttestationDocument
	CertificateInfo  *CertificateInfo
	CertificateChain []CertificateInfo
	ChainValidated   bool
	RootFingerprint  string
	PCRValidations   []PCRValidationResult
	Errors           []error

	// Optional fields from attestation document
	UserData  []byte
	PublicKey []byte
	Nonce     []byte
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
type PCRValidationResult struct {
	Index    uint
	Expected []byte
	Actual   []byte
	Valid    bool
	Error    error
}

// PCRRule defines a validation rule for a PCR value
type PCRRule struct {
	Index uint
	Value []byte
}

// AWSNitroVerifierOptions configures the AWS Nitro verifier behavior
type AWSNitroVerifierOptions struct {
	// SkipTimestampCheck skips certificate timestamp validation
	// Often these certificates need to be validated much later in offline systems, skipping makes sense
	// I considered that this could be some kind of threshold but that's more complicated, I prefer something simple like "secure/insecure"
	SkipTimestampCheck bool

	// CurrentTime overrides the current time for certificate validation
	// If nil, uses time.Now()
	CurrentTime time.Time

	// PCRRules defines expected PCR values to validate
	// Certain applications need to set specific values for PCRs.
	PCRRules []PCRRule

	// ExpectedCertificateCNs enables certificate Common Name (CN) validation for the entire chain.
	// The array order must match the certificate chain order:
	//   [0] = leaf certificate (from attestation document)
	//   [1] = root certificate (aws.nitro-enclaves)
	//   [2] = regional intermediate
	//   [3] = zonal intermediate
	//   [4] = instance/parent intermediate
	//
	// Use empty string "" to skip validation at any position in the chain.
	//
	// Security Context:
	// By default, certificate chain verification only validates cryptographic properties
	// (signatures, trust chain) but does NOT verify which instance/enclave the certificate
	// was issued to. This means any valid AWS Nitro certificate will pass verification,
	// enabling potential certificate substitution attacks in multi-tenant scenarios.
	//
	// AWS Nitro certificate CN patterns:
	//   Leaf (attestation):     {instance-id}-{enclave-id}.{region}.aws
	//   Root:                   aws.nitro-enclaves
	//   Regional intermediate:  {hash}.{region}.aws.nitro-enclaves
	//   Zonal intermediate:     {hash}.zonal.{region}.aws.nitro-enclaves
	//   Instance intermediate:  {instance-id}.{region}.aws.nitro-enclaves
	//
	// Example - Validate only leaf and instance (skip root and regional/zonal):
	//   ExpectedCertificateCNs: []string{
	//       "i-021e5d515ed8a0f16-enc0196696aaef2d328.us-east-1.aws",     // leaf
	//       "",                                                          // skip root
	//       "",                                                          // skip regional
	//       "",                                                          // skip zonal
	//       "i-021e5d515ed8a0f16.us-east-1.aws.nitro-enclaves",          // instance
	//   }
	//
	// Example - Validate full chain:
	//   ExpectedCertificateCNs: []string{
	//       "i-021e5d515ed8a0f16-enc0196696aaef2d328.us-east-1.aws",     // leaf
	//       "aws.nitro-enclaves",                                        // root
	//       "6c41a20877fc3447.us-east-1.aws.nitro-enclaves",            // regional
	//       "bf5a3262ba2de815.zonal.us-east-1.aws.nitro-enclaves",      // zonal
	//       "i-021e5d515ed8a0f16.us-east-1.aws.nitro-enclaves",          // instance
	//   }
	//
	// Leave nil to skip all CN validation (suitable when only software attestation via
	// PCRs is needed). Set to bind attestations to specific instances/enclaves.
	ExpectedCertificateCNs []string
}
