package awsnitroverifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Verifier defines the interface for verifying AWS Nitro attestation documents
type Verifier interface {
	Validate(attestationBytes []byte) (*ValidationResult, error)
}

// PCRRule defines a validation rule for a PCR value
type PCRRule struct {
	Index uint
	Value []byte
}

// PCRValidationResult represents the result of a single PCR validation
type PCRValidationResult struct {
	Index    uint   // PCR index
	Expected []byte // Expected PCR value
	Actual   []byte // Actual PCR value from attestation
	Valid    bool   // Whether the PCR matches expected value
}

// AWSNitroVerifierOptions configures the AWS Nitro verifier behavior
type AWSNitroVerifierOptions struct {
	// SkipTimestampCheck skips certificate timestamp validation.
	// Often these certificates need to be validated much later in offline systems,
	// so skipping the timestamp check may be necessary.
	SkipTimestampCheck bool

	// PCRRules defines expected PCR values to validate.
	// If provided, the verifier will check that the attestation's PCR values match these rules.
	PCRRules []PCRRule
}

// ValidationResult contains the result of AWS Nitro attestation validation
type ValidationResult struct {
	// Overall validation status - true if all required checks passed
	// Valid is true iff all required validations passed, ie.: Errors is empty
	Valid bool

	// Validation errors - empty if Valid is true
	// Each entry describes a specific validation failure
	Errors []error

	// Certificate chain validation details
	ChainTrusted    bool   // True if certificate chain validated to AWS Nitro root
	RootFingerprint string // SHA256 fingerprint of the root certificate (set if ChainTrusted is true)

	// Optional fields extracted from attestation document
	UserData  []byte // Application-specific data included in the attestation
	PublicKey []byte // Public key included in the attestation
	Nonce     []byte // Nonce included in the attestation

	// PCR validation results (only set if PCRRules were provided in options)
	PCRResults []PCRValidationResult

	// Document is added for debugging purposes and for services that may need to inspect it further
	Document *AttestationDocument
}

// verifier implements the Verifier interface
type verifier struct {
	options AWSNitroVerifierOptions
}

// NewVerifier creates a new attestation validator with the given options
func NewVerifier(options AWSNitroVerifierOptions) Verifier {
	return &verifier{
		options: options,
	}
}

// Validate performs validation on attestation document bytes
func (v *verifier) Validate(attestationBytes []byte) (*ValidationResult, error) {
	return v.validateBytes(attestationBytes)
}

// validateBytes performs validation on raw attestation document bytes
func (v *verifier) validateBytes(attestationBytes []byte) (*ValidationResult, error) {
	result := &ValidationResult{}

	// Parse the outer COSE Sign1 structure - return error for malformed input
	var coseSign1 interface{}
	if err := cbor.Unmarshal(attestationBytes, &coseSign1); err != nil {
		return nil, fmt.Errorf("malformed attestation: failed to parse CBOR: %w", err)
	}

	// Extract the payload (attestation document)
	coseArray, ok := coseSign1.([]interface{})
	if !ok || len(coseArray) < 3 {
		return nil, fmt.Errorf("malformed attestation: invalid COSE Sign1 structure")
	}

	payload, ok := coseArray[2].([]byte)
	if !ok {
		return nil, fmt.Errorf("malformed attestation: invalid COSE payload type")
	}

	// Parse the attestation document - return error for malformed input
	doc, err := parseAttestationDocument(payload)
	if err != nil {
		return nil, fmt.Errorf("malformed attestation: failed to parse document: %w", err)
	}

	// Extract optional fields from attestation
	result.UserData = doc.UserData
	result.PublicKey = doc.PublicKey
	result.Nonce = doc.Nonce

	// Now perform validations - accumulate errors in result.Errors
	var validationErrors []error

	// Validate certificate chain and signature
	if len(doc.Certificate) > 0 {
		// Parse certificate for chain verification
		cert, err := x509.ParseCertificate(doc.Certificate)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("certificate parsing: %v", err))
		} else {
			// Validate certificate timestamp if not skipped
			if !v.options.SkipTimestampCheck {
				certInfo, err := extractCertificateInfo(doc.Certificate)
				if err != nil {
					validationErrors = append(validationErrors, fmt.Errorf("certificate extraction: %v", err))
				} else if err := validateCertificateTimestamp(certInfo, time.Now()); err != nil {
					validationErrors = append(validationErrors, fmt.Errorf("certificate expired: %v", err))
				}
			}

			// Validate certificate chain against AWS root
			if doc.CABundle != nil {
				if err := verifyCertificateChain(cert, doc.CABundle, &v.options); err != nil {
					validationErrors = append(validationErrors, fmt.Errorf("certificate chain: %v", err))
				} else {
					result.ChainTrusted = true
					// Calculate root fingerprint
					if len(doc.CABundle) > 0 {
						rootCert, err := x509.ParseCertificate(doc.CABundle[0])
						if err == nil {
							result.RootFingerprint = calculateCertificateFingerprint(rootCert)
						}
					}
				}
			}

			// Validate signature
			if err := v.verifySignature(attestationBytes, doc); err != nil {
				validationErrors = append(validationErrors, fmt.Errorf("signature: %v", err))
			}
		}
	}

	// Validate PCRs if rules are provided
	if len(v.options.PCRRules) > 0 {
		// Validate PCRs
		result.PCRResults = validatePCRs(doc.PCRs, v.options.PCRRules)

		// Check for any PCR validation failures
		for _, pcr := range result.PCRResults {
			if !pcr.Valid {
				if pcr.Actual == nil {
					validationErrors = append(validationErrors, fmt.Errorf("PCR[%d] not found in attestation", pcr.Index))
				} else {
					validationErrors = append(validationErrors, fmt.Errorf("PCR[%d] mismatch", pcr.Index))
				}
			}
		}
	}

	// Set overall validation result
	result.Errors = validationErrors
	result.Valid = len(validationErrors) == 0

	return result, nil
}

// verifySignature verifies the COSE Sign1 signature
func (v *verifier) verifySignature(attestationBytes []byte, doc *AttestationDocument) error {
	// Parse the certificate
	cert, err := x509.ParseCertificate(doc.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse certificate for signature verification: %w", err)
	}

	// Parse COSE Sign1 structure
	var coseSign1 interface{}
	if err := cbor.Unmarshal(attestationBytes, &coseSign1); err != nil {
		return fmt.Errorf("failed to unmarshal COSE Sign1: %w", err)
	}

	coseArray, ok := coseSign1.([]interface{})
	if !ok || len(coseArray) < 4 {
		return errors.New("invalid COSE Sign1 structure")
	}

	// Extract components
	protectedHeaders, ok := coseArray[0].([]byte)
	if !ok {
		return errors.New("invalid protected headers type")
	}
	payload, ok := coseArray[2].([]byte)
	if !ok {
		return errors.New("invalid payload type")
	}
	signature, ok := coseArray[3].([]byte)
	if !ok {
		return errors.New("invalid signature type")
	}

	// Create the signature base
	var sigStructure []interface{}
	sigStructure = append(sigStructure, "Signature1")
	sigStructure = append(sigStructure, protectedHeaders)
	sigStructure = append(sigStructure, []byte{}) // empty for unprotected headers in Sign1
	sigStructure = append(sigStructure, payload)

	sigBase, err := cbor.Marshal(sigStructure)
	if err != nil {
		return fmt.Errorf("failed to create signature base: %w", err)
	}

	// Verify ECDSA signature (AWS Nitro exclusively uses ECDSA)
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("unsupported public key type %T: AWS Nitro attestation documents only use ECDSA keys", cert.PublicKey)
	}

	return v.verifyECDSA(pub, sigBase, signature)
}

// verifyECDSA verifies an ECDSA signature
func (v *verifier) verifyECDSA(pub *ecdsa.PublicKey, sigBase, signature []byte) error {
	// Determine hash based on curve size
	var hash []byte
	switch pub.Curve.Params().BitSize {
	case 256:
		h := sha256.Sum256(sigBase)
		hash = h[:]
	case 384:
		h := sha512.Sum384(sigBase)
		hash = h[:]
	case 521:
		h := sha512.Sum512(sigBase)
		hash = h[:]
	default:
		return fmt.Errorf("unsupported curve size: %d", pub.Curve.Params().BitSize)
	}

	// AWS Nitro uses raw ECDSA signatures (r||s format)
	// The signature should be exactly twice the key size
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	if len(signature) != 2*keySize {
		return fmt.Errorf("invalid ECDSA signature length: expected %d bytes, got %d", 2*keySize, len(signature))
	}

	// Split signature into r and s components
	r := new(big.Int).SetBytes(signature[:keySize])
	s := new(big.Int).SetBytes(signature[keySize:])

	if !ecdsa.Verify(pub, hash, r, s) {
		return errors.New("ECDSA signature verification failed")
	}

	return nil
}
