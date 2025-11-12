package nitroverifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/anchorageoss/awsnitroverifier/internal"
	"github.com/fxamacker/cbor/v2"
)

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
	doc, err := internal.ParseAttestationDocument(payload)
	if err != nil {
		return nil, fmt.Errorf("malformed attestation: failed to parse document: %w", err)
	}

	// Extract optional fields from attestation
	result.UserData = doc.UserData
	result.PublicKey = doc.PublicKey
	result.Nonce = doc.Nonce

	// Now perform validations - accumulate errors in result.Errors
	var validationErrors []string

	// Validate certificate chain and signature
	if len(doc.Certificate) > 0 {
		// Parse certificate for chain verification
		cert, err := x509.ParseCertificate(doc.Certificate)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("certificate parsing: %v", err))
		} else {
			// Validate certificate timestamp if not skipped
			if !v.options.SkipTimestampCheck {
				certInfo, err := internal.ExtractCertificateInfo(doc.Certificate)
				if err != nil {
					validationErrors = append(validationErrors, fmt.Sprintf("certificate extraction: %v", err))
				} else if err := internal.ValidateCertificateTimestamp(certInfo, time.Now()); err != nil {
					validationErrors = append(validationErrors, fmt.Sprintf("certificate expired: %v", err))
				}
			}

			// Validate certificate chain against AWS root
			if doc.CABundle != nil {
				internalOpts := &internal.AWSNitroVerifierOptions{
					SkipTimestampCheck: v.options.SkipTimestampCheck,
				}
				if err := internal.VerifyCertificateChain(cert, doc.CABundle, internalOpts); err != nil {
					validationErrors = append(validationErrors, fmt.Sprintf("certificate chain: %v", err))
				} else {
					result.ChainTrusted = true
					// Calculate root fingerprint
					if len(doc.CABundle) > 0 {
						rootCert, err := x509.ParseCertificate(doc.CABundle[0])
						if err == nil {
							result.RootFingerprint = internal.CalculateCertificateFingerprint(rootCert)
						}
					}
				}
			}

			// Validate signature
			if err := v.verifySignature(attestationBytes, doc); err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("signature: %v", err))
			}
		}
	}

	// Validate PCRs if rules are provided
	if len(v.options.PCRRules) > 0 {
		// Convert public PCRRules to internal format
		internalPCRRules := make([]internal.PCRRule, len(v.options.PCRRules))
		for i, rule := range v.options.PCRRules {
			internalPCRRules[i] = internal.PCRRule{
				Index: rule.Index,
				Value: rule.Value,
			}
		}

		internalResults := internal.ValidatePCRs(doc.PCRs, internalPCRRules)

		// Convert internal results to public format
		result.PCRResults = make([]PCRValidationResult, len(internalResults))
		for i, internalResult := range internalResults {
			result.PCRResults[i] = PCRValidationResult{
				Index:    internalResult.Index,
				Expected: internalResult.Expected,
				Actual:   internalResult.Actual,
				Valid:    internalResult.Valid,
			}

			// Check for any PCR validation failures
			if !internalResult.Valid {
				validationErrors = append(validationErrors, fmt.Sprintf("PCR[%d] mismatch", internalResult.Index))
			}
		}
	}

	// Set overall validation result
	result.Errors = validationErrors
	result.Valid = len(validationErrors) == 0

	return result, nil
}

// verifySignature verifies the COSE Sign1 signature
func (v *verifier) verifySignature(attestationBytes []byte, doc *internal.AttestationDocument) error {
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