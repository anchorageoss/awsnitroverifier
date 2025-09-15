package nitroverifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Verifier provides methods to validate AWS Nitro attestations
type Verifier struct {
	options ValidatorOptions
}

// NewVerifier creates a new attestation validator with the given options
func NewVerifier(options ValidatorOptions) *Verifier {
	return &Verifier{
		options: options,
	}
}

// Validate performs validation on a base64-encoded attestation document
func (v *Verifier) Validate(attestationBase64 string) (*ValidationResult, error) {
	// Decode base64
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 attestation: %w", err)
	}

	return v.ValidateBytes(attestationBytes)
}

// ValidateBytes performs validation on raw attestation document bytes
func (v *Verifier) ValidateBytes(attestationBytes []byte) (*ValidationResult, error) {
	result := &ValidationResult{
		Errors: []error{},
	}

	// Parse the outer COSE Sign1 structure
	var coseSign1 interface{}
	if err := cbor.Unmarshal(attestationBytes, &coseSign1); err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to parse COSE Sign1: %w", err))
		return result, nil
	}

	// Extract the payload (attestation document)
	coseArray, ok := coseSign1.([]interface{})
	if !ok || len(coseArray) < 3 {
		result.Errors = append(result.Errors, errors.New("invalid COSE Sign1 structure"))
		return result, nil
	}

	payload, ok := coseArray[2].([]byte)
	if !ok {
		result.Errors = append(result.Errors, errors.New("failed to extract payload from COSE Sign1"))
		return result, nil
	}

	// Parse the attestation document
	doc, err := ParseAttestationDocument(payload)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Errorf("failed to parse attestation document: %w", err))
		return result, nil
	}
	result.Document = doc

	// Copy optional fields to result for easy access
	result.UserData = doc.UserData
	result.PublicKey = doc.PublicKey
	result.Nonce = doc.Nonce

	// Parse certificate information
	if len(doc.Certificate) > 0 {
		certInfo, err := ParseCertificate(doc.Certificate)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to parse certificate: %w", err))
		} else {
			result.CertificateInfo = certInfo

			// Validate certificate timestamp if not skipped
			if !v.options.SkipTimestampCheck {
				checkTime := time.Now()
				if v.options.CurrentTime != nil {
					checkTime = *v.options.CurrentTime
				}

				if err := ValidateCertificateTimestamp(certInfo, checkTime); err != nil {
					result.Errors = append(result.Errors, fmt.Errorf("certificate timestamp validation failed: %w", err))
				}
			}
		}

		// Validate certificate chain against AWS root if not skipped
		if !v.options.SkipChainValidation && doc.CABundle != nil {
			// Extract chain info
			chainInfo, err := ExtractCertificateChainInfo(doc.CABundle)
			if err == nil {
				result.CertificateChain = chainInfo
			}

			// Verify chain of trust
			if err := VerifyChainOfTrust(doc.Certificate, doc.CABundle, v.options.SkipTimestampCheck); err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("certificate chain validation failed: %w", err))
			} else {
				result.ChainValidated = true

				// Calculate root fingerprint
				if len(doc.CABundle) > 0 {
					rootCert, err := x509.ParseCertificate(doc.CABundle[0])
					if err == nil {
						result.RootFingerprint = CalculateCertificateFingerprint(rootCert)
					}
				}
			}
		}
	}

	// Validate signature if not skipped
	if !v.options.SkipSignatureVerification && len(doc.Certificate) > 0 {
		if err := v.verifySignature(attestationBytes, doc); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("signature verification failed: %w", err))
		}
	}

	// Validate PCRs if rules are provided
	if len(v.options.PCRRules) > 0 {
		result.PCRValidations = ValidatePCRs(doc.PCRs, v.options.PCRRules)

		// Check for any PCR validation failures
		for _, pcrResult := range result.PCRValidations {
			if !pcrResult.Valid && pcrResult.Error != nil {
				result.Errors = append(result.Errors, pcrResult.Error)
			}
		}
	}

	// Set overall validation result
	result.Valid = len(result.Errors) == 0

	return result, nil
}

// verifySignature verifies the COSE Sign1 signature
func (v *Verifier) verifySignature(attestationBytes []byte, doc *AttestationDocument) error {
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
	// unprotectedHeaders := coseArray[1] // Not used in Sign1
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

	// Verify based on public key type
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return v.verifyECDSA(pub, sigBase, signature)
	case *rsa.PublicKey:
		return v.verifyRSA(pub, sigBase, signature, protectedHeaders)
	default:
		return fmt.Errorf("unsupported public key type %T, only ECDSA and RSA keys are supported", pub)
	}
}

// verifyECDSA verifies an ECDSA signature
func (v *Verifier) verifyECDSA(pub *ecdsa.PublicKey, sigBase, signature []byte) error {
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

	// AWS Nitro uses raw ECDSA signatures (r||s format), not ASN.1 DER encoded
	// The signature should be exactly twice the key size
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	var rawVerified bool
	if len(signature) != 2*keySize {
		return fmt.Errorf("invalid ECDSA signature: neither raw (expected length %d, got %d) nor ASN.1 format verified", 2*keySize, len(signature))
	}
	if len(signature) == 2*keySize {
		// Split signature into r and s components
		r := new(big.Int).SetBytes(signature[:keySize])
		s := new(big.Int).SetBytes(signature[keySize:])
		rawVerified = ecdsa.Verify(pub, hash, r, s)
	}

	// verified ECDSA
	if rawVerified {
		return nil
	}

	// Try ASN.1 format as fallback
	if ecdsa.VerifyASN1(pub, hash, signature) {
		return nil
	}

	return errors.New("ECDSA signature verification failed (tried raw and ASN.1 formats)")
}

// verifyRSA verifies an RSA signature
func (v *Verifier) verifyRSA(pub *rsa.PublicKey, sigBase, signature, protectedHeaders []byte) error {
	// Parse protected headers to determine hash algorithm
	var protected map[int]interface{}
	if err := cbor.Unmarshal(protectedHeaders, &protected); err != nil {
		return fmt.Errorf("failed to parse protected headers: %w", err)
	}

	// Default to SHA256
	hashFunc := crypto.SHA256
	h := sha256.Sum256(sigBase)
	hash := h[:]

	// Check if different algorithm is specified
	if alg, ok := protected[1]; ok {
		switch alg {
		case -37: // PS256
			hashFunc = crypto.SHA256
		case -38: // PS384
			hashFunc = crypto.SHA384
			h384 := sha512.Sum384(sigBase)
			hash = h384[:]
		case -39: // PS512
			hashFunc = crypto.SHA512
			h512 := sha512.Sum512(sigBase)
			hash = h512[:]
		}
	}

	if err := rsa.VerifyPSS(pub, hashFunc, hash, signature, nil); err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	return nil
}

// ValidateWithDefaults validates an attestation with default options
func ValidateWithDefaults(attestationBase64 string) (*ValidationResult, error) {
	validator := NewVerifier(ValidatorOptions{})
	return validator.Validate(attestationBase64)
}

// ValidatePCRsOnly validates only the PCR values without signature or timestamp checks
func ValidatePCRsOnly(attestationBase64 string, pcrRules []PCRRule) (*ValidationResult, error) {
	validator := NewVerifier(ValidatorOptions{
		SkipTimestampCheck:        true,
		SkipSignatureVerification: true,
		PCRRules:                  pcrRules,
	})
	return validator.Validate(attestationBase64)
}
