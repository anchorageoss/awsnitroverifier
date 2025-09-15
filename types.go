package nitroverifier

import (
	"time"
)

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

// ValidatorOptions configures the validator behavior
type ValidatorOptions struct {
	// SkipTimestampCheck skips certificate timestamp validation
	SkipTimestampCheck bool

	// CurrentTime overrides the current time for certificate validation
	// If nil, uses time.Now()
	CurrentTime *time.Time

	// PCRRules defines expected PCR values to validate
	PCRRules []PCRRule

	// SkipSignatureVerification skips the signature verification
	SkipSignatureVerification bool

	// SkipChainValidation skips certificate chain validation against AWS root
	SkipChainValidation bool
}
