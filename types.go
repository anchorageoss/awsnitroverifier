package nitroverifier

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
	Index    uint
	Expected []byte
	Actual   []byte
	Valid    bool
	Error    error
}

// ValidationResult contains the result of AWS Nitro attestation validation
type ValidationResult struct {
	// Core validation results
	Valid           bool   // Whether the attestation passed all validation checks
	ChainValidated  bool   // Whether the certificate chain was validated against AWS Nitro root
	RootFingerprint string // SHA256 fingerprint of the root certificate in the chain

	// Optional fields from attestation document
	UserData  []byte // Application-specific data included in the attestation
	PublicKey []byte // Public key included in the attestation
	Nonce     []byte // Nonce included in the attestation

	// PCR validation results
	PCRValidations []PCRValidationResult // Results of PCR validations if PCRRules were provided
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
