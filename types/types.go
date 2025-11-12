package types

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
}

// CountPCRValidations returns the count of valid and invalid PCR validations
func CountPCRValidations(results []PCRValidationResult) (valid, invalid int) {
	for _, pcr := range results {
		if pcr.Valid {
			valid++
		} else {
			invalid++
		}
	}
	return valid, invalid
}
