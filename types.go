package nitroverifier

// Re-export public types from the types package for convenience
import "github.com/anchorageoss/awsnitroverifier/types"

// Verifier defines the interface for verifying AWS Nitro attestation documents
type Verifier = types.Verifier

// PCRRule defines a validation rule for a PCR value
type PCRRule = types.PCRRule

// PCRValidationResult represents the result of a single PCR validation
type PCRValidationResult = types.PCRValidationResult

// AWSNitroVerifierOptions configures the AWS Nitro verifier behavior
type AWSNitroVerifierOptions = types.AWSNitroVerifierOptions

// ValidationResult contains the result of AWS Nitro attestation validation
type ValidationResult = types.ValidationResult
