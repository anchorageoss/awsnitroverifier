package nitroverifier

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// ValidatePCR validates a single PCR value against an expected value
func ValidatePCR(actual []byte, expected []byte, index uint) PCRValidationResult {
	result := PCRValidationResult{
		Index:    index,
		Expected: expected,
		Actual:   actual,
		Valid:    bytes.Equal(actual, expected),
	}

	if !result.Valid {
		result.Error = fmt.Errorf("PCR[%d] mismatch: expected %s, got %s",
			index, hex.EncodeToString(expected), hex.EncodeToString(actual))
	}

	return result
}

// ValidatePCRs validates multiple PCR values against rules
// Returns results for all validations, allowing partial success
func ValidatePCRs(pcrs map[uint][]byte, rules []PCRRule) []PCRValidationResult {
	results := make([]PCRValidationResult, 0, len(rules))

	for _, rule := range rules {
		actual, exists := pcrs[rule.Index]
		if !exists {
			results = append(results, PCRValidationResult{
				Index:    rule.Index,
				Expected: rule.Value,
				Actual:   nil,
				Valid:    false,
				Error:    fmt.Errorf("PCR[%d] not found in attestation document", rule.Index),
			})
			continue
		}

		result := ValidatePCR(actual, rule.Value, rule.Index)
		results = append(results, result)
	}

	return results
}

// PCRValidationSummary provides a summary of PCR validation results
type PCRValidationSummary struct {
	Total   int
	Valid   int
	Invalid int
	Missing int
}

// GetPCRValidationSummary analyzes validation results and returns a summary
func GetPCRValidationSummary(results []PCRValidationResult) PCRValidationSummary {
	summary := PCRValidationSummary{
		Total: len(results),
	}

	for _, result := range results {
		if result.Actual == nil {
			summary.Missing++
		} else if result.Valid {
			summary.Valid++
		} else {
			summary.Invalid++
		}
	}

	return summary
}

// FilterValidPCRs returns only the valid PCR results
func FilterValidPCRs(results []PCRValidationResult) []PCRValidationResult {
	var valid []PCRValidationResult
	for _, result := range results {
		if result.Valid {
			valid = append(valid, result)
		}
	}
	return valid
}

// FilterInvalidPCRs returns only the invalid PCR results
func FilterInvalidPCRs(results []PCRValidationResult) []PCRValidationResult {
	var invalid []PCRValidationResult
	for _, result := range results {
		if !result.Valid {
			invalid = append(invalid, result)
		}
	}
	return invalid
}
