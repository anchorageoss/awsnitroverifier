package internal

import (
	"bytes"
	"github.com/anchorageoss/awsnitroverifier/types"
)

// ValidatePCR validates a single PCR value against an expected value
func ValidatePCR(actual []byte, expected []byte, index uint) types.PCRValidationResult {
	return types.PCRValidationResult{
		Index:    index,
		Expected: expected,
		Actual:   actual,
		Valid:    bytes.Equal(actual, expected),
	}
}

// ValidatePCRs validates multiple PCR values against rules
// Returns results for all validations, allowing partial success
func ValidatePCRs(pcrs map[uint][]byte, rules []types.PCRRule) []types.PCRValidationResult {
	results := make([]types.PCRValidationResult, 0, len(rules))

	for _, rule := range rules {
		actual, exists := pcrs[rule.Index]
		if !exists {
			results = append(results, types.PCRValidationResult{
				Index:    rule.Index,
				Expected: rule.Value,
				Actual:   nil,
				Valid:    false,
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
func GetPCRValidationSummary(results []types.PCRValidationResult) PCRValidationSummary {
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
func FilterValidPCRs(results []types.PCRValidationResult) []types.PCRValidationResult {
	var valid []types.PCRValidationResult
	for _, result := range results {
		if result.Valid {
			valid = append(valid, result)
		}
	}
	return valid
}

// FilterInvalidPCRs returns only the invalid PCR results
func FilterInvalidPCRs(results []types.PCRValidationResult) []types.PCRValidationResult {
	var invalid []types.PCRValidationResult
	for _, result := range results {
		if !result.Valid {
			invalid = append(invalid, result)
		}
	}
	return invalid
}
