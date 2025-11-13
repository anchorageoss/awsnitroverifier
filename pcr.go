package awsnitroverifier

import (
	"bytes"
)

// validatePCR validates a single PCR value against an expected value
func validatePCR(actual []byte, expected []byte, index uint) PCRValidationResult {
	return PCRValidationResult{
		Index:    index,
		Expected: expected,
		Actual:   actual,
		Valid:    bytes.Equal(actual, expected),
	}
}

// validatePCRs validates multiple PCR values against rules
// Returns results for all validations, allowing partial success
func validatePCRs(pcrs map[uint][]byte, rules []PCRRule) []PCRValidationResult {
	results := make([]PCRValidationResult, 0, len(rules))

	for _, rule := range rules {
		actual, exists := pcrs[rule.Index]
		if !exists {
			results = append(results, PCRValidationResult{
				Index:    rule.Index,
				Expected: rule.Value,
				Actual:   nil,
				Valid:    false,
			})
			continue
		}

		result := validatePCR(actual, rule.Value, rule.Index)
		results = append(results, result)
	}

	return results
}
