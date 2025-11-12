package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPCRRule(t *testing.T) {
	tests := []struct {
		name  string
		rule  PCRRule
		index uint
		value []byte
	}{
		{
			name:  "Basic rule",
			rule:  PCRRule{Index: 0, Value: []byte("test-value")},
			index: 0,
			value: []byte("test-value"),
		},
		{
			name:  "PCR index 8",
			rule:  PCRRule{Index: 8, Value: []byte("another-value")},
			index: 8,
			value: []byte("another-value"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.index, tt.rule.Index)
			require.Equal(t, tt.value, tt.rule.Value)
		})
	}
}

func TestPCRValidationResult(t *testing.T) {
	tests := []struct {
		name     string
		result   PCRValidationResult
		wantValid bool
		index    uint
	}{
		{
			name: "Valid PCR",
			result: PCRValidationResult{
				Index:    0,
				Expected: []byte("expected"),
				Actual:   []byte("expected"),
				Valid:    true,
			},
			wantValid: true,
			index:     0,
		},
		{
			name: "Invalid PCR mismatch",
			result: PCRValidationResult{
				Index:    1,
				Expected: []byte("expected"),
				Actual:   []byte("actual"),
				Valid:    false,
			},
			wantValid: false,
			index:     1,
		},
		{
			name: "Invalid PCR missing",
			result: PCRValidationResult{
				Index:    8,
				Expected: []byte("value"),
				Actual:   nil,
				Valid:    false,
			},
			wantValid: false,
			index:     8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantValid, tt.result.Valid)
			require.Equal(t, tt.index, tt.result.Index)
		})
	}
}

func TestAWSNitroVerifierOptions(t *testing.T) {
	tests := []struct {
		name                   string
		opts                   AWSNitroVerifierOptions
		wantSkipTimestampCheck bool
		wantPCRRulesLen        int
	}{
		{
			name:                   "Default options",
			opts:                   AWSNitroVerifierOptions{},
			wantSkipTimestampCheck: false,
			wantPCRRulesLen:        0,
		},
		{
			name: "Skip timestamp check",
			opts: AWSNitroVerifierOptions{
				SkipTimestampCheck: true,
			},
			wantSkipTimestampCheck: true,
			wantPCRRulesLen:        0,
		},
		{
			name: "With PCR rules",
			opts: AWSNitroVerifierOptions{
				SkipTimestampCheck: true,
				PCRRules: []PCRRule{
					{Index: 0, Value: []byte("value0")},
					{Index: 1, Value: []byte("value1")},
				},
			},
			wantSkipTimestampCheck: true,
			wantPCRRulesLen:        2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantSkipTimestampCheck, tt.opts.SkipTimestampCheck)
			require.Len(t, tt.opts.PCRRules, tt.wantPCRRulesLen)
		})
	}
}

func TestValidationResult(t *testing.T) {
	tests := []struct {
		name              string
		result            ValidationResult
		wantValid         bool
		wantChainTrusted  bool
		wantErrorsLen     int
		wantPCRResultsLen int
		wantHasUserData   bool
		wantHasPublicKey  bool
	}{
		{
			name: "Valid result",
			result: ValidationResult{
				Valid:  true,
				Errors: []string{},
			},
			wantValid:         true,
			wantChainTrusted:  false,
			wantErrorsLen:     0,
			wantPCRResultsLen: 0,
			wantHasUserData:   false,
			wantHasPublicKey:  false,
		},
		{
			name: "Invalid result with errors",
			result: ValidationResult{
				Valid: false,
				Errors: []string{
					"error 1",
					"error 2",
				},
				ChainTrusted: false,
			},
			wantValid:         false,
			wantChainTrusted:  false,
			wantErrorsLen:     2,
			wantPCRResultsLen: 0,
			wantHasUserData:   false,
			wantHasPublicKey:  false,
		},
		{
			name: "Result with attestation fields",
			result: ValidationResult{
				Valid:     true,
				Errors:    []string{},
				UserData:  []byte("user-data"),
				PublicKey: []byte("public-key"),
				Nonce:     []byte("nonce"),
			},
			wantValid:         true,
			wantChainTrusted:  false,
			wantErrorsLen:     0,
			wantPCRResultsLen: 0,
			wantHasUserData:   true,
			wantHasPublicKey:  true,
		},
		{
			name: "Result with chain trusted",
			result: ValidationResult{
				Valid:           true,
				ChainTrusted:    true,
				RootFingerprint: "abc123def456",
			},
			wantValid:         true,
			wantChainTrusted:  true,
			wantErrorsLen:     0,
			wantPCRResultsLen: 0,
			wantHasUserData:   false,
			wantHasPublicKey:  false,
		},
		{
			name: "Result with PCR validation results",
			result: ValidationResult{
				Valid:  false,
				Errors: []string{"PCR mismatch"},
				PCRResults: []PCRValidationResult{
					{
						Index:    0,
						Expected: []byte("expected"),
						Actual:   []byte("actual"),
						Valid:    false,
					},
				},
			},
			wantValid:         false,
			wantChainTrusted:  false,
			wantErrorsLen:     1,
			wantPCRResultsLen: 1,
			wantHasUserData:   false,
			wantHasPublicKey:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantValid, tt.result.Valid)
			require.Equal(t, tt.wantChainTrusted, tt.result.ChainTrusted)
			require.Len(t, tt.result.Errors, tt.wantErrorsLen)
			require.Len(t, tt.result.PCRResults, tt.wantPCRResultsLen)

			if tt.wantHasUserData {
				require.NotEmpty(t, tt.result.UserData)
			} else {
				require.Empty(t, tt.result.UserData)
			}

			if tt.wantHasPublicKey {
				require.NotEmpty(t, tt.result.PublicKey)
			} else {
				require.Empty(t, tt.result.PublicKey)
			}
		})
	}
}
