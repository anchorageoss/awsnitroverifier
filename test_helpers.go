package awsnitroverifier

import (
	_ "embed"
	"strings"
)

//go:embed testdata/turnkey-prod.base64
var turnkeyProductionAttestationData string

// getTurnkeyProductionAttestation returns a real attestation from Turnkey production for testing
func getTurnkeyProductionAttestation() string {
	return strings.TrimSpace(turnkeyProductionAttestationData)
}
