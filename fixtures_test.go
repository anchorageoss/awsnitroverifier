//go:build !selectTest || isolatedTest

package nitroverifier

import (
	_ "embed"
	"strings"
)

// Embedded attestation fixtures for testing
// These include both Turnkey-specific attestations and generic AWS examples

//go:embed testdata/turnkey-prod.base64
var turnkeyProductionAttestation string

//go:embed testdata/turnkey-preprod.base64
var turnkeyPreProductionAttestation string

//go:embed testdata/aws-nitro-example.base64
var awsNitroExampleAttestation string //nolint:unused // Reserved for future AWS Nitro example fixtures

// turnkeyFixtures provides access to embedded Turnkey attestation test data (test-only)
var turnkeyFixtures = struct {
	Production    string
	PreProduction string
}{
	Production:    strings.TrimSpace(turnkeyProductionAttestation),
	PreProduction: strings.TrimSpace(turnkeyPreProductionAttestation),
}

// awsFixtures provides access to generic AWS Nitro attestation examples (test-only)
var awsFixtures = struct { //nolint:unused // Reserved for future AWS Nitro example fixtures
	Example string
}{
	Example: strings.TrimSpace(awsNitroExampleAttestation),
}

// getTurnkeyProductionAttestation returns a Turnkey production attestation document for testing
func getTurnkeyProductionAttestation() string {
	return turnkeyFixtures.Production
}

// getTurnkeyPreProductionAttestation returns a Turnkey pre-production attestation document for testing
func getTurnkeyPreProductionAttestation() string {
	return turnkeyFixtures.PreProduction
}

// getAWSExampleAttestation returns a generic AWS Nitro attestation example for testing
func getAWSExampleAttestation() string { //nolint:unused // Reserved for future AWS Nitro example fixtures
	return awsFixtures.Example
}

// Commands to obtain attestation documents:
//
// ## For Generic AWS Nitro Enclaves:
// To obtain your own attestation documents from AWS Nitro Enclaves:
// 1. Create an enclave with your application
// 2. From within the enclave, call the Nitro Secure Module to get an attestation
// 3. The attestation document will contain your PCR values and optional user data
//
// Example from within an enclave (Python):
// ```python
// import subprocess
// import base64
//
// # Get attestation with optional user data and nonce
// result = subprocess.run([
//     '/usr/bin/nitro-cli', 'describe-eif',
//     '--eif-path', '/app/enclave.eif'
// ], capture_output=True, text=True)
//
// # Parse and encode the attestation document
// attestation = base64.b64encode(attestation_bytes).decode('utf-8')
// ```
//
// For more information, see:
// - https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-concepts.html
// - https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
//
// ## For Turnkey-specific attestations:
// The Turnkey attestation documents embedded in this library were obtained using the Turnkey CLI:
//
// ### Production Attestation:
// ```bash
// turnkey request \
//   --host api.turnkey.com \
//   --path /public/v1/query/get_attestation \
//   --body '{"organizationId": "<yourOrgId>","enclaveType": "signer"}' \
//   --organization=<yourOrgId> | jq -r '.attestationDocument' > turnkey-attestation.base64
// ```
//
// ### Pre-production Attestation:
// ```bash
// turnkey request \
//   --host api.preprod.turnkey.engineering \
//   --path /public/v1/query/get_attestation \
//   --body '{"organizationId": "<yourOrgId>","enclaveType": "signer"}' \
//   --organization=<yourOrgId> | jq -r '.attestationDocument' > turnkey-preprod-attestation.base64
// ```
//
// Replace <yourOrgId> with your actual Turnkey organization ID.
// Requires the Turnkey CLI and appropriate permissions.
//
// ## Key differences between Turnkey fixtures:
//
// Production fixture (`turnkey-prod.base64`):
// - PCR[3]: b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b
// - UserData: 8a5510ca253818acec5fb27b3ca114b4a260fb84f881838eb124aae9c968ad74 (32 bytes)
// - PublicKey: 130 bytes (ECDSA)
//
// Pre-production fixture (`turnkey-preprod.base64`):
// - PCR[3]: 864e9095a9947ab14698122370c13baf23183f4e9911953cf5b909a49db00f43f446707314674d9309974f3cc4b24728
// - UserData: 37ef96370730962341148a03754955137884516def11439b5d841809f6f9caac (32 bytes)
// - PublicKey: 130 bytes (ECDSA)
//
// Note: These attestation documents contain expired certificates and should only be used for testing
// with SkipTimestampCheck: true
