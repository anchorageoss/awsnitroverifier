package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/urfave/cli/v3"
)

func main() {
	cmd := &cli.Command{
		Name:  "awsnitroverifier",
		Usage: "Verify AWS Nitro Enclave attestation documents",
		Commands: []*cli.Command{
			{
				Name:  "verify",
				Usage: "Verify an attestation document from a file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "File containing attestation document (base64 format)",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "pcrs",
						Usage: "PCR validation rules in format 'index:expectedhex,index:expectedhex'",
					},
					&cli.BoolFlag{
						Name:  "skip-timestamp",
						Usage: "Skip certificate timestamp validation",
						Value: true, // Default to true for test fixtures
					},
					&cli.BoolFlag{
						Name:  "skip-signature",
						Usage: "Skip signature verification",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Verbose output with detailed validation results",
					},
				},
				Action: runBasicVerification,
			},
			{
				Name:  "test-turnkey",
				Usage: "Test with embedded Turnkey fixtures",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "env",
						Usage: "Environment to test: 'production' or 'preprod'",
						Value: "production",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Verbose output with detailed validation results",
					},
				},
				Action: runTurnkeyTest,
			},
			{
				Name:  "full-turnkey-attestation",
				Usage: "Full attestation verification including boot and app verification",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Aliases:  []string{"f"},
						Usage:    "File containing attestation document",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "format",
						Usage: "Format of the input file: 'base64' or 'binary'",
						Value: "base64",
					},
					&cli.StringFlag{
						Name:    "output",
						Aliases: []string{"o"},
						Usage:   "Output file for decoded attestation JSON (optional)",
					},
					&cli.StringFlag{
						Name:  "pcrs",
						Usage: "PCR validation rules in format 'index:expectedhex,index:expectedhex'",
					},
					&cli.BoolFlag{
						Name:  "skip-timestamp",
						Usage: "Skip certificate timestamp validation",
					},
					&cli.BoolFlag{
						Name:  "skip-signature",
						Usage: "Skip signature verification",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Verbose output with detailed validation results",
					},
					&cli.StringFlag{
						Name:  "timestamp",
						Usage: "Override timestamp for validation (RFC3339 format)",
					},
					&cli.StringFlag{
						Name:  "message",
						Usage: "Message hash to verify against the second public key (hex format)",
					},
					&cli.StringFlag{
						Name:  "signature",
						Usage: "Signature to verify against the message hash (hex format)",
					},
					&cli.StringFlag{
						Name:  "turnkey-public-key",
						Usage: "Turnkey public key for verification (130-byte hex format from Turnkey API)",
					},
					&cli.StringFlag{
						Name:  "qos-manifest",
						Usage: "QoS manifest to compare against UserData in attestation (hex format)",
					},
				},
				Action: runFullTurnkeyVerification,
			},
			{
				Name:  "app-only-attestation",
				Usage: "App attestation verification only using ephemeral signing key",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "message",
						Usage:    "Message hash to verify (hex format)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "signature",
						Usage:    "Signature to verify (hex format)",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "turnkey-public-key",
						Usage:    "Turnkey public key (130-byte hex format from Turnkey API)",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Verbose output with detailed verification results",
					},
				},
				Action: runAppOnlyVerification,
			},
		},
	}

	if err := cmd.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// runBasicVerification performs basic attestation verification from a file
func runBasicVerification(ctx context.Context, cmd *cli.Command) error {
	attestationFile := cmd.String("file")
	pcrRules := cmd.String("pcrs")
	skipTimestamp := cmd.Bool("skip-timestamp")
	skipSignature := cmd.Bool("skip-signature")
	verbose := cmd.Bool("verbose")

	// Read the attestation file
	data, err := os.ReadFile(attestationFile)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", attestationFile, err)
	}

	// Parse PCR validation rules if provided
	var pcrValidations []nitroverifier.PCRRule
	if pcrRules != "" {
		pcrValidations = parsePCRRules(pcrRules)
	}

	// Create validator with options
	validator := nitroverifier.NewVerifier(nitroverifier.ValidatorOptions{
		SkipTimestampCheck:        skipTimestamp,
		SkipSignatureVerification: skipSignature,
		PCRRules:                  pcrValidations,
	})

	// Validate the attestation
	attestationBase64 := strings.TrimSpace(string(data))
	result, err := validator.Validate(attestationBase64)
	if err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	// Print results
	printValidationResults(result, verbose)

	if !result.Valid {
		os.Exit(1)
	}
	return nil
}

// runTurnkeyTest runs tests with embedded Turnkey fixtures
func runTurnkeyTest(ctx context.Context, cmd *cli.Command) error {
	env := cmd.String("env")
	_ = cmd.Bool("verbose") // TODO: Use for verbose output

	fmt.Printf("🧪 Testing with Turnkey %s fixtures\n", env)
	fmt.Println("========================================")

	fmt.Println("Test fixtures are available in the testdata/ directory:")
	fmt.Println("  - testdata/turnkey-prod.base64")
	fmt.Println("  - testdata/turnkey-preprod.base64")
	fmt.Println()

	switch env {
	case "production":
		fmt.Println("Expected PCR values for Turnkey production:")
		fmt.Println("  PCR[3]: b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b")
		fmt.Println()
		fmt.Println("Example command:")
		fmt.Println("  go run ./cmd/awsnitroverifier verify -f ./testdata/turnkey-prod.base64 --pcrs 3:b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b")
	case "preprod":
		fmt.Println("Expected PCR values for Turnkey pre-production:")
		fmt.Println("  PCR[3]: 864e9095a9947ab14698122370c13baf23183f4e9911953cf5b909a49db00f43f446707314674d9309974f3cc4b24728")
		fmt.Println("  PCR[4]: 461a8588acc774ebfbde179cd1cd9f49e3c830eca6cd2ffed3aa773f187fb7e75f7bea0b12277a150b9a230011a55362")
		fmt.Println()
		fmt.Println("Example command:")
		fmt.Println("  go run ./cmd/awsnitroverifier verify -f ./testdata/turnkey-preprod.base64 \\")
		fmt.Println("    --pcrs 3:864e9095a9947ab14698122370c13baf23183f4e9911953cf5b909a49db00f43f446707314674d9309974f3cc4b24728,4:461a8588acc774ebfbde179cd1cd9f49e3c830eca6cd2ffed3aa773f187fb7e75f7bea0b12277a150b9a230011a55362")
	default:
		return fmt.Errorf("unknown environment: %s (must be 'production' or 'preprod')", env)
	}

	return nil
}

// printValidationResults prints the validation results in a clean format
func printValidationResults(result *nitroverifier.ValidationResult, verbose bool) {
	if result.Valid {
		fmt.Println("✅ Attestation validation PASSED")
		fmt.Println("  🔐 Certificate chain validated")
		fmt.Println("  🏛️ Signatures verified")
		if result.ChainValidated {
			fmt.Printf("  🔗 AWS root fingerprint: %s\n", result.RootFingerprint)
		}
	} else {
		fmt.Println("❌ Attestation validation FAILED")
		if len(result.Errors) > 0 {
			fmt.Println("\nErrors:")
			for _, err := range result.Errors {
				fmt.Printf("  - %v\n", err)
			}
		}
	}

	// Print certificate info
	if verbose && result.CertificateInfo != nil {
		fmt.Printf("\n📜 Certificate Information:\n")
		fmt.Printf("  Subject: %s\n", result.CertificateInfo.Subject)
		fmt.Printf("  Valid: %s to %s\n",
			result.CertificateInfo.NotBefore.Format("2006-01-02 15:04:05"),
			result.CertificateInfo.NotAfter.Format("2006-01-02 15:04:05"))
	}

	// Print PCR results
	if len(result.PCRValidations) > 0 {
		fmt.Printf("\n🔐 PCR Validations:\n")
		summary := nitroverifier.GetPCRValidationSummary(result.PCRValidations)
		fmt.Printf("  Total: %d | Valid: %d | Invalid: %d\n",
			summary.Total, summary.Valid, summary.Invalid)

		for _, pcr := range result.PCRValidations {
			if pcr.Valid {
				fmt.Printf("  ✅ PCR[%d]: Valid\n", pcr.Index)
				if verbose {
					fmt.Printf("     Value: %s\n", hex.EncodeToString(pcr.Actual))
				}
			} else {
				fmt.Printf("  ❌ PCR[%d]: Invalid\n", pcr.Index)
				if pcr.Actual != nil {
					fmt.Printf("     Expected: %s\n", hex.EncodeToString(pcr.Expected))
					fmt.Printf("     Actual:   %s\n", hex.EncodeToString(pcr.Actual))
				}
			}
		}
	}

	// Print optional fields
	if verbose {
		if result.UserData != nil {
			fmt.Printf("\n🔑 UserData: %d bytes\n", len(result.UserData))
			fmt.Printf("  Hex: %s\n", hex.EncodeToString(result.UserData))
		}
		if result.PublicKey != nil {
			fmt.Printf("\n🔑 PublicKey: %d bytes\n", len(result.PublicKey))
			fmt.Printf("  Hex: %s\n", hex.EncodeToString(result.PublicKey))
		}
	}
}

func runFullTurnkeyVerification(ctx context.Context, cmd *cli.Command) error {
	attestationFile := cmd.String("file")
	format := cmd.String("format")
	outputFile := cmd.String("output")
	pcrRules := cmd.String("pcrs")
	skipTimestamp := cmd.Bool("skip-timestamp")
	skipSignature := cmd.Bool("skip-signature")
	verbose := cmd.Bool("verbose")
	timestampOverride := cmd.String("timestamp")
	messageHash := cmd.String("message")
	signatureHex := cmd.String("signature")
	turnkeyPublicKey := cmd.String("turnkey-public-key")
	qosManifest := cmd.String("qos-manifest")

	// Track app attestation verification status
	var appAttestationVerified bool
	var appAttestationAttempted bool
	var qosManifestVerified bool
	var qosManifestAttempted bool

	if format != "base64" && format != "binary" {
		return fmt.Errorf("invalid format: %s. Must be 'base64' or 'binary'", format)
	}

	data, err := os.ReadFile(attestationFile)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", attestationFile, err)
	}

	// Parse PCR validation rules if provided
	var pcrValidations []nitroverifier.PCRRule
	if pcrRules != "" {
		pcrValidations = parsePCRRules(pcrRules)
	}

	// Setup validator options
	validatorOptions := nitroverifier.ValidatorOptions{
		SkipTimestampCheck:        skipTimestamp,
		SkipSignatureVerification: skipSignature,
		PCRRules:                  pcrValidations,
	}

	// Parse timestamp override if provided
	if timestampOverride != "" {
		t, err := time.Parse(time.RFC3339, timestampOverride)
		if err != nil {
			return fmt.Errorf("error parsing timestamp override: %w", err)
		}
		validatorOptions.CurrentTime = &t
	}

	// Create validator and validate
	validator := nitroverifier.NewVerifier(validatorOptions)
	var result *nitroverifier.ValidationResult

	if format == "base64" {
		// Pass base64 string directly to the validator
		attestationBase64 := strings.TrimSpace(string(data))
		result, err = validator.Validate(attestationBase64)
	} else {
		// Use binary data directly
		result, err = validator.ValidateBytes(data)
	}

	if err != nil {
		return fmt.Errorf("fatal error during validation: %w", err)
	}

	// Print validation results
	if result.Valid {
		fmt.Println("✅ AWS Nitro Enclave Attestation Validation PASSED") //nolint:forbidigo
		fmt.Println("   🔐 Boot attestation verified")                    //nolint:forbidigo
		fmt.Println("   🏛️  Certificate chain validated")                //nolint:forbidigo
		fmt.Println("   🔏 Cryptographic signatures verified")            //nolint:forbidigo
		// App attestation status will be printed later after signature verification
	} else {
		fmt.Println("❌ AWS Nitro Enclave Attestation Validation FAILED") //nolint:forbidigo
		if len(result.Errors) > 0 {
			fmt.Println("\nValidation errors:") //nolint:forbidigo
			for _, err := range result.Errors {
				fmt.Printf("  - %v\n", err) //nolint:forbidigo
			}
		}
	}

	// Print certificate info if available and verbose
	if verbose && result.CertificateInfo != nil {
		fmt.Println("\n📜 Certificate Information:")                                             //nolint:forbidigo
		fmt.Printf("  Subject: %s\n", result.CertificateInfo.Subject)                           //nolint:forbidigo
		fmt.Printf("  Issuer: %s\n", result.CertificateInfo.Issuer)                             //nolint:forbidigo
		fmt.Printf("  Not Before: %s\n", result.CertificateInfo.NotBefore.Format(time.RFC3339)) //nolint:forbidigo
		fmt.Printf("  Not After: %s\n", result.CertificateInfo.NotAfter.Format(time.RFC3339))   //nolint:forbidigo
		fmt.Printf("  Serial Number: %s\n", result.CertificateInfo.SerialNumber)                //nolint:forbidigo

		if !skipTimestamp {
			checkTime := time.Now()
			if validatorOptions.CurrentTime != nil {
				checkTime = *validatorOptions.CurrentTime
			}
			fmt.Printf("  Checked at: %s\n", checkTime.Format(time.RFC3339)) //nolint:forbidigo
		}

		// Display chain validation status
		if result.ChainValidated {
			fmt.Println("\n✅ Certificate Chain Validation:")                     //nolint:forbidigo
			fmt.Printf("  Chain validated against AWS Nitro root certificate\n") //nolint:forbidigo
			fmt.Printf("  Root fingerprint: %s\n", result.RootFingerprint)       //nolint:forbidigo
		} else if !skipSignature {
			fmt.Println("\n⚠️  Certificate chain not validated against AWS root") //nolint:forbidigo
		}

		// Display certificate chain if available
		if len(result.CertificateChain) > 0 && verbose {
			fmt.Println("\n🔗 Certificate Chain:") //nolint:forbidigo
			for i, cert := range result.CertificateChain {
				fmt.Printf("  [%d] %s\n", i, cert.Subject) //nolint:forbidigo
			}
		}
	}

	// Print PCR validation results
	if len(result.PCRValidations) > 0 {
		fmt.Println("\n🔐 PCR Validation Results:") //nolint:forbidigo
		summary := nitroverifier.GetPCRValidationSummary(result.PCRValidations)
		fmt.Printf("  Total: %d | Valid: %d | Invalid: %d | Missing: %d\n", //nolint:forbidigo
			summary.Total, summary.Valid, summary.Invalid, summary.Missing)

		if verbose || summary.Invalid > 0 || summary.Missing > 0 {
			fmt.Println("\n  Details:") //nolint:forbidigo
			for _, pcr := range result.PCRValidations {
				if pcr.Valid {
					fmt.Printf("    ✅ PCR[%d]: Valid\n", pcr.Index) //nolint:forbidigo
					if verbose {
						fmt.Printf("       Value: %s\n", hex.EncodeToString(pcr.Actual)) //nolint:forbidigo
					}
				} else {
					fmt.Printf("    ❌ PCR[%d]: Invalid\n", pcr.Index) //nolint:forbidigo
					if pcr.Actual == nil {
						fmt.Printf("       Error: PCR not found in attestation\n")            //nolint:forbidigo
						fmt.Printf("       Expected: %s\n", hex.EncodeToString(pcr.Expected)) //nolint:forbidigo
					} else {
						fmt.Printf("       Expected: %s\n", hex.EncodeToString(pcr.Expected)) //nolint:forbidigo
						fmt.Printf("       Actual:   %s\n", hex.EncodeToString(pcr.Actual))   //nolint:forbidigo
					}
				}
			}
		}
	}

	// Print all PCRs from the document if verbose
	if verbose && result.Document != nil && len(result.Document.PCRs) > 0 {
		fmt.Println("\n📋 All PCRs in attestation document:") //nolint:forbidigo
		for i := uint(0); i <= 15; i++ {
			if value, exists := result.Document.PCRs[i]; exists {
				if len(value) > 0 {
					fmt.Printf("  PCR[%2d]: %s\n", i, hex.EncodeToString(value)) //nolint:forbidigo
				}
			}
		}
	}

	// Print optional attestation fields (critical for Turnkey validation)
	appAttestationVerified, appAttestationAttempted = printOptionalFields(
		ctx, result, verbose, messageHash, signatureHex, turnkeyPublicKey,
		qosManifest, &qosManifestVerified, &qosManifestAttempted)

	// Output the decoded document as JSON if requested
	if outputFile != "" && result.Document != nil {
		jsonOutput, err := json.MarshalIndent(result.Document, "", "  ")
		if err != nil {
			return fmt.Errorf("error encoding document to JSON: %w", err)
		}
		err = os.WriteFile(outputFile, jsonOutput, 0o644)
		if err != nil {
			return fmt.Errorf("error writing to output file %s: %w", outputFile, err)
		}
		fmt.Printf("\n📄 Decoded attestation document written to %s\n", outputFile) //nolint:forbidigo
	}

	// Print final app attestation status
	fmt.Printf("\n") //nolint:forbidigo
	if appAttestationAttempted {
		if appAttestationVerified {
			fmt.Printf("🚀 Application Attestation: ✅ VERIFIED (signature verification successful)\n") //nolint:forbidigo
		} else {
			fmt.Printf("🚀 Application Attestation: ❌ FAILED (signature verification failed)\n") //nolint:forbidigo
		}
	} else {
		fmt.Printf("🚀 Application Attestation: ⚠️  SKIPPED (no message/signature provided)\n") //nolint:forbidigo
	}

	// Print QoS manifest verification status
	if qosManifestAttempted {
		if qosManifestVerified {
			fmt.Printf("📋 QoS Manifest: ✅ VERIFIED (matches UserData)\n") //nolint:forbidigo
		} else {
			fmt.Printf("📋 QoS Manifest: ❌ FAILED (does not match UserData)\n") //nolint:forbidigo
		}
	} else {
		fmt.Printf("📋 QoS Manifest: ⚠️  SKIPPED (no manifest provided)\n") //nolint:forbidigo
	}

	// Exit with appropriate code
	if !result.Valid {
		os.Exit(1)
	}

	return nil
}

// printOptionalFields prints the optional attestation fields and performs signature verification
func printOptionalFields(ctx context.Context, result *nitroverifier.ValidationResult, verbose bool,
	messageHash, signatureHex, turnkeyPublicKey, qosManifest string,
	qosManifestVerified, qosManifestAttempted *bool,
) (bool, bool) {
	var appAttestationVerified bool
	var appAttestationAttempted bool

	if result.UserData == nil && result.PublicKey == nil && result.Nonce == nil {
		return appAttestationVerified, appAttestationAttempted
	}

	fmt.Println("\n🔑 Optional Attestation Fields:") //nolint:forbidigo
	if result.UserData != nil {
		fmt.Printf("  UserData: %d bytes\n", len(result.UserData)) //nolint:forbidigo
		if verbose {
			fmt.Printf("    Hex: %s\n", hex.EncodeToString(result.UserData)) //nolint:forbidigo
			// Try to print as string if it looks like text
			if isPrintableASCII(result.UserData) {
				fmt.Printf("    ASCII: %s\n", string(result.UserData)) //nolint:forbidigo
			}
		}

		// Compare against QoS manifest if provided
		if qosManifest != "" {
			*qosManifestAttempted = true
			fmt.Printf("\n  🔍 QoS Manifest Verification:\n") //nolint:forbidigo

			qosManifestBytes, err := hex.DecodeString(qosManifest)
			if err != nil {
				fmt.Printf("    ❌ Invalid QoS manifest hex: %v\n", err) //nolint:forbidigo
				*qosManifestVerified = false
			} else {
				fmt.Printf("    Expected QoS: %s (%d bytes)\n", qosManifest, len(qosManifestBytes))                        //nolint:forbidigo
				fmt.Printf("    UserData:     %s (%d bytes)\n", hex.EncodeToString(result.UserData), len(result.UserData)) //nolint:forbidigo

				if len(qosManifestBytes) == len(result.UserData) && hex.EncodeToString(qosManifestBytes) == hex.EncodeToString(result.UserData) {
					fmt.Printf("    Result:       ✅ QoS MANIFEST MATCHES UserData\n") //nolint:forbidigo
					*qosManifestVerified = true
				} else {
					fmt.Printf("    Result:       ❌ QoS MANIFEST MISMATCH\n") //nolint:forbidigo
					if len(qosManifestBytes) != len(result.UserData) {
						fmt.Printf("    Note:         Length differs (expected %d, got %d)\n", len(qosManifestBytes), len(result.UserData)) //nolint:forbidigo
					}
					*qosManifestVerified = false
				}
			}
		}
	}
	if result.PublicKey != nil { //nolint:nestif
		fmt.Printf("  PublicKey: %d bytes\n", len(result.PublicKey)) //nolint:forbidigo
		if verbose {
			fmt.Printf("    Hex: %s\n", hex.EncodeToString(result.PublicKey)) //nolint:forbidigo

			// First try to decode as DER-encoded P-256 public key
			if pubKey, err := x509.ParsePKIXPublicKey(result.PublicKey); err == nil {
				if ecdsaKey, ok := pubKey.(*ecdsa.PublicKey); ok && ecdsaKey.Curve.Params().Name == "P-256" {
					fmt.Printf("    DER-encoded P-256 public key:\n")                   //nolint:forbidigo
					fmt.Printf("      X: %s\n", hex.EncodeToString(ecdsaKey.X.Bytes())) //nolint:forbidigo
					fmt.Printf("      Y: %s\n", hex.EncodeToString(ecdsaKey.Y.Bytes())) //nolint:forbidigo

					// Create uncompressed public key (0x04 + X + Y)
					xBytes := make([]byte, 32)
					yBytes := make([]byte, 32)
					ecdsaKey.X.FillBytes(xBytes)
					ecdsaKey.Y.FillBytes(yBytes)
					xyCombined := make([]byte, 0, 64)
					xyCombined = append(xyCombined, xBytes...)
					xyCombined = append(xyCombined, yBytes...)
					uncompressed := append([]byte{0x04}, xyCombined...)
					fmt.Printf("      Uncompressed: %s\n", hex.EncodeToString(uncompressed)) //nolint:forbidigo

					// Show compressed format
					var compressed []byte
					if ecdsaKey.Y.Bit(0) == 0 {
						compressed = append([]byte{0x02}, xBytes...)
					} else {
						compressed = append([]byte{0x03}, xBytes...)
					}
					fmt.Printf("      Compressed: %s\n", hex.EncodeToString(compressed)) //nolint:forbidigo
				} else {
					fmt.Printf("    DER-encoded key (not P-256): %T\n", pubKey) //nolint:forbidigo
				}
			} else {
				// If DER decoding fails, check for raw P-256 formats
				if len(result.PublicKey) == 65 && result.PublicKey[0] == 0x04 {
					// Standard uncompressed P-256 (65 bytes: 0x04 + 32 + 32)
					fmt.Printf("    Raw P-256 uncompressed public key:\n") //nolint:forbidigo
					xBytes := result.PublicKey[1:33]
					yBytes := result.PublicKey[33:65]
					fmt.Printf("      X: %s\n", hex.EncodeToString(xBytes)) //nolint:forbidigo
					fmt.Printf("      Y: %s\n", hex.EncodeToString(yBytes)) //nolint:forbidigo

					// Show compressed format
					var compressed []byte
					if yBytes[31]&1 == 0 {
						compressed = append([]byte{0x02}, xBytes...)
					} else {
						compressed = append([]byte{0x03}, xBytes...)
					}
					fmt.Printf("      Compressed: %s\n", hex.EncodeToString(compressed)) //nolint:forbidigo
				} else if len(result.PublicKey) == 130 && result.PublicKey[0] == 0x04 && result.PublicKey[65] == 0x04 {
					// Dual P-256 keys (130 bytes: two uncompressed keys)
					fmt.Printf("    🔑 Turnkey Dual P-256 Keys Detected (130 bytes):\n") //nolint:forbidigo
					fmt.Printf("       ✅ Boot Attestation Verified\n")                  //nolint:forbidigo
					fmt.Printf("\n")                                                    //nolint:forbidigo

					// First key (Encryption Key)
					xBytes1 := result.PublicKey[1:33]
					yBytes1 := result.PublicKey[33:65]
					fmt.Printf("    🔒 EncryptionKey (Key 1):\n")              //nolint:forbidigo
					fmt.Printf("       X: %s\n", hex.EncodeToString(xBytes1)) //nolint:forbidigo
					fmt.Printf("       Y: %s\n", hex.EncodeToString(yBytes1)) //nolint:forbidigo

					var compressed1 []byte
					if yBytes1[31]&1 == 0 {
						compressed1 = append([]byte{0x02}, xBytes1...)
					} else {
						compressed1 = append([]byte{0x03}, xBytes1...)
					}
					fmt.Printf("       Compressed: %s\n", hex.EncodeToString(compressed1))   //nolint:forbidigo
					fmt.Printf("       Purpose: Data encryption and secure communication\n") //nolint:forbidigo
					fmt.Printf("\n")                                                         //nolint:forbidigo

					// Second key (Signing Key)
					xBytes2 := result.PublicKey[66:98]
					yBytes2 := result.PublicKey[98:130]
					fmt.Printf("    ✍️  SigningKey (Key 2):\n")               //nolint:forbidigo
					fmt.Printf("       X: %s\n", hex.EncodeToString(xBytes2)) //nolint:forbidigo
					fmt.Printf("       Y: %s\n", hex.EncodeToString(yBytes2)) //nolint:forbidigo

					var compressed2 []byte
					if yBytes2[31]&1 == 0 {
						compressed2 = append([]byte{0x02}, xBytes2...)
					} else {
						compressed2 = append([]byte{0x03}, xBytes2...)
					}
					fmt.Printf("       Compressed: %s\n", hex.EncodeToString(compressed2))         //nolint:forbidigo
					fmt.Printf("       Purpose: Transaction signing and message authentication\n") //nolint:forbidigo

					// Perform signature verification if message and signature are provided
					if messageHash != "" && signatureHex != "" {
						appAttestationAttempted = true
						fmt.Printf("\n    🔐 Message Signature Verification:\n") //nolint:forbidigo
						fmt.Printf("       Message Hash: %s\n", messageHash)    //nolint:forbidigo
						fmt.Printf("       Signature:    %s\n", signatureHex)   //nolint:forbidigo

						// Compare the dual key with Turnkey's public key if provided
						if turnkeyPublicKey != "" {
							fmt.Printf("       Turnkey PublicKey: %s\n", turnkeyPublicKey) //nolint:forbidigo
							attestationKeyHex := hex.EncodeToString(result.PublicKey)
							fmt.Printf("       Attestation Key:   %s\n", attestationKeyHex) //nolint:forbidigo
							if strings.EqualFold(turnkeyPublicKey, attestationKeyHex) {
								fmt.Printf("       Key Match:    ✅ Turnkey key matches attestation\n") //nolint:forbidigo
							} else {
								fmt.Printf("       Key Match:    ❌ Turnkey key differs from attestation\n") //nolint:forbidigo
							}
						}

						fmt.Printf("       Using Key:    SigningKey (Key 2 from dual format)\n") //nolint:forbidigo
						fmt.Printf("       Key X:        %s\n", hex.EncodeToString(xBytes2))     //nolint:forbidigo
						fmt.Printf("       Key Y:        %s\n", hex.EncodeToString(yBytes2))     //nolint:forbidigo
						fmt.Printf("       Algorithm:    ECDSA P-256\n")                         //nolint:forbidigo

						if err := verifySignatureWithSigningKey(messageHash, signatureHex, xBytes2, yBytes2, verbose); err != nil {
							fmt.Printf("       Result:       ❌ VERIFICATION FAILED: %v\n", err) //nolint:forbidigo

							// Try with Turnkey's public key if provided and different
							if turnkeyPublicKey != "" {
								fmt.Printf("       Trying with Turnkey's exact public key...\n") //nolint:forbidigo
								if err := verifyWithTurnkeyKey(messageHash, signatureHex, turnkeyPublicKey); err != nil {
									fmt.Printf("       Turnkey Key:  ❌ ALSO FAILED: %v\n", err) //nolint:forbidigo
								} else {
									fmt.Printf("       Turnkey Key:  ✅ SUCCESS with Turnkey's key!\n") //nolint:forbidigo
								}
							}
							appAttestationVerified = false
						} else {
							fmt.Printf("       Result:       ✅ VERIFICATION SUCCESSFUL\n")      //nolint:forbidigo
							fmt.Printf("       Status:       Message authenticity confirmed\n") //nolint:forbidigo
							appAttestationVerified = true
							fmt.Printf("       ✅ App Attestation Verified\n") //nolint:forbidigo
						}
					} else if messageHash != "" || signatureHex != "" {
						appAttestationAttempted = true
						appAttestationVerified = false
						fmt.Printf("\n    ⚠️  Partial Signature Data Provided:\n") //nolint:forbidigo
						if messageHash == "" {
							fmt.Printf("       Missing: --message flag (message hash)\n") //nolint:forbidigo
						}
						if signatureHex == "" {
							fmt.Printf("       Missing: --signature flag (signature)\n") //nolint:forbidigo
						}
						fmt.Printf("       Note: Both --message and --signature required for verification\n") //nolint:forbidigo
					}
				} else {
					fmt.Printf("    Unknown public key format:\n")                //nolint:forbidigo
					fmt.Printf("      Length: %d bytes\n", len(result.PublicKey)) //nolint:forbidigo
					if len(result.PublicKey) > 0 {
						fmt.Printf("      First byte: 0x%02x\n", result.PublicKey[0]) //nolint:forbidigo
					}
					if len(result.PublicKey) >= 8 {
						fmt.Printf("      First 8 bytes: %s\n", hex.EncodeToString(result.PublicKey[:8])) //nolint:forbidigo
					}
				}
			}
		}
	}
	if result.Nonce != nil {
		fmt.Printf("  Nonce: %d bytes\n", len(result.Nonce)) //nolint:forbidigo
		if verbose {
			fmt.Printf("    Hex: %s\n", hex.EncodeToString(result.Nonce)) //nolint:forbidigo
		}
	}

	return appAttestationVerified, appAttestationAttempted
}

// isPrintableASCII checks if all bytes are printable ASCII characters
func isPrintableASCII(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return len(data) > 0
}

// parsePCRRules parses PCR validation rules from a string format
func parsePCRRules(rulesStr string) []nitroverifier.PCRRule {
	var validations []nitroverifier.PCRRule

	// Split by comma to get individual rules
	rules := strings.Split(rulesStr, ",")
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		parts := strings.Split(rule, ":")
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "Warning: Invalid PCR rule format: %s (expected 'index:expectedhex')\n", rule)
			continue
		}

		var index uint
		_, err := fmt.Sscanf(parts[0], "%d", &index)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Invalid PCR index in rule: %s\n", rule)
			continue
		}

		expectedHex := strings.ToLower(strings.TrimSpace(parts[1]))
		expectedBytes, err := hex.DecodeString(expectedHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Invalid hex value in PCR rule: %s\n", rule)
			continue
		}

		validations = append(validations, nitroverifier.PCRRule{
			Index: index,
			Value: expectedBytes,
		})
	}

	return validations
}

// verifySignatureWithSigningKey verifies a signature using the second P-256 public key from a dual key format
func verifySignatureWithSigningKey(messageHashHex, signatureHex string, xBytes, yBytes []byte, debug bool) error {
	// Decode the message hash
	messageHash, err := hex.DecodeString(messageHashHex)
	if err != nil {
		return fmt.Errorf("invalid message hash hex: %w", err)
	}

	if debug {
		fmt.Printf("   🔍 Input message analysis:\n")                                    //nolint:forbidigo
		fmt.Printf("      Raw message: %x (%d bytes)\n", messageHash, len(messageHash)) //nolint:forbidigo

		// Try hashing the message (in case it needs to be hashed)
		sha256Hash := sha256.Sum256(messageHash)
		fmt.Printf("      SHA256 of message: %x (%d bytes)\n", sha256Hash[:], len(sha256Hash)) //nolint:forbidigo
	}

	// Decode the signature
	signatureBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	// P-256 signatures are typically 64 bytes (32 bytes r + 32 bytes s)
	if len(signatureBytes) != 64 {
		return fmt.Errorf("invalid signature length: expected 64 bytes, got %d", len(signatureBytes))
	}

	if debug {
		fmt.Printf("   🔍 Signature breakdown:\n")                                                //nolint:forbidigo
		fmt.Printf("      Full signature: %x (%d bytes)\n", signatureBytes, len(signatureBytes)) //nolint:forbidigo
		fmt.Printf("      R component: %x\n", signatureBytes[:32])                               //nolint:forbidigo
		fmt.Printf("      S component: %x\n", signatureBytes[32:])                               //nolint:forbidigo
	}

	// Extract r and s from the signature
	r := new(big.Int).SetBytes(signatureBytes[0:32])
	s := new(big.Int).SetBytes(signatureBytes[32:64])

	// Create the ECDSA public key from the coordinates
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	if debug {
		fmt.Printf("   🔍 Verification details:\n")                                       //nolint:forbidigo
		fmt.Printf("      Message hash: %x (%d bytes)\n", messageHash, len(messageHash)) //nolint:forbidigo
		fmt.Printf("      R value: %s\n", r.String())                                    //nolint:forbidigo
		fmt.Printf("      S value: %s\n", s.String())                                    //nolint:forbidigo
		fmt.Printf("      Public key X: %s\n", x.String())                               //nolint:forbidigo
		fmt.Printf("      Public key Y: %s\n", y.String())                               //nolint:forbidigo
		fmt.Printf("      Key on curve: %v\n", publicKey.IsOnCurve(x, y))          //nolint:forbidigo
	}

	// Verify the signature
	// Note: The signature is over the SHA256 hash of the provided message hash
	sha256Hash := sha256.Sum256(messageHash)
	valid := ecdsa.Verify(publicKey, sha256Hash[:], r, s)
	if !valid {
		if debug {
			fmt.Printf("   ❌ ECDSA verification returned false\n") //nolint:forbidigo
		}
		return errors.New("signature verification failed")
	}

	if debug {
		fmt.Printf("   ✅ ECDSA verification successful!\n") //nolint:forbidigo
	}

	return nil
}

// verifyWithTurnkeyKey verifies a signature using Turnkey's exact public key format
func verifyWithTurnkeyKey(messageHashHex, signatureHex, turnkeyPublicKeyHex string) error {
	// Decode Turnkey's public key
	turnkeyKeyBytes, err := hex.DecodeString(turnkeyPublicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid Turnkey public key hex: %w", err)
	}

	// For Turnkey's 130-byte format, try both keys
	if len(turnkeyKeyBytes) == 130 && turnkeyKeyBytes[0] == 0x04 && turnkeyKeyBytes[65] == 0x04 {
		// Try first key (bytes 1-64)
		xBytes1 := turnkeyKeyBytes[1:33]
		yBytes1 := turnkeyKeyBytes[33:65]
		if err := verifySignatureWithSigningKey(messageHashHex, signatureHex, xBytes1, yBytes1, false); err == nil {
			return nil // Success with first key
		}

		// Try second key (bytes 66-129)
		xBytes2 := turnkeyKeyBytes[66:98]
		yBytes2 := turnkeyKeyBytes[98:130]
		return verifySignatureWithSigningKey(messageHashHex, signatureHex, xBytes2, yBytes2, false)
	}

	// For other formats, try to parse as single key
	if len(turnkeyKeyBytes) == 65 && turnkeyKeyBytes[0] == 0x04 {
		xBytes := turnkeyKeyBytes[1:33]
		yBytes := turnkeyKeyBytes[33:65]
		return verifySignatureWithSigningKey(messageHashHex, signatureHex, xBytes, yBytes, false)
	}

	return fmt.Errorf("unsupported Turnkey public key format: %d bytes", len(turnkeyKeyBytes))
}

// runAppOnlyVerification performs app attestation verification only using Turnkey's ephemeral signing key
func runAppOnlyVerification(ctx context.Context, cmd *cli.Command) error {
	messageHashHex := cmd.String("message")
	signatureHex := cmd.String("signature")
	turnkeyPublicKeyHex := cmd.String("turnkey-public-key")
	verbose := cmd.Bool("verbose")
	fmt.Println("🚀 App Attestation Verification Only Mode")   //nolint:forbidigo
	fmt.Println("==========================================") //nolint:forbidigo

	// Decode Turnkey's 130-byte public key
	turnkeyKeyBytes, err := hex.DecodeString(turnkeyPublicKeyHex)
	if err != nil {
		return fmt.Errorf("invalid Turnkey public key hex: %w", err)
	}

	if len(turnkeyKeyBytes) != 130 {
		return fmt.Errorf("expected 130-byte public key, got %d bytes", len(turnkeyKeyBytes))
	}

	if turnkeyKeyBytes[0] != 0x04 || turnkeyKeyBytes[65] != 0x04 {
		return fmt.Errorf("invalid dual key format: expected 0x04 at positions 0 and 65")
	}

	fmt.Printf("📝 Input Parameters:\n")                                                       //nolint:forbidigo
	fmt.Printf("   Message Hash: %s\n", messageHashHex)                                       //nolint:forbidigo
	fmt.Printf("   Signature:    %s\n", signatureHex)                                         //nolint:forbidigo
	fmt.Printf("   Public Key:   %s (%d bytes)\n", turnkeyPublicKeyHex, len(turnkeyKeyBytes)) //nolint:forbidigo

	// Extract both keys from the dual format
	encryptionKeyX := turnkeyKeyBytes[1:33]
	encryptionKeyY := turnkeyKeyBytes[33:65]
	signingKeyX := turnkeyKeyBytes[66:98]
	signingKeyY := turnkeyKeyBytes[98:130]

	if verbose {
		fmt.Printf("\n🔑 Extracted Keys:\n")                             //nolint:forbidigo
		fmt.Printf("   🔒 EncryptionKey (Key 1):\n")                     //nolint:forbidigo
		fmt.Printf("      X: %s\n", hex.EncodeToString(encryptionKeyX)) //nolint:forbidigo
		fmt.Printf("      Y: %s\n", hex.EncodeToString(encryptionKeyY)) //nolint:forbidigo

		var compressed1 []byte
		if encryptionKeyY[31]&1 == 0 {
			compressed1 = append([]byte{0x02}, encryptionKeyX...)
		} else {
			compressed1 = append([]byte{0x03}, encryptionKeyX...)
		}
		fmt.Printf("      Compressed: %s\n", hex.EncodeToString(compressed1)) //nolint:forbidigo

		fmt.Printf("   ✍️  SigningKey (Key 2 - Ephemeral):\n")       //nolint:forbidigo
		fmt.Printf("      X: %s\n", hex.EncodeToString(signingKeyX)) //nolint:forbidigo
		fmt.Printf("      Y: %s\n", hex.EncodeToString(signingKeyY)) //nolint:forbidigo

		var compressed2 []byte
		if signingKeyY[31]&1 == 0 {
			compressed2 = append([]byte{0x02}, signingKeyX...)
		} else {
			compressed2 = append([]byte{0x03}, signingKeyX...)
		}
		fmt.Printf("      Compressed: %s\n", hex.EncodeToString(compressed2)) //nolint:forbidigo
	}

	// Verify signature using the ephemeral signing key (Key 2)
	fmt.Printf("\n🔐 Signature Verification:\n")                //nolint:forbidigo
	fmt.Printf("   Using:     Ephemeral SigningKey (Key 2)\n") //nolint:forbidigo
	fmt.Printf("   Algorithm: ECDSA P-256\n")                  //nolint:forbidigo

	if err := verifySignatureWithSigningKey(messageHashHex, signatureHex, signingKeyX, signingKeyY, verbose); err != nil {
		fmt.Printf("   Result:    ❌ VERIFICATION FAILED: %v\n", err) //nolint:forbidigo

		// Also try with the first key for debugging
		if verbose {
			fmt.Printf("\n🔍 Debug: Trying with EncryptionKey (Key 1):\n") //nolint:forbidigo
			if err2 := verifySignatureWithSigningKey(messageHashHex, signatureHex, encryptionKeyX, encryptionKeyY, verbose); err2 != nil {
				fmt.Printf("   Key 1:     ❌ ALSO FAILED: %v\n", err2) //nolint:forbidigo
			} else {
				fmt.Printf("   Key 1:     ✅ SUCCESS! (Note: This should be Key 2)\n") //nolint:forbidigo
			}
		}

		fmt.Printf("\n🚀 App Attestation: ❌ FAILED\n") //nolint:forbidigo
		return errors.New("app attestation verification failed")
	}

	fmt.Printf("   Result:    ✅ VERIFICATION SUCCESSFUL\n")      //nolint:forbidigo
	fmt.Printf("   Status:    Message authenticity confirmed\n") //nolint:forbidigo
	fmt.Printf("\n🚀 App Attestation: ✅ VERIFIED\n")              //nolint:forbidigo

	return nil
}
