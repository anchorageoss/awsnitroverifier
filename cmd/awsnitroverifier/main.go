package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	nitroverifier "github.com/anchorageoss/awsnitroverifier"
	"github.com/anchorageoss/awsnitroverifier/version"
	"github.com/urfave/cli/v3"
)

// countPCRValidations returns the count of valid and invalid PCR validations
func countPCRValidations(results []nitroverifier.PCRValidationResult) (valid, invalid int) {
	for _, pcr := range results {
		if pcr.Valid {
			valid++
		} else {
			invalid++
		}
	}
	return valid, invalid
}

func main() {
	cmd := &cli.Command{
		Name:    "awsnitroverifier",
		Usage:   "Verify AWS Nitro Enclave attestation documents",
		Version: version.String(),
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
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Verbose output with detailed validation results",
					},
				},
				Action: runBasicVerification,
			},
			{
				Name:  "examples",
				Usage: "Print example invocations for the bundled testdata fixtures",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "env",
						Usage: "Fixture environment: 'production' or 'preprod'",
						Value: "production",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Verbose output with detailed validation results",
					},
				},
				Action: runExamples,
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
	verbose := cmd.Bool("verbose")

	// Read the attestation file
	data, err := os.ReadFile(attestationFile)
	if err != nil {
		return fmt.Errorf("error reading file %s: %w", attestationFile, err)
	}

	// Decode base64 to bytes
	attestationBase64 := strings.TrimSpace(string(data))
	attestationBytes, err := base64.StdEncoding.DecodeString(attestationBase64)
	if err != nil {
		return fmt.Errorf("failed to decode attestation from base64: %w", err)
	}

	// Parse PCR validation rules if provided
	var pcrValidations []nitroverifier.PCRRule
	if pcrRules != "" {
		pcrValidations = parsePCRRules(pcrRules)
	}

	// Create validator with options
	validator := nitroverifier.NewVerifier(nitroverifier.AWSNitroVerifierOptions{
		SkipTimestampCheck: skipTimestamp,
		PCRRules:           pcrValidations,
	})

	// Validate the attestation
	result, err := validator.Validate(attestationBytes)
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

// runExamples prints example invocations for the bundled testdata fixtures.
// The fixtures themselves are real-world AWS Nitro Enclave attestations
// (sourced from Turnkey enclaves) bundled to keep the CLI useful out of the box.
func runExamples(ctx context.Context, cmd *cli.Command) error {
	env := cmd.String("env")
	_ = cmd.Bool("verbose") // TODO: Use for verbose output

	fmt.Println("🧪 Example invocations for bundled testdata fixtures")
	fmt.Println("====================================================")

	fmt.Println("Bundled fixtures in testdata/:")
	fmt.Println("  - testdata/turnkey-prod.base64")
	fmt.Println("  - testdata/turnkey-preprod.base64")
	fmt.Println()

	switch env {
	case "production":
		fmt.Println("Expected PCR values for testdata/turnkey-prod.base64:")
		fmt.Println("  PCR[3]: b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b")
		fmt.Println()
		fmt.Println("Example command:")
		fmt.Println("  go run ./cmd/awsnitroverifier verify -f ./testdata/turnkey-prod.base64 --pcrs 3:b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b")
	case "preprod":
		fmt.Println("Expected PCR values for testdata/turnkey-preprod.base64:")
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
		if result.ChainTrusted {
			fmt.Printf("  🔗 AWS root fingerprint: %s\n", result.RootFingerprint)
		}
	} else {
		fmt.Println("❌ Attestation validation FAILED")
		if len(result.Errors) > 0 {
			fmt.Println("\nValidation errors:")
			for _, errMsg := range result.Errors {
				fmt.Printf("  - %s\n", errMsg)
			}
		}
	}

	// Print PCR results
	if len(result.PCRResults) > 0 {
		fmt.Printf("\n🔐 PCR Validations:\n")
		validCount, invalidCount := countPCRValidations(result.PCRResults)
		fmt.Printf("  Total: %d | Valid: %d | Invalid: %d\n",
			len(result.PCRResults), validCount, invalidCount)

		for _, pcr := range result.PCRResults {
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
		if result.Nonce != nil {
			fmt.Printf("\n🔑 Nonce: %d bytes\n", len(result.Nonce))
			fmt.Printf("  Hex: %s\n", hex.EncodeToString(result.Nonce))
		}
	}
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
