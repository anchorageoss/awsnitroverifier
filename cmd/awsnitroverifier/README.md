# Turnkey AWS Nitro Enclave Attestation Verifier

A CLI tool for verifying AWS Nitro Enclave attestations and Turnkey transaction signatures with support for P-256 ECDSA cryptography.

## Overview

This tool provides two main verification modes:
1. **Full Turnkey Attestation**: Verifies both AWS Nitro Enclave boot attestation and application-level signature verification
2. **App-Only Attestation**: Performs isolated signature verification against Turnkey's ephemeral signing key

## Prerequisites

- [Turnkey CLI](https://docs.turnkey.com/getting-started/cli) installed and configured
- `jq` for JSON processing
- Go 1.21+ for building the tool

## Quick Start

### 1. Build the Tool

```bash
go build -o confidentialcomputeverifier
```

### 2. Test with Existing Data (Working Example)

```bash
# Test app-only verification with known working data
go run . app-only-attestation \
  --message a19750d348742823803a5503651ba3872ce10cd14dce2c150c49af1e6c3d8a8b \
  --signature 67a029a63dac93c0130a64b5dc0c20e1a00b3b8cb54f9f4d0655c9477d27e9572421ebd0c633660affedb482bf0b424abc533bb06c35239943cff61d392074b2 \
  --turnkey-public-key 04451028fc9d42cef6d8f2a3ebe17d65783c470dbc6f04663d500c12009930cf9b209e733f6ac6103cc28f07ecde2dbb55095738b828d6b7a55caf4ddf9d67f2ae047827dcd2325b8d58694c2ea14e8f1e1f8a36c84438d291ff9b1b067debdb3e2ba3822984cde8bed4de2c237bd323526da4961d368bcc63cbd2d37d00e936683e \
  --verbose
```

Expected output: `🚀 App Attestation: ✅ VERIFIED`

### 3. Test with QoS Manifest (Example)

```bash
# Test full verification with QoS manifest validation
go run . full-turnkey-attestation \
  --file attestation.txt \
  --message a19750d348742823803a5503651ba3872ce10cd14dce2c150c49af1e6c3d8a8b \
  --signature 67a029a63dac93c0130a64b5dc0c20e1a00b3b8cb54f9f4d0655c9477d27e9572421ebd0c633660affedb482bf0b424abc533bb06c35239943cff61d392074b2 \
  --turnkey-public-key 04451028fc9d42cef6d8f2a3ebe17d65783c470dbc6f04663d500c12009930cf9b209e733f6ac6103cc28f07ecde2dbb55095738b828d6b7a55caf4ddf9d67f2ae047827dcd2325b8d58694c2ea14e8f1e1f8a36c84438d291ff9b1b067debdb3e2ba3822984cde8bed4de2c237bd323526da4961d368bcc63cbd2d37d00e936683e \
  --qos-manifest 48656c6c6f20576f726c64 \
  --verbose
```

Expected output: `📋 QoS Manifest: ✅ VERIFIED` (if UserData matches the manifest)

## Complete Turnkey Workflow

### Step 1: Parse Transaction and Get Signature Data

First, call the Turnkey visualsign API to parse your transaction and obtain the signature data:

```bash
turnkey request \
  --host api.preprod.turnkey.engineering \
  --path /visualsign/api/v1/parse \
  --body '{
    "request": {
      "unsigned_payload": "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAGDpVgWUMU7MEPPORo0ORMinVaO1ktDjHe3//f1qqIwJ2XYaz02Vuj7xyKHc5e6LXN5WxDxzUGN72irt3XVidnPQdbX1g0C8G9eZLm2AYo6hVEwP0bql0mb8fZLQW6g3h/XIjx/6Oi3+YXvcTjVzJRoyLj/K6B5aRXOQ5kdRwApGXinqdo/t9kTIqum44hiK3Qa8VQ+/cWyCK5zmPHeD2VLh8J5qP+7PmQMuHB32uXItyzY057jjRAk2vDSwzByOtSH/zRQemDLK8QrZF0lcoPJxtbKTzUcCfqc3AH7UDrOaC9BIo+CMO0lb4X9FQn2JvsW4DH4mlcGGTXZ0PbOb7TRtYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFTlniTAUaihSnsel5fw4Szfp0kCFmUxlaalEqbxZmArjJclj04kifG7PRApFI4NgwtaE5na/xCEBI572Nvp+FkDBkZv5SEXMv/srbpyw5vnvIzlu8X3EmssQ5s6QAAAAAaBTtTK9ooXRnL9rIYDGmPoTqFe+h1EtyKT9tvbABZQBt324ddloZPZy+FGzut5rBy0he1fWzeROoz1hX7/AKk7YUJFOy/o1K3RALVqqztUypoKMpR8OCcCt0Rr0FUhSAYIAgABDAIAAAAA5AtUAgAAAAoGAAIABggNAQEMCgcJBAECBQIGCA0JDgDkC1QCAAAACwAFAoAaBgALAAkDUMMAAAAAAAAIAgADDAIAAAAQJwAAAAAAAA==",
      "chain": "CHAIN_SOLANA"
    },
    "organization_id": "9beeaabc-26a7-4890-9d43-df22ae80d4a0"
  }' \
  -k preprod \
  --organization 9beeaabc-26a7-4890-9d43-df22ae80d4a0
```

This returns a response with:
- `response.parsedTransaction.signature.message`: The message hash
- `response.parsedTransaction.signature.signature`: The ECDSA signature
- `response.parsedTransaction.signature.publicKey`: The 130-byte dual P-256 public key

### Step 2: Get Attestation Document

Get the current attestation document from Turnkey:

```bash
turnkey request \
  --host api.preprod.turnkey.engineering \
  --path /public/v1/query/get_attestation \
  --body '{
    "organizationId": "9beeaabc-26a7-4890-9d43-df22ae80d4a0",
    "enclaveType": "signer"
  }' \
  -k preprod | jq -r '.attestationDocument' > attestation-$(date +%Y-%m-%d).base64
```

### Step 3: Verify App-Only Attestation (Current Working Method)

Since the visualsign parser doesn't yet return boot attestation data, we can verify the signature independently:

```bash
go run . app-only-attestation \
  --message <MESSAGE_FROM_STEP_1> \
  --signature <SIGNATURE_FROM_STEP_1> \
  --turnkey-public-key <PUBLIC_KEY_FROM_STEP_1> \
  --verbose
```

Example with actual values:
```bash
go run . app-only-attestation \
  --message a19750d348742823803a5503651ba3872ce10cd14dce2c150c49af1e6c3d8a8b \
  --signature 67a029a63dac93c0130a64b5dc0c20e1a00b3b8cb54f9f4d0655c9477d27e9572421ebd0c633660affedb482bf0b424abc533bb06c35239943cff61d392074b2 \
  --turnkey-public-key 04451028fc9d42cef6d8f2a3ebe17d65783c470dbc6f04663d500c12009930cf9b209e733f6ac6103cc28f07ecde2dbb55095738b828d6b7a55caf4ddf9d67f2ae047827dcd2325b8d58694c2ea14e8f1e1f8a36c84438d291ff9b1b067debdb3e2ba3822984cde8bed4de2c237bd323526da4961d368bcc63cbd2d37d00e936683e \
  --verbose
```

### Step 4: Full Attestation Verification (Future)

Once visualsign-parser returns boot attestation data, you'll be able to run complete verification:

```bash
go run . full-turnkey-attestation \
  --file attestation-2025-09-02.base64 \
  --message <MESSAGE_FROM_STEP_1> \
  --signature <SIGNATURE_FROM_STEP_1> \
  --turnkey-public-key <PUBLIC_KEY_FROM_STEP_1> \
  --verbose
```

**Note**: Currently this will show `❌ Key mismatch` because the attestation document contains different keys than those used in the transaction signing. This is expected since the keys rotate when enclaves restart.

## Command Reference

### App-Only Attestation

Verifies only the cryptographic signature against the provided public key:

```bash
go run . app-only-attestation [options]
```

**Options:**
- `--message`: Message hash to verify (hex format)
- `--signature`: ECDSA signature (64-byte hex format: 32 bytes r + 32 bytes s)
- `--turnkey-public-key`: Turnkey's 130-byte dual P-256 public key (hex format)
- `--verbose`: Show detailed verification information

### Full Turnkey Attestation

Verifies both AWS Nitro Enclave attestation and signature:

```bash
go run . full-turnkey-attestation [options]
```

**Options:**
- `--file`: Path to base64-encoded attestation document
- `--message`: Message hash to verify (hex format)
- `--signature`: ECDSA signature (64-byte hex format)
- `--turnkey-public-key`: Turnkey's 130-byte dual P-256 public key (hex format)
- `--qos-manifest`: QoS manifest to compare against UserData in attestation (hex format)
- `--verbose`: Show detailed verification information
- `--skip-signature`: Skip signature verification
- `--skip-timestamp`: Skip certificate timestamp validation

## Technical Details

### Turnkey P-256 Dual Key Format

Turnkey uses a 130-byte format containing two P-256 public keys:
- **Bytes 0-64**: Encryption key (for data encryption/communication)
- **Bytes 65-129**: Signing key (for transaction signing/authentication)

Each key follows the uncompressed point format: `04` + 32-byte X coordinate + 32-byte Y coordinate

### Signature Verification

- **Algorithm**: ECDSA P-256
- **Hash Function**: SHA256 (signatures are over `SHA256(message)`, not raw message)
- **Key Used**: Ephemeral signing key (second 65 bytes of the dual key format)
- **Signature Format**: 64 bytes (32-byte r + 32-byte s components)

### QoS Manifest Verification

Quality of Service (QoS) manifests can be verified against the UserData field in attestation documents:

- **Purpose**: Ensure the enclave was booted with expected configuration
- **Format**: Hex-encoded manifest data
- **Verification**: Byte-for-byte comparison with UserData field
- **Usage**: Add `--qos-manifest <hex_data>` to compare against UserData

**Example:**
```bash
go run . full-turnkey-attestation \
  --file attestation.txt \
  --qos-manifest 48656c6c6f20576f726c64 \
  --verbose
```

The tool will compare the provided QoS manifest against the UserData field and report:
- ✅ **MATCHES**: QoS manifest exactly matches UserData
- ❌ **MISMATCH**: QoS manifest differs from UserData
- ⚠️ **SKIPPED**: No QoS manifest provided for verification

### Current Limitations

1. **Enclave Key Rotation**: Keys change when Turnkey enclaves restart, so attestation documents may contain different keys than those used for signing
2. **Visualsign Integration**: The visualsign parser doesn't yet return boot attestation data, limiting full attestation verification
3. **Key Matching**: You may need to poll for attestation documents with matching keys (see polling scripts)

## Helper Scripts

This directory includes helper scripts for working with Turnkey attestations:

- `./get-attestation.sh`: Get current attestation document
- `./poll-turnkey-attestation.sh`: Poll until finding matching public key
- See `README-scripts.md` for detailed usage

## Troubleshooting

### Common Issues

1. **Signature Verification Failed**: Ensure you're using the correct message hash and public key from the same transaction
2. **Key Mismatch**: Attestation keys may differ from signing keys due to enclave restarts
3. **Invalid Format**: Verify hex strings are properly formatted (no spaces, correct length)

### Debug Mode

Use `--verbose` flag for detailed debugging information:
- Key extraction and parsing details
- Signature component breakdown
- Verification step-by-step process
- Certificate chain validation

## Configuration

Default Turnkey API endpoints:
- **Host**: `api.preprod.turnkey.engineering`
- **Organization ID**: `9beeaabc-26a7-4890-9d43-df22ae80d4a0`
- **Enclave Type**: `signer`

Modify the scripts or commands as needed for your specific Turnkey configuration.
