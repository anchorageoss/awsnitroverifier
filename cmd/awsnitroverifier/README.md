# AWS Nitro Enclave Attestation Verifier CLI

A command-line interface for [`awsnitroverifier`](../../README.md), the Go library that verifies AWS Nitro Enclave attestation documents.

## Build

From the repository root:

```bash
make build
# → bin/awsnitroverifier
```

`make build` injects the version and short commit hash via `-ldflags`. To build manually:

```bash
go build -o bin/awsnitroverifier ./cmd/awsnitroverifier
```

(Builds without ldflags will report `--version` as `dev (commit: none)`.)

## Subcommands

### `verify`

Verifies a base64-encoded attestation document from a file.

```bash
bin/awsnitroverifier verify --file <path> [--pcrs <rules>] [--skip-timestamp] [--verbose]
```

| Flag | Description |
| --- | --- |
| `--file`, `-f` | Path to a file containing a base64-encoded attestation document. Required. |
| `--pcrs` | Comma-separated PCR expectations, e.g. `3:b798ab...,4:461a85...`. Each rule is `index:expected-hex`. |
| `--skip-timestamp` | Skip certificate `NotBefore`/`NotAfter` checks. Defaults to `true` so that bundled test fixtures (now in the past) still validate. Pass `--skip-timestamp=false` against fresh attestations. |
| `--verbose`, `-v` | Print full validation detail (per-PCR hex, UserData, PublicKey, Nonce). |

Exit code: `0` on a valid attestation, `1` otherwise.

Example using a bundled fixture:

```bash
bin/awsnitroverifier verify \
  --file testdata/turnkey-prod.base64 \
  --pcrs 3:b798abfdbd591d5e1b7db6485a6de9e65100f5796d9e3a2bd7c179989cd663338b567162974974fbcc45d03847e70d8b \
  --verbose
```

### `examples`

Prints ready-to-copy `verify` invocations for the bundled `testdata/` fixtures along with the PCR values expected for each.

```bash
bin/awsnitroverifier examples --env production
bin/awsnitroverifier examples --env preprod
```

The bundled fixtures (`testdata/turnkey-prod.base64`, `testdata/turnkey-preprod.base64`) are real-world AWS Nitro Enclave attestations captured from Turnkey signer enclaves. They're representative attestation documents — nothing about the verifier itself is Turnkey-specific.

### `--version`

Prints the injected version and short commit hash:

```bash
$ bin/awsnitroverifier --version
awsnitroverifier version 0.1.0+main-6ca7c799321b (commit: 6ca7c799321b)
```

Released binaries (built via goreleaser) print just the semver portion (e.g. `0.1.0`); local `make build` includes branch and hash metadata.

## See also

- [Root README](../../README.md) — library API, installation, releases.
- [USAGE.md](../../USAGE.md) — programmatic usage patterns.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — capturing new test fixtures.
