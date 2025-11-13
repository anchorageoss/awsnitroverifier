package awsnitroverifier

import (
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/anchorageoss/awsnitroverifier/internal"
	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/turnkey-boot-attestation.base64
var awsNitroAttestationBase64 string

//go:embed testdata/aws_turnkey_valid_cert_chain.pem
var awsNitroCertChainPEM []byte

// ============================================================================
// Helper Functions
// ============================================================================

// loadNitroAttestationPayload loads and extracts the attestation document from testdata
// The test data is from a real AWS Nitro Enclave attestation (Turnkey service)
func loadNitroAttestationPayload(t *testing.T) []byte {
	t.Helper()

	rawAttestation, err := base64.StdEncoding.DecodeString(awsNitroAttestationBase64)
	require.NoError(t, err, "failed to decode base64")

	coseSign1, err := parseCOSESign1(rawAttestation)
	require.NoError(t, err, "failed to parse COSE_Sign1")

	return coseSign1.Payload
}

// loadFirstCertFromPEM loads the first certificate from PEM data
func loadFirstCertFromPEM(t *testing.T, pemData []byte) []byte {
	t.Helper()

	block, _ := pem.Decode(pemData)
	require.NotNil(t, block, "failed to decode PEM")
	require.Equal(t, "CERTIFICATE", block.Type)

	return block.Bytes
}

// ============================================================================
// Tests: parseCOSESign1
// ============================================================================

func TestParseCOSESign1(t *testing.T) {
	rawAttestation, err := base64.StdEncoding.DecodeString(awsNitroAttestationBase64)
	require.NoError(t, err)

	tests := []struct {
		name        string
		data        []byte
		wantErr     bool
		errContains string
		validate    func(t *testing.T, cose *internal.COSESign1)
	}{
		{
			name:    "valid AWS Nitro COSE_Sign1",
			data:    rawAttestation,
			wantErr: false,
			validate: func(t *testing.T, cose *internal.COSESign1) {
				require.NotNil(t, cose.ProtectedHeaders)
				require.NotNil(t, cose.Payload)
				require.NotNil(t, cose.Signature)
				require.NotEmpty(t, cose.ProtectedHeaders)
				require.NotEmpty(t, cose.Payload)
				require.NotEmpty(t, cose.Signature)
			},
		},
		{
			name:        "empty data",
			data:        []byte{},
			wantErr:     true,
			errContains: "empty",
		},
		{
			name:        "invalid CBOR",
			data:        []byte{0xff, 0xff, 0xff},
			wantErr:     true,
			errContains: "failed to unmarshal",
		},
		{
			name: "wrong number of elements",
			data: func() []byte {
				data, _ := cbor.Marshal([]interface{}{[]byte("header"), []byte("payload")})
				return data
			}(),
			wantErr:     true,
			errContains: "expected 4 elements",
		},
		{
			name: "invalid protected headers type",
			data: func() []byte {
				data, _ := cbor.Marshal([]interface{}{"not bytes", map[string]interface{}{}, []byte("payload"), []byte("sig")})
				return data
			}(),
			wantErr:     true,
			errContains: "invalid protected headers type",
		},
		{
			name: "invalid payload type",
			data: func() []byte {
				data, _ := cbor.Marshal([]interface{}{[]byte("header"), map[string]interface{}{}, "not bytes", []byte("sig")})
				return data
			}(),
			wantErr:     true,
			errContains: "invalid payload type",
		},
		{
			name: "invalid signature type",
			data: func() []byte {
				data, _ := cbor.Marshal([]interface{}{[]byte("header"), map[string]interface{}{}, []byte("payload"), "not bytes"})
				return data
			}(),
			wantErr:     true,
			errContains: "invalid signature type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cose, err := parseCOSESign1(tt.data)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cose)
			if tt.validate != nil {
				tt.validate(t, cose)
			}
		})
	}
}

// ============================================================================
// Tests: ParseAttestationDocument
// ============================================================================

func TestParseAttestationDocument(t *testing.T) {
	validPayload := loadNitroAttestationPayload(t)

	// Create CBOR with deeply nested structure for testing limits
	deeplyNestedCBOR := createDeeplyNestedCBOR(t, 40)

	// Create CBOR with large array for testing limits
	largeArrayCBOR := createLargeArrayCBOR(t, 200)

	tests := []struct {
		name        string
		data        []byte
		wantErr     bool
		errContains string
		validate    func(t *testing.T, doc *internal.AttestationDocument)
	}{
		{
			name:    "valid AWS Nitro attestation document",
			data:    validPayload,
			wantErr: false,
			validate: func(t *testing.T, doc *internal.AttestationDocument) {
				require.NotEmpty(t, doc.ModuleID)
				require.NotZero(t, doc.Timestamp)
				require.NotEmpty(t, doc.Certificate)
				require.NotEmpty(t, doc.CABundle)
				require.Contains(t, doc.ModuleID, "i-")
			},
		},
		{
			name:        "empty data",
			data:        []byte{},
			wantErr:     true,
			errContains: "empty",
		},
		{
			name:        "oversized data",
			data:        make([]byte, 17*1024*1024), // 17 MB
			wantErr:     true,
			errContains: "exceeds maximum size",
		},
		{
			name:        "invalid CBOR",
			data:        []byte{0xff, 0xff, 0xff},
			wantErr:     true,
			errContains: "failed to decode CBOR",
		},
		{
			name:        "CBOR with deeply nested structure",
			data:        deeplyNestedCBOR,
			wantErr:     true,
			errContains: "failed to decode CBOR",
		},
		{
			name:        "CBOR with large array",
			data:        largeArrayCBOR,
			wantErr:     true,
			errContains: "failed to decode CBOR",
		},
		{
			name: "missing module_id",
			data: createAttestationCBOR(t, map[string]interface{}{
				"timestamp":   uint64(1234567890),
				"digest":      "SHA384",
				"pcrs":        map[uint][]byte{},
				"certificate": []byte("cert"),
				"cabundle":    [][]byte{[]byte("ca")},
			}),
			wantErr:     true,
			errContains: "module_id",
		},
		{
			name: "missing timestamp",
			data: createAttestationCBOR(t, map[string]interface{}{
				"module_id":   "test-module",
				"digest":      "SHA384",
				"pcrs":        map[uint][]byte{},
				"certificate": []byte("cert"),
				"cabundle":    [][]byte{[]byte("ca")},
			}),
			wantErr:     true,
			errContains: "timestamp",
		},
		{
			name: "missing certificate",
			data: createAttestationCBOR(t, map[string]interface{}{
				"module_id": "test-module",
				"timestamp": uint64(1234567890),
				"digest":    "SHA384",
				"pcrs":      map[uint][]byte{},
				"cabundle":  [][]byte{[]byte("ca")},
			}),
			wantErr:     true,
			errContains: "certificate",
		},
		{
			name: "missing cabundle",
			data: createAttestationCBOR(t, map[string]interface{}{
				"module_id":   "test-module",
				"timestamp":   uint64(1234567890),
				"digest":      "SHA384",
				"pcrs":        map[uint][]byte{},
				"certificate": []byte("cert"),
			}),
			wantErr:     true,
			errContains: "cabundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := parseAttestationDocument(tt.data)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, doc)
			if tt.validate != nil {
				tt.validate(t, doc)
			}
		})
	}
}

// ============================================================================
// Tests: ExtractCertificateInfo
// ============================================================================

func TestExtractCertificateInfo(t *testing.T) {
	validCertDER := loadFirstCertFromPEM(t, awsNitroCertChainPEM)

	tests := []struct {
		name        string
		certDER     []byte
		wantErr     bool
		errContains string
		validate    func(t *testing.T, info *internal.CertificateInfo)
	}{
		{
			name:    "valid certificate from AWS Nitro chain",
			certDER: validCertDER,
			wantErr: false,
			validate: func(t *testing.T, info *internal.CertificateInfo) {
				require.NotZero(t, info.NotBefore)
				require.NotZero(t, info.NotAfter)
				require.NotEmpty(t, info.Subject)
				require.NotEmpty(t, info.Issuer)
				require.NotEmpty(t, info.SerialNumber)
				require.NotNil(t, info.Certificate)
				require.True(t, info.NotBefore.Before(info.NotAfter))
			},
		},
		{
			name:        "empty certificate data",
			certDER:     []byte{},
			wantErr:     true,
			errContains: "empty",
		},
		{
			name:        "oversized certificate data",
			certDER:     make([]byte, 11*1024), // 11 KB
			wantErr:     true,
			errContains: "exceeds maximum size",
		},
		{
			name:        "invalid DER data",
			certDER:     []byte{0xff, 0xff, 0xff, 0xff},
			wantErr:     true,
			errContains: "failed to parse certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := extractCertificateInfo(tt.certDER)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, info)
			if tt.validate != nil {
				tt.validate(t, info)
			}
		})
	}
}

// ============================================================================
// Tests: ValidateCertificateTimestamp
// ============================================================================

func TestValidateCertificateTimestamp(t *testing.T) {
	validCert := &internal.CertificateInfo{
		NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
	}

	tests := []struct {
		name        string
		certInfo    *internal.CertificateInfo
		checkTime   time.Time
		wantErr     bool
		errContains string
	}{
		{
			name:      "valid time within range",
			certInfo:  validCert,
			checkTime: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
			wantErr:   false,
		},
		{
			name:      "valid time at NotBefore",
			certInfo:  validCert,
			checkTime: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			wantErr:   false,
		},
		{
			name:      "valid time at NotAfter",
			certInfo:  validCert,
			checkTime: time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			wantErr:   false,
		},
		{
			name:        "nil certInfo",
			certInfo:    nil,
			checkTime:   time.Now(),
			wantErr:     true,
			errContains: "nil",
		},
		{
			name:        "zero checkTime",
			certInfo:    validCert,
			checkTime:   time.Time{},
			wantErr:     true,
			errContains: "zero",
		},
		{
			name:        "time before NotBefore",
			certInfo:    validCert,
			checkTime:   time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC),
			wantErr:     true,
			errContains: "not yet valid",
		},
		{
			name:        "time after NotAfter",
			certInfo:    validCert,
			checkTime:   time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
			wantErr:     true,
			errContains: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCertificateTimestamp(tt.certInfo, tt.checkTime)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// ============================================================================
// Tests: AttestationDocument.Validate
// ============================================================================

func TestAttestationDocumentValidate(t *testing.T) {
	validDoc := &internal.AttestationDocument{
		ModuleID:    "test-module",
		Timestamp:   1234567890,
		Certificate: []byte("cert"),
		CABundle:    [][]byte{[]byte("ca")},
	}

	tests := []struct {
		name        string
		doc         *internal.AttestationDocument
		wantErr     bool
		errContains string
	}{
		{
			name:    "valid document",
			doc:     validDoc,
			wantErr: false,
		},
		{
			name: "missing module_id",
			doc: &internal.AttestationDocument{
				Timestamp:   1234567890,
				Certificate: []byte("cert"),
				CABundle:    [][]byte{[]byte("ca")},
			},
			wantErr:     true,
			errContains: "module_id",
		},
		{
			name: "missing timestamp",
			doc: &internal.AttestationDocument{
				ModuleID:    "test-module",
				Certificate: []byte("cert"),
				CABundle:    [][]byte{[]byte("ca")},
			},
			wantErr:     true,
			errContains: "timestamp",
		},
		{
			name: "missing certificate",
			doc: &internal.AttestationDocument{
				ModuleID:  "test-module",
				Timestamp: 1234567890,
				CABundle:  [][]byte{[]byte("ca")},
			},
			wantErr:     true,
			errContains: "certificate",
		},
		{
			name: "missing cabundle",
			doc: &internal.AttestationDocument{
				ModuleID:    "test-module",
				Timestamp:   1234567890,
				Certificate: []byte("cert"),
			},
			wantErr:     true,
			errContains: "cabundle",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.doc.Validate()

			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					require.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			require.NoError(t, err)
		})
	}
}

// ============================================================================
// CBOR Test Helpers
// ============================================================================

func createAttestationCBOR(t *testing.T, fields map[string]interface{}) []byte {
	t.Helper()

	data, err := cbor.Marshal(fields)
	require.NoError(t, err)

	return data
}

func createDeeplyNestedCBOR(t *testing.T, depth int) []byte {
	t.Helper()

	// Create a deeply nested map structure
	var nested interface{} = "bottom"
	for i := 0; i < depth; i++ {
		nested = map[string]interface{}{"level": nested}
	}

	data, err := cbor.Marshal(nested)
	require.NoError(t, err)

	return data
}

func createLargeArrayCBOR(t *testing.T, size int) []byte {
	t.Helper()

	// Create an array with many elements
	arr := make([]int, size)
	for i := 0; i < size; i++ {
		arr[i] = i
	}

	data, err := cbor.Marshal(map[string]interface{}{
		"large_array": arr,
		"module_id":   "test",
		"timestamp":   uint64(123),
		"certificate": []byte("cert"),
		"cabundle":    [][]byte{[]byte("ca")},
	})
	require.NoError(t, err)

	return data
}
