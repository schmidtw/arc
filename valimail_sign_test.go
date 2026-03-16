// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type valimailSignSuite struct {
	Description string                    `yaml:"description"`
	Tests       map[string]valimailSignTC `yaml:"tests"`
	Domain      string                    `yaml:"domain"`
	Sel         string                    `yaml:"sel"`
	PrivateKey  string                    `yaml:"privatekey"` //nolint:gosec // Test data, not actual secrets
	TXTRecords  map[string]string         `yaml:"txt-records"`
}

type valimailSignTC struct {
	Spec        string `yaml:"spec"`
	Description string `yaml:"description"`
	Message     string `yaml:"message"`
	T           int64  `yaml:"t"`
	SigHeaders  string `yaml:"sig-headers"`
	SrvID       string `yaml:"srv-id"`
	AS          string `yaml:"AS"`
	AMS         string `yaml:"AMS"`
	AAR         string `yaml:"AAR"`
}

func TestValimailSignSuite(t *testing.T) {
	data, err := os.ReadFile("testdata/arc-draft-sign-tests.yml")
	if err != nil {
		t.Skipf("test suite not found: %v", err)
	}

	// The file contains multiple YAML documents separated by ---
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	var suites []valimailSignSuite
	for {
		var suite valimailSignSuite
		err := decoder.Decode(&suite)
		if err != nil {
			break
		}
		suites = append(suites, suite)
	}

	require.NotEmpty(t, suites)

	for _, suite := range suites {
		// Parse private key if present at suite level.
		var privKey crypto.Signer
		if suite.PrivateKey != "" {
			privKey = parsePrivateKey(t, suite.PrivateKey)
		}
		var resolver Resolver
		if suite.TXTRecords != nil {
			resolver = buildTXTRecordResolver(suite.TXTRecords)
		}

		domain := suite.Domain
		sel := suite.Sel

		for name, tc := range suite.Tests {
			t.Run(name, func(t *testing.T) {
				// Skip tests where expected output is empty (no signing expected).
				expectedAS := strings.TrimSpace(tc.AS)
				expectedAMS := strings.TrimSpace(tc.AMS)
				expectedAAR := strings.TrimSpace(tc.AAR)

				if expectedAS == "" && expectedAMS == "" && expectedAAR == "" {
					// This test expects signing to be refused (e.g. failing chain).
					testSignRefused(t, tc, privKey, domain, sel, resolver)
					return
				}

				// Parse sig-headers.
				sigHeaders := toHeaderFields(strings.Split(tc.SigHeaders, ":"))

				// Extract auth results from the message's Authentication-Results header.
				authResults := extractAuthResults(tc.Message, tc.SrvID)

				signer, err := NewSigner(privKey, sel+"._domainkey."+domain,
					WithAuthServID(tc.SrvID),
					WithSignedHeaders(sigHeaders...),
					WithTimestamp(time.Unix(tc.T, 0)),
					WithResolver(resolver),
					WithMinRSAKeyBits(1024),
				)
				require.NoError(t, err)

				result, err := signer.Sign(context.Background(), strings.NewReader(tc.Message), authResults)
				require.NoError(t, err)

				// Since RSA PKCS#1 v1.5 is deterministic, compare signatures.
				resultStr := string(result)
				compareGeneratedSignature(t, resultStr, "ARC-Seal", expectedAS)
				compareGeneratedSignature(t, resultStr, "ARC-Message-Signature", expectedAMS)
			})
		}
	}
}

// testSignRefused verifies that signing is refused for the given test case.
func testSignRefused(t *testing.T, tc valimailSignTC, privKey crypto.Signer, domain, sel string, resolver Resolver) {
	t.Helper()

	sigHeaders := toHeaderFields(strings.Split(tc.SigHeaders, ":"))
	authResults := extractAuthResults(tc.Message, tc.SrvID)

	signer, err := NewSigner(privKey, sel+"._domainkey."+domain,
		WithAuthServID(tc.SrvID),
		WithSignedHeaders(sigHeaders...),
		WithTimestamp(time.Unix(tc.T, 0)),
		WithResolver(resolver),
		WithMinRSAKeyBits(1024),
	)
	require.NoError(t, err)

	_, err = signer.Sign(context.Background(), strings.NewReader(tc.Message), authResults)
	assert.Error(t, err)
}

// extractAuthResults extracts and merges authentication results from all
// Authentication-Results headers matching the given srv-id.
func extractAuthResults(message, srvID string) string {
	lines := strings.Split(message, "\n")

	// First, collect all header lines (handling folded headers).
	type hdr struct {
		key, value string
	}
	var headers []hdr
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			break
		}

		// Continuation line?
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(headers) > 0 {
				headers[len(headers)-1].value += " " + strings.TrimSpace(trimmed)
			}
			continue
		}

		// New header.
		colonIdx := strings.IndexByte(trimmed, ':')
		if colonIdx < 0 {
			continue
		}
		headers = append(headers, hdr{
			key:   trimmed[:colonIdx],
			value: strings.TrimSpace(trimmed[colonIdx+1:]),
		})
	}

	// Collect auth results from all matching Authentication-Results headers.
	var results []string
	for _, h := range headers {
		if !strings.EqualFold(h.key, "Authentication-Results") {
			continue
		}
		val := h.value
		if !strings.HasPrefix(val, srvID) {
			continue
		}
		// Remove srv-id prefix.
		rest := strings.TrimPrefix(val, srvID)
		rest = strings.TrimLeft(rest, "; ")
		if rest != "" {
			results = append(results, rest)
		}
	}

	return strings.Join(results, ";\n    ")
}

// compareGeneratedSignature extracts the b= tag from both the generated and
// expected headers and compares them.
func compareGeneratedSignature(t *testing.T, result, headerName, expected string) {
	t.Helper()

	genSig := extractBTag(result, headerName)
	expSig := extractBTagFromValue(expected)

	require.NotEmpty(t, genSig, "could not find %s b= tag in generated output", headerName)
	require.NotEmpty(t, expSig, "could not find b= tag in expected %s", headerName)

	assert.Equal(t, expSig, genSig, "%s signature mismatch", headerName)
}

// extractBTag extracts the b= tag value from a specific header in a message.
func extractBTag(message, headerName string) string {
	lines := strings.Split(message, "\n")
	var headerValue string
	collecting := false

	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "" {
			break
		}

		if collecting {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				headerValue += " " + strings.TrimSpace(trimmed)
				continue
			}
			break
		}

		if strings.HasPrefix(trimmed, headerName+":") {
			headerValue = strings.TrimSpace(trimmed[len(headerName)+1:])
			collecting = true
		}
	}

	return extractBTagFromValue(headerValue)
}

// extractBTagFromValue extracts the b= tag value from a header value string.
func extractBTagFromValue(val string) string {
	// Remove whitespace for comparison.
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, val)

	parts := strings.Split(cleaned, ";")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(trimmed, "b=") && !strings.HasPrefix(trimmed, "bh=") {
			return trimmed[2:]
		}
	}
	return ""
}

// parsePrivateKey parses a PEM-encoded private key.
func parsePrivateKey(t *testing.T, pemStr string) crypto.Signer {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "failed to decode PEM private key")

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8.
		key8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, err2, "failed to parse private key: PKCS1: %v", err)
		signer, ok := key8.(crypto.Signer)
		require.True(t, ok, "parsed key does not implement crypto.Signer")
		return signer
	}
	return key
}
