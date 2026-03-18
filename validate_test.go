// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateNoArcHeaders(t *testing.T) {
	msg := "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Test\r\n\r\nBody.\r\n"
	v := NewValidator(WithResolver(&mapResolver{records: map[string]string{}}))
	present, err := v.Validate(context.Background(), strings.NewReader(msg))
	require.NoError(t, err)
	assert.False(t, present)
}

func TestValidateValidChain(t *testing.T) {
	key, resolver := generateTestKey(t, "example.org", "sel")

	msg := buildSignedMessage(t, key, "example.org", "sel", 1)

	v := NewValidator(WithResolver(resolver))
	present, err := v.Validate(context.Background(), strings.NewReader(msg))
	require.NoError(t, err)
	assert.True(t, present)
}

func TestValidateStructuralFailures(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{
			name: "missing AAR",
			msg: "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.org; s=sel; t=12345; b=dGVzdA==\r\n" +
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from:to:subject; s=sel; t=12345; bh=dGVzdA==; b=dGVzdA==\r\n" +
				"From: test@example.com\r\n\r\nBody.\r\n",
		},
		{
			name: "cv=pass on instance 1",
			msg: "ARC-Seal: i=1; a=rsa-sha256; cv=pass; d=example.org; s=sel; t=12345; b=dGVzdA==\r\n" +
				"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from:to:subject; s=sel; t=12345; bh=dGVzdA==; b=dGVzdA==\r\n" +
				"ARC-Authentication-Results: i=1; example.org; spf=pass\r\n" +
				"From: test@example.com\r\n\r\nBody.\r\n",
		},
	}

	resolver := &mapResolver{records: map[string]string{}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewValidator(WithResolver(resolver))
			present, err := v.Validate(context.Background(), strings.NewReader(tt.msg))
			assert.True(t, present)
			assert.Error(t, err)
		})
	}
}

func TestValidateHighestCVFail(t *testing.T) {
	msg := "ARC-Seal: i=1; a=rsa-sha256; cv=fail; d=example.org; s=sel; t=12345; b=dGVzdA==\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from:to:subject; s=sel; t=12345; bh=dGVzdA==; b=dGVzdA==\r\n" +
		"ARC-Authentication-Results: i=1; example.org; spf=pass\r\n" +
		"From: test@example.com\r\n\r\nBody.\r\n"

	v := NewValidator(WithResolver(&mapResolver{records: map[string]string{}}))
	present, err := v.Validate(context.Background(), strings.NewReader(msg))
	assert.True(t, present)
	assert.Error(t, err)
}

// Helper functions for building test messages with valid signatures.

func generateTestKey(t *testing.T, domain, selector string) (*rsa.PrivateKey, *mapResolver) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	resolver := &mapResolver{
		records: map[string]string{
			selector + "._domainkey." + domain: encodeDKIMRecord(t, &key.PublicKey),
		},
	}

	return key, resolver
}

// encodeDKIMRecord encodes an RSA public key as a DKIM TXT record value.
func encodeDKIMRecord(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func buildSignedMessage(t *testing.T, key *rsa.PrivateKey, domain, selector string, instance int) string {
	t.Helper()

	bodyContent := "Hey gang,\r\nThis is a test message.\r\n--J.\r\n"
	baseHeaders := "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Test\r\n"

	ts := time.Unix(12345, 0)

	// Compute body hash.
	bodyHash := computeBodyHash([]byte(bodyContent))

	signHeaders := []string{"from", "to", "subject"}

	// Build the AAR.
	aarStr := serializeAAR(instance, domain, "spf=pass")

	// Build AMS for signing (with empty b=).
	amsForSigning := serializeAMSForSigning(instance, algRSASHA256, domain, selector,
		signHeaders, bodyHash, ts)

	// Build the data the AMS signs.
	// Parse the message to get headers for signing.
	fullMsg := aarStr + "\r\n" + baseHeaders + "\r\n" + bodyContent
	msg, err := parseMessageBytes([]byte(fullMsg))
	require.NoError(t, err)

	var amsBuf strings.Builder
	for _, h := range signHeaders {
		for i := len(msg.Headers) - 1; i >= 0; i-- {
			if strings.EqualFold(msg.Headers[i].Key, h) {
				canon := canonicalizeHeaderRelaxed(msg.Headers[i].Key, msg.Headers[i].Value)
				amsBuf.WriteString(canon)
				amsBuf.WriteString("\r\n")
				break
			}
		}
	}
	// Add AMS header with empty b=.
	amsCanon := canonicalizeHeaderRelaxedRaw(amsForSigning)
	amsBuf.WriteString(amsCanon)

	amsSig, err := sign(key, algRSASHA256, []byte(amsBuf.String()))
	require.NoError(t, err)

	amsStr := serializeAMS(instance, algRSASHA256, domain, selector,
		signHeaders, bodyHash, amsSig, ts)

	// Build AS.
	cv := string(chainNone)
	if instance > 1 {
		cv = string(chainPass)
	}

	asForSigning := serializeArcSealForSigning(instance, algRSASHA256, domain, selector, cv, ts)

	// AS signs: AAR(1..K), AMS(1..K), AS(1..K-1), current AS with empty b=.
	var asBuf strings.Builder
	// AAR
	aarCanon := canonicalizeHeaderRelaxedRaw(aarStr)
	asBuf.WriteString(aarCanon)
	asBuf.WriteString("\r\n")
	// AMS
	amsCanonForAS := canonicalizeHeaderRelaxedRaw(amsStr)
	asBuf.WriteString(amsCanonForAS)
	asBuf.WriteString("\r\n")
	// Current AS with empty b=
	asCanon := canonicalizeHeaderRelaxedRaw(asForSigning)
	asBuf.WriteString(asCanon)

	asSig, err := sign(key, algRSASHA256, []byte(asBuf.String()))
	require.NoError(t, err)

	asStr := serializeArcSeal(instance, algRSASHA256, domain, selector, cv, asSig, ts)

	// Assemble final message.
	var result strings.Builder
	result.WriteString(asStr + "\r\n")
	result.WriteString(amsStr + "\r\n")
	result.WriteString(aarStr + "\r\n")
	result.WriteString(baseHeaders)
	result.WriteString("\r\n")
	result.WriteString(bodyContent)

	return result.String()
}

func TestValidatorMinRSAKeyBits(t *testing.T) {
	tests := []struct {
		name       string
		keySize    int
		minBits    int
		shouldPass bool
	}{
		{
			name:       "1024-bit key with min=1024 should pass",
			keySize:    1024,
			minBits:    1024,
			shouldPass: true,
		},
		{
			name:       "2048-bit key with min=1024 should pass",
			keySize:    2048,
			minBits:    1024,
			shouldPass: true,
		},
		{
			name:       "1024-bit key with min=2048 should fail",
			keySize:    1024,
			minBits:    2048,
			shouldPass: false,
		},
		{
			name:       "2048-bit key with min=2048 should pass",
			keySize:    2048,
			minBits:    2048,
			shouldPass: true,
		},
		{
			name:       "4096-bit key with min=2048 should pass",
			keySize:    4096,
			minBits:    2048,
			shouldPass: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate a key of the specified size.
			key, err := rsa.GenerateKey(rand.Reader, tt.keySize)
			require.NoError(t, err)

			// Create resolver with the public key.
			resolver := &mapResolver{
				records: map[string]string{
					"sel._domainkey.example.org": encodeDKIMRecord(t, &key.PublicKey),
				},
			}

			// Create a signed message with this key.
			msg := buildSignedMessage(t, key, "example.org", "sel", 1)

			// Validate with the specified minBits.
			v := NewValidator(WithResolver(resolver), WithMinRSAKeyBits(tt.minBits))
			present, err := v.Validate(context.Background(), strings.NewReader(msg))
			assert.True(t, present)

			if tt.shouldPass {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "RSA key too small")
			}
		})
	}
}

func TestValidatorDefaultMinBits(t *testing.T) {
	// Test that the default minimum is 1024 bits.
	key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Testing weak keys
	require.NoError(t, err)

	resolver := &mapResolver{
		records: map[string]string{
			"sel._domainkey.example.org": encodeDKIMRecord(t, &key.PublicKey),
		},
	}

	msg := buildSignedMessage(t, key, "example.org", "sel", 1)

	v := NewValidator(WithResolver(resolver)) // No explicit minBits
	present, err := v.Validate(context.Background(), strings.NewReader(msg))
	assert.True(t, present)
	require.NoError(t, err, "default should accept 1024-bit keys")
}

func TestValidatorMaxArcSets(t *testing.T) {
	resolver := &mapResolver{records: map[string]string{}}

	t.Run("exceeds max", func(t *testing.T) {
		// Build a message with 3 ARC sets.
		var headers strings.Builder
		for i := 1; i <= 3; i++ {
			cv := "none"
			if i > 1 {
				cv = "pass"
			}
			fmt.Fprintf(&headers, "ARC-Seal: i=%d; a=rsa-sha256; cv=%s; d=example.org; s=sel; t=12345; b=dGVzdA==\r\n", i, cv)
			fmt.Fprintf(&headers, "ARC-Message-Signature: i=%d; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from; s=sel; t=12345; bh=dGVzdA==; b=dGVzdA==\r\n", i)
			fmt.Fprintf(&headers, "ARC-Authentication-Results: i=%d; example.org; spf=pass\r\n", i)
		}
		msg := headers.String() + "From: test@example.com\r\n\r\nBody.\r\n"

		v := NewValidator(WithResolver(resolver), WithMaxArcSets(2))
		present, err := v.Validate(context.Background(), strings.NewReader(msg))
		assert.True(t, present)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("within max", func(t *testing.T) {
		// Build a message with 2 ARC sets.
		var headers strings.Builder
		for i := 1; i <= 2; i++ {
			cv := "none"
			if i > 1 {
				cv = "pass"
			}
			fmt.Fprintf(&headers, "ARC-Seal: i=%d; a=rsa-sha256; cv=%s; d=example.org; s=sel; t=12345; b=dGVzdA==\r\n", i, cv)
			fmt.Fprintf(&headers, "ARC-Message-Signature: i=%d; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from; s=sel; t=12345; bh=dGVzdA==; b=dGVzdA==\r\n", i)
			fmt.Fprintf(&headers, "ARC-Authentication-Results: i=%d; example.org; spf=pass\r\n", i)
		}
		msg := headers.String() + "From: test@example.com\r\n\r\nBody.\r\n"

		v := NewValidator(WithResolver(resolver), WithMaxArcSets(2))
		present, err := v.Validate(context.Background(), strings.NewReader(msg))
		assert.True(t, present)
		// Will fail later (signature verification), but not on instance count.
		if err != nil {
			assert.NotContains(t, err.Error(), "exceeds maximum")
		}
	})
}

func TestRFC8617AppendixB(t *testing.T) {
	// Test parsing of RFC 8617 Appendix B example message.
	data, err := os.ReadFile("testdata/rfc8617-appendix-b.eml")
	require.NoError(t, err)

	msg, err := parseMessage(strings.NewReader(string(data)))
	require.NoError(t, err)

	sets, err := collectArcSets(msg)
	require.NoError(t, err)

	require.Len(t, sets, 3)

	// Verify instance numbers.
	for i, s := range sets {
		assert.Equal(t, i+1, s.Instance)
	}

	// Verify ARC Set 1 (lists.example.org).
	assert.Equal(t, "lists.example.org", sets[0].Seal.Domain)
	assert.Equal(t, "dk-lists", sets[0].Seal.Selector)
	assert.Equal(t, chainNone, sets[0].Seal.ChainValidation)
	assert.Equal(t, "lists.example.org", sets[0].AMS.Domain)
	assert.Equal(t, "lists.example.org", sets[0].AAR.AuthServID)

	// Verify ARC Set 2 (gmail.example).
	assert.Equal(t, "gmail.example", sets[1].Seal.Domain)
	assert.Equal(t, "20120806", sets[1].Seal.Selector)
	assert.Equal(t, chainPass, sets[1].Seal.ChainValidation)
	assert.Equal(t, "gmail.example", sets[1].AMS.Domain)
	assert.Equal(t, "gmail.example", sets[1].AAR.AuthServID)

	// Verify ARC Set 3 (clochette.example.org).
	assert.Equal(t, "clochette.example.org", sets[2].Seal.Domain)
	assert.Equal(t, "clochette", sets[2].Seal.Selector)
	assert.Equal(t, chainPass, sets[2].Seal.ChainValidation)
	assert.Equal(t, "clochette.example.org", sets[2].AMS.Domain)
	assert.Equal(t, "clochette.example.org", sets[2].AAR.AuthServID)

	// Verify all sets use RSA-SHA256.
	for i, s := range sets {
		assert.Equal(t, algRSASHA256, s.Seal.Algorithm, "set[%d].Seal.Algorithm", i)
		assert.Equal(t, algRSASHA256, s.AMS.Algorithm, "set[%d].AMS.Algorithm", i)
	}

	// Verify timestamp (all have t=12345).
	for i, s := range sets {
		wantT := time.Unix(12345, 0)
		assert.True(t, s.Seal.Timestamp.Equal(wantT), "set[%d].Seal.Timestamp = %v, want %v", i, s.Seal.Timestamp, wantT)
		assert.True(t, s.AMS.Timestamp.Equal(wantT), "set[%d].AMS.Timestamp = %v, want %v", i, s.AMS.Timestamp, wantT)
	}
}
