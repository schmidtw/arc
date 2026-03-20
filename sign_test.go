// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMessage       = "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Test\r\n\r\nBody.\r\n"
	testMessageSimple = "From: test@example.com\r\n\r\nBody.\r\n"
)

func TestSignNoExistingChain(t *testing.T) {
	key, resolver := generateTestKey(t, "example.org", "sel")

	msg := testMessage

	v, err := NewValidator(WithResolver(resolver))
	require.NoError(t, err)

	signer, err := NewSigner(key, "sel._domainkey.example.org",
		WithValidator(v),
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12345, 0)),
		WithResolver(resolver),
	)
	require.NoError(t, err)

	result, err := signer.Sign(context.Background(), strings.NewReader(msg), "spf=pass")
	require.NoError(t, err)

	// Verify the result contains ARC headers.
	resultStr := string(result)
	assert.Contains(t, resultStr, "ARC-Seal:")
	assert.Contains(t, resultStr, "ARC-Message-Signature:")
	assert.Contains(t, resultStr, "ARC-Authentication-Results:")
	assert.Contains(t, resultStr, "cv=none")
	assert.Contains(t, resultStr, "i=1")

	// Validate the signed message.
	present, err := v.ValidateBytes(context.Background(), result)
	require.NoError(t, err)
	assert.True(t, present)
}

func TestSignWithExistingChain(t *testing.T) {
	key1, resolver1 := generateTestKey(t, "example.org", "sel1")
	key2, resolver2 := generateTestKey(t, "example.net", "sel2")

	// Combine both resolvers into one.
	combined := &mapResolver{records: map[string]string{}}
	for k, v := range resolver1.records {
		combined.records[k] = v
	}
	for k, v := range resolver2.records {
		combined.records[k] = v
	}

	msg := testMessage

	v, err := NewValidator(WithResolver(combined))
	require.NoError(t, err)

	// Sign first time.
	signer1, err := NewSigner(key1, "sel1._domainkey.example.org",
		WithValidator(v),
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12345, 0)),
		WithResolver(combined),
	)
	require.NoError(t, err)

	signed1, err := signer1.Sign(context.Background(), strings.NewReader(msg), "spf=pass")
	require.NoError(t, err)

	// Sign second time with different key.
	signer2, err := NewSigner(key2, "sel2._domainkey.example.net",
		WithValidator(v),
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12346, 0)),
		WithResolver(combined),
	)
	require.NoError(t, err)

	signed2, err := signer2.SignBytes(context.Background(), signed1, "spf=fail; arc=pass")
	require.NoError(t, err)

	resultStr := string(signed2)
	assert.Contains(t, resultStr, "cv=pass")
	assert.Contains(t, resultStr, "i=2")

	// Validate the doubly-signed message.
	present, err := v.ValidateBytes(context.Background(), signed2)
	require.NoError(t, err)
	assert.True(t, present)
}

func TestSignRefusesFailedChain(t *testing.T) {
	key, resolver := generateTestKey(t, "example.org", "sel")

	// Message with cv=fail.
	msg := "ARC-Seal: i=1; a=rsa-sha256; cv=fail; d=example.org; s=sel; t=12345; b=dGVzdA==\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from:to:subject; s=sel; t=12345; bh=dGVzdA==; b=dGVzdA==\r\n" +
		"ARC-Authentication-Results: i=1; example.org; spf=pass\r\n" +
		testMessageSimple

	v, err := NewValidator(WithResolver(resolver))
	require.NoError(t, err)
	signer, err := NewSigner(key, "sel._domainkey.example.org",
		WithValidator(v),
		WithSignedHeaders(HeaderFrom),
		WithResolver(resolver),
	)
	require.NoError(t, err)

	_, err = signer.Sign(context.Background(), strings.NewReader(msg), "spf=fail")
	require.Error(t, err)
}

func TestSignWithEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	resolver := &mapResolver{
		records: map[string]string{
			"sel._domainkey.example.org": "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub),
		},
	}

	msg := testMessage

	v, err := NewValidator(WithResolver(resolver))
	require.NoError(t, err)
	signer, err := NewSigner(priv, "sel._domainkey.example.org",
		WithValidator(v),
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12345, 0)),
		WithResolver(resolver),
	)
	require.NoError(t, err)

	result, err := signer.Sign(context.Background(), strings.NewReader(msg), "spf=pass")
	require.NoError(t, err)

	present, err := v.ValidateBytes(context.Background(), result)
	require.NoError(t, err)
	assert.True(t, present)
}

func TestSignUnsupportedKeyType(t *testing.T) {
	// ecdsa keys are not supported for ARC signing.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	v, err := NewValidator()
	require.NoError(t, err)
	_, err = NewSigner(ecKey, "sel._domainkey.example.org", WithValidator(v))
	require.Error(t, err)
}

func TestSignerMinRSAKeyBits(t *testing.T) {
	t.Run("512-bit option rejected", func(t *testing.T) {
		key := getRSATestKey(t, 2048)
		s, err := NewSigner(key, "sel._domainkey.example.org",
			WithMinRSAKeyBits(512))
		assert.Error(t, err, "should reject 512-bit keys")
		assert.Nil(t, s)
	})

	// Test that the signer enforces a minimum of 2048 bits for RSA keys.
	t.Run("1024-bit key rejected", func(t *testing.T) {
		key := getRSATestKey(t, 1024)

		resolver := &mapResolver{
			records: map[string]string{
				"sel._domainkey.example.org": encodeDKIMRecord(t, &key.PublicKey),
			},
		}

		v, err := NewValidator(WithResolver(resolver))
		require.NoError(t, err)
		_, err = NewSigner(key, "sel._domainkey.example.org",
			WithValidator(v),
			WithResolver(resolver))
		require.Error(t, err, "should reject 1024-bit keys")
		assert.Contains(t, err.Error(), "RSA key too small")
	})

	t.Run("2048-bit key accepted", func(t *testing.T) {
		key := getRSATestKey(t, 2048)

		resolver := &mapResolver{
			records: map[string]string{
				"sel._domainkey.example.org": encodeDKIMRecord(t, &key.PublicKey),
			},
		}

		v, err := NewValidator(WithResolver(resolver))
		require.NoError(t, err)
		_, err = NewSigner(key, "sel._domainkey.example.org",
			WithValidator(v),
			WithResolver(resolver))
		require.NoError(t, err, "should accept 2048-bit keys")
	})
}

func TestSignerValidatorMinBits(t *testing.T) {
	// Test that the Signer uses the provided validator's minBits for validation.
	ctx := context.Background()

	// Create a 3072-bit key for the second signer.
	signingKey := getRSATestKey(t, 3072)

	// Create a 2048-bit key for the first signer.
	existingKey := getRSATestKey(t, 2048)

	resolver := &mapResolver{
		records: map[string]string{
			"sel1._domainkey.example.org": encodeDKIMRecord(t, &existingKey.PublicKey),
			"sel2._domainkey.example.org": encodeDKIMRecord(t, &signingKey.PublicKey),
		},
	}

	// Create the first signer with a validator that accepts 2048-bit keys.
	v1, err := NewValidator(WithResolver(resolver), WithMinRSAKeyBits(2048))
	require.NoError(t, err)
	signer1, err := NewSigner(existingKey, "sel1._domainkey.example.org",
		WithValidator(v1),
		WithResolver(resolver),
	)
	require.NoError(t, err)

	// Sign a message with the 2048-bit key.
	msg1, err := signer1.Sign(ctx, strings.NewReader(testMessage), "spf=pass")
	require.NoError(t, err)

	// Create a second signer with a validator that requires 3072-bit keys.
	// The signer's own key is 3072 bits, so construction should succeed.
	v2, err := NewValidator(WithResolver(resolver), WithMinRSAKeyBits(3072))
	require.NoError(t, err)
	signer2, err := NewSigner(signingKey, "sel2._domainkey.example.org",
		WithValidator(v2),
		WithResolver(resolver),
	)
	require.NoError(t, err)

	// When signing, the validator should detect that the existing chain
	// has a 2048-bit key (below minBits=3072) and mark it as cv=fail.
	// The signer should still succeed but mark the chain as broken.
	msg2, err := signer2.SignBytes(ctx, msg1, "spf=pass")
	require.NoError(t, err)

	// Verify the new seal has cv=fail (not cv=pass).
	msg2Parsed, err := parseMessage(bytes.NewReader(msg2))
	require.NoError(t, err)

	sets, err := collectArcSets(msg2Parsed)
	require.NoError(t, err)
	require.Len(t, sets, 2, "should have 2 ARC sets")

	// The most recent seal (instance 2) should have cv=fail.
	require.Equal(t, chainFail, sets[1].Seal.ChainValidation)
}

func TestEndToEndSignThenValidate(t *testing.T) {
	// End-to-end test: sign a message twice with different keys, then validate.
	ctx := context.Background()

	// Generate two different keys.
	key1 := getRSATestKey(t, 2048)
	key2 := getRSATestKey(t, 2048)

	// Create a resolver with both public keys.
	resolver := &mapResolver{
		records: map[string]string{
			"sel1._domainkey.domain1.example": encodeDKIMRecord(t, &key1.PublicKey),
			"sel2._domainkey.domain2.example": encodeDKIMRecord(t, &key2.PublicKey),
		},
	}

	v, err := NewValidator(WithResolver(resolver))
	require.NoError(t, err)

	// Original message.
	originalMsg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test message.\r\n"

	// Sign with first key (instance 1).
	signer1, err := NewSigner(key1, "sel1._domainkey.domain1.example",
		WithValidator(v),
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(1234567890, 0)),
		WithResolver(resolver),
	)
	require.NoError(t, err)

	signed1, err := signer1.Sign(ctx, strings.NewReader(originalMsg), "spf=pass; dkim=pass")
	require.NoError(t, err)

	// Validate after first signature.
	present1, err := v.Validate(ctx, bytes.NewReader(signed1))
	require.NoError(t, err)
	assert.True(t, present1)

	// Sign again with second key (instance 2).
	signer2, err := NewSigner(key2, "sel2._domainkey.domain2.example",
		WithValidator(v),
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(1234567900, 0)),
		WithResolver(resolver),
	)
	require.NoError(t, err)

	signed2, err := signer2.Sign(ctx, bytes.NewReader(signed1), "spf=pass; dkim=pass; arc=pass")
	require.NoError(t, err)

	// Validate the full 2-hop chain.
	present2, err := v.Validate(ctx, bytes.NewReader(signed2))
	require.NoError(t, err)
	assert.True(t, present2)

	// Verify instance numbers.
	parsedMsg, err := parseMessage(bytes.NewReader(signed2))
	require.NoError(t, err)
	sets, err := collectArcSets(parsedMsg)
	require.NoError(t, err)
	require.Len(t, sets, 2)
	assert.Equal(t, 1, sets[0].Instance)
	assert.Equal(t, 2, sets[1].Instance)

	// Verify cv values.
	assert.Equal(t, chainNone, sets[0].Seal.ChainValidation)
	assert.Equal(t, chainPass, sets[1].Seal.ChainValidation)
}
