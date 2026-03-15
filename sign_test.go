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
	"crypto/rsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

const (
	testMessage       = "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Test\r\n\r\nBody.\r\n"
	testMessageSimple = "From: test@example.com\r\n\r\nBody.\r\n"
)

func TestSignNoExistingChain(t *testing.T) {
	key, resolver := generateTestKey(t, "example.org", "sel")

	msg := testMessage

	v := NewValidator(WithResolver(resolver))
	signer, err := NewSigner(key, "sel._domainkey.example.org",
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12345, 0)),
		WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	result, err := signer.Sign(context.Background(), strings.NewReader(msg), "spf=pass")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verify the result contains ARC headers.
	resultStr := string(result)
	if !strings.Contains(resultStr, "ARC-Seal:") {
		t.Error("result missing ARC-Seal")
	}
	if !strings.Contains(resultStr, "ARC-Message-Signature:") {
		t.Error("result missing ARC-Message-Signature")
	}
	if !strings.Contains(resultStr, "ARC-Authentication-Results:") {
		t.Error("result missing ARC-Authentication-Results")
	}
	if !strings.Contains(resultStr, "cv=none") {
		t.Error("first instance should have cv=none")
	}
	if !strings.Contains(resultStr, "i=1") {
		t.Error("first instance should be i=1")
	}

	// Validate the signed message.
	present, err := v.ValidateBytes(context.Background(), result)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !present {
		t.Error("expected ARC chain present")
	}
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

	v := NewValidator(WithResolver(combined))

	// Sign first time.
	signer1, err := NewSigner(key1, "sel1._domainkey.example.org",
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12345, 0)),
		WithResolver(combined),
	)
	if err != nil {
		t.Fatalf("NewSigner #1: %v", err)
	}

	signed1, err := signer1.Sign(context.Background(), strings.NewReader(msg), "spf=pass")
	if err != nil {
		t.Fatalf("Sign #1: %v", err)
	}

	// Sign second time with different key.
	signer2, err := NewSigner(key2, "sel2._domainkey.example.net",
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12346, 0)),
		WithResolver(combined),
	)
	if err != nil {
		t.Fatalf("NewSigner #2: %v", err)
	}

	signed2, err := signer2.SignBytes(context.Background(), signed1, "spf=fail; arc=pass")
	if err != nil {
		t.Fatalf("Sign #2: %v", err)
	}

	resultStr := string(signed2)
	if !strings.Contains(resultStr, "cv=pass") {
		t.Error("second instance should have cv=pass")
	}
	if !strings.Contains(resultStr, "i=2") {
		t.Error("second instance should be i=2")
	}

	// Validate the doubly-signed message.
	present, err := v.ValidateBytes(context.Background(), signed2)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !present {
		t.Error("expected ARC chain present")
	}
}

func TestSignRefusesFailedChain(t *testing.T) {
	key, resolver := generateTestKey(t, "example.org", "sel")

	// Message with cv=fail.
	msg := "ARC-Seal: i=1; a=rsa-sha256; cv=fail; d=example.org; s=sel; t=12345; b=dGVzdA==\r\n" +
		"ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from:to:subject; s=sel; t=12345; bh=dGVzdA==; b=dGVzdA==\r\n" +
		"ARC-Authentication-Results: i=1; example.org; spf=pass\r\n" +
		testMessageSimple

	signer, err := NewSigner(key, "sel._domainkey.example.org",
		WithSignedHeaders(HeaderFrom),
		WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	_, err = signer.Sign(context.Background(), strings.NewReader(msg), "spf=fail")
	if err == nil {
		t.Fatal("expected error when signing with failed chain")
	}
}

func TestSignWithEd25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	resolver := &mapResolver{
		records: map[string]string{
			"sel._domainkey.example.org": "v=DKIM1; k=ed25519; p=" + base64.StdEncoding.EncodeToString(pub),
		},
	}

	msg := testMessage

	v := NewValidator(WithResolver(resolver))
	signer, err := NewSigner(priv, "sel._domainkey.example.org",
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(12345, 0)),
		WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	result, err := signer.Sign(context.Background(), strings.NewReader(msg), "spf=pass")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	present, err := v.ValidateBytes(context.Background(), result)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !present {
		t.Error("expected ARC chain present")
	}
}

func TestSignUnsupportedKeyType(t *testing.T) {
	// ecdsa keys are not supported for ARC signing.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, err = NewSigner(ecKey, "sel._domainkey.example.org")
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestEndToEndSignThenValidate(t *testing.T) {
	// End-to-end test: sign a message twice with different keys, then validate.
	ctx := context.Background()

	// Generate two different keys.
	key1, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Testing weak keys
	if err != nil {
		t.Fatal(err)
	}
	key2, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Testing weak keys
	if err != nil {
		t.Fatal(err)
	}

	// Create a resolver with both public keys.
	resolver := &mapResolver{
		records: map[string]string{
			"sel1._domainkey.domain1.example": encodeDKIMRecord(t, &key1.PublicKey),
			"sel2._domainkey.domain2.example": encodeDKIMRecord(t, &key2.PublicKey),
		},
	}

	v := NewValidator(WithResolver(resolver))

	// Original message.
	originalMsg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nThis is a test message.\r\n"

	// Sign with first key (instance 1).
	signer1, err := NewSigner(key1, "sel1._domainkey.domain1.example",
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(1234567890, 0)),
		WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewSigner #1: %v", err)
	}

	signed1, err := signer1.Sign(ctx, strings.NewReader(originalMsg), "spf=pass; dkim=pass")
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}

	// Validate after first signature.
	present1, err := v.Validate(ctx, bytes.NewReader(signed1))
	if err != nil {
		t.Fatalf("validate after first sign: %v", err)
	}
	if !present1 {
		t.Error("expected ARC chain present after first sign")
	}

	// Sign again with second key (instance 2).
	signer2, err := NewSigner(key2, "sel2._domainkey.domain2.example",
		WithSignedHeaders(HeaderFrom, HeaderTo, HeaderSubject),
		WithTimestamp(time.Unix(1234567900, 0)),
		WithResolver(resolver),
	)
	if err != nil {
		t.Fatalf("NewSigner #2: %v", err)
	}

	signed2, err := signer2.Sign(ctx, bytes.NewReader(signed1), "spf=pass; dkim=pass; arc=pass")
	if err != nil {
		t.Fatalf("second sign: %v", err)
	}

	// Validate the full 2-hop chain.
	present2, err := v.Validate(ctx, bytes.NewReader(signed2))
	if err != nil {
		t.Fatalf("validate after second sign: %v", err)
	}
	if !present2 {
		t.Error("expected ARC chain present after second sign")
	}
	// Verify instance numbers.
	parsedMsg, err := parseMessage(bytes.NewReader(signed2))
	if err != nil {
		t.Fatalf("parsing final message: %v", err)
	}
	sets, err := collectArcSets(parsedMsg)
	if err != nil {
		t.Fatalf("collecting sets: %v", err)
	}
	if len(sets) != 2 {
		t.Fatalf("got %d sets, want 2", len(sets))
	}
	if sets[0].Instance != 1 {
		t.Errorf("set[0].Instance = %d, want 1", sets[0].Instance)
	}
	if sets[1].Instance != 2 {
		t.Errorf("set[1].Instance = %d, want 2", sets[1].Instance)
	}

	// Verify cv values.
	if sets[0].Seal.ChainValidation != chainNone {
		t.Errorf("set[0] cv = %q, want none", sets[0].Seal.ChainValidation)
	}
	if sets[1].Seal.ChainValidation != chainPass {
		t.Errorf("set[1] cv = %q, want pass", sets[1].Seal.ChainValidation)
	}
}
