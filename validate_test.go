// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateNoArcHeaders(t *testing.T) {
	msg := "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Test\r\n\r\nBody.\r\n"
	v := NewValidator(WithResolver(&mapResolver{records: map[string]string{}}))
	present, err := v.Validate(context.Background(), strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if present {
		t.Error("expected no ARC chain present")
	}
}

func TestValidateValidChain(t *testing.T) {
	key, resolver := generateTestKey(t, "example.org", "sel")

	msg := buildSignedMessage(t, key, "example.org", "sel", 1)

	v := NewValidator(WithResolver(resolver))
	present, err := v.Validate(context.Background(), strings.NewReader(msg))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !present {
		t.Error("expected ARC chain present")
	}
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
			if !present {
				t.Error("expected ARC chain present")
			}
			if err == nil {
				t.Error("expected validation error")
			}
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
	if !present {
		t.Error("expected ARC chain present")
	}
	if err == nil {
		t.Error("expected validation error")
	}
}

// Helper functions for building test messages with valid signatures.

func generateTestKey(t *testing.T, domain, selector string) (*rsa.PrivateKey, *mapResolver) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatalf("marshaling public key: %v", err)
	}
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
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}

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
	if err != nil {
		t.Fatal(err)
	}

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

func TestRFC8617AppendixB(t *testing.T) {
	// Test parsing of RFC 8617 Appendix B example message.
	data, err := os.ReadFile("testdata/rfc8617-appendix-b.eml")
	if err != nil {
		t.Fatalf("reading test file: %v", err)
	}

	msg, err := parseMessage(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("parsing message: %v", err)
	}

	sets, err := collectArcSets(msg)
	if err != nil {
		t.Fatalf("collecting ARC sets: %v", err)
	}

	if len(sets) != 3 {
		t.Fatalf("got %d ARC sets, want 3", len(sets))
	}

	// Verify instance numbers.
	for i, s := range sets {
		wantInstance := i + 1
		if s.Instance != wantInstance {
			t.Errorf("set[%d].Instance = %d, want %d", i, s.Instance, wantInstance)
		}
	}

	// Verify ARC Set 1 (lists.example.org).
	if sets[0].Seal.Domain != "lists.example.org" {
		t.Errorf("set[0].Seal.Domain = %q, want %q", sets[0].Seal.Domain, "lists.example.org")
	}
	if sets[0].Seal.Selector != "dk-lists" {
		t.Errorf("set[0].Seal.Selector = %q, want %q", sets[0].Seal.Selector, "dk-lists")
	}
	if sets[0].Seal.ChainValidation != chainNone {
		t.Errorf("set[0].Seal.CV = %q, want %q", sets[0].Seal.ChainValidation, string(chainNone))
	}
	if sets[0].AMS.Domain != "lists.example.org" {
		t.Errorf("set[0].AMS.Domain = %q, want %q", sets[0].AMS.Domain, "lists.example.org")
	}
	if sets[0].AAR.AuthServID != "lists.example.org" {
		t.Errorf("set[0].AAR.AuthServID = %q, want %q", sets[0].AAR.AuthServID, "lists.example.org")
	}

	// Verify ARC Set 2 (gmail.example).
	if sets[1].Seal.Domain != "gmail.example" {
		t.Errorf("set[1].Seal.Domain = %q, want %q", sets[1].Seal.Domain, "gmail.example")
	}
	if sets[1].Seal.Selector != "20120806" {
		t.Errorf("set[1].Seal.Selector = %q, want %q", sets[1].Seal.Selector, "20120806")
	}
	if sets[1].Seal.ChainValidation != chainPass {
		t.Errorf("set[1].Seal.CV = %q, want %q", sets[1].Seal.ChainValidation, string(chainPass))
	}
	if sets[1].AMS.Domain != "gmail.example" {
		t.Errorf("set[1].AMS.Domain = %q, want %q", sets[1].AMS.Domain, "gmail.example")
	}
	if sets[1].AAR.AuthServID != "gmail.example" {
		t.Errorf("set[1].AAR.AuthServID = %q, want %q", sets[1].AAR.AuthServID, "gmail.example")
	}

	// Verify ARC Set 3 (clochette.example.org).
	if sets[2].Seal.Domain != "clochette.example.org" {
		t.Errorf("set[2].Seal.Domain = %q, want %q", sets[2].Seal.Domain, "clochette.example.org")
	}
	if sets[2].Seal.Selector != "clochette" {
		t.Errorf("set[2].Seal.Selector = %q, want %q", sets[2].Seal.Selector, "clochette")
	}
	if sets[2].Seal.ChainValidation != chainPass {
		t.Errorf("set[2].Seal.CV = %q, want %q", sets[2].Seal.ChainValidation, string(chainPass))
	}
	if sets[2].AMS.Domain != "clochette.example.org" {
		t.Errorf("set[2].AMS.Domain = %q, want %q", sets[2].AMS.Domain, "clochette.example.org")
	}
	if sets[2].AAR.AuthServID != "clochette.example.org" {
		t.Errorf("set[2].AAR.AuthServID = %q, want %q", sets[2].AAR.AuthServID, "clochette.example.org")
	}

	// Verify all sets use RSA-SHA256.
	for i, s := range sets {
		if s.Seal.Algorithm != algRSASHA256 {
			t.Errorf("set[%d].Seal.Algorithm = %q, want %q", i, s.Seal.Algorithm, algRSASHA256)
		}
		if s.AMS.Algorithm != algRSASHA256 {
			t.Errorf("set[%d].AMS.Algorithm = %q, want %q", i, s.AMS.Algorithm, algRSASHA256)
		}
	}

	// Verify timestamp (all have t=12345).
	for i, s := range sets {
		wantT := time.Unix(12345, 0)
		if !s.Seal.Timestamp.Equal(wantT) {
			t.Errorf("set[%d].Seal.Timestamp = %v, want %v", i, s.Seal.Timestamp, wantT)
		}
		if !s.AMS.Timestamp.Equal(wantT) {
			t.Errorf("set[%d].AMS.Timestamp = %v, want %v", i, s.AMS.Timestamp, wantT)
		}
	}
}
