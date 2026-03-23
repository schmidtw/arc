// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAAR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		input      string
		wantInst   int
		wantServID string
		wantErr    bool
	}{
		{
			name:       "basic AAR",
			input:      "i=1; lists.example.org; spf=pass smtp.mfrom=jqd@d1.example",
			wantInst:   1,
			wantServID: "lists.example.org",
		},
		{
			name:       "AAR with multiple results",
			input:      "i=2; gmail.example; spf=fail; dkim=pass; dmarc=fail",
			wantInst:   2,
			wantServID: "gmail.example",
		},
		{
			name:       "AAR with folded header",
			input:      "i=1; lists.example.org; spf=pass\n smtp.mfrom=jqd@d1.example",
			wantInst:   1,
			wantServID: "lists.example.org",
		},
		{
			name:    "AAR missing instance",
			input:   "lists.example.org; spf=pass",
			wantErr: true,
		},
		{
			name:    "AAR instance out of range",
			input:   "i=0; lists.example.org; spf=pass",
			wantErr: true,
		},
		{
			name:    "AAR instance too high",
			input:   "i=51; lists.example.org; spf=pass",
			wantErr: true,
		},
		{
			name:    "AAR no semicolon",
			input:   "i=1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			aar, err := parseAAR(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantInst, aar.Instance)
			assert.Equal(t, tt.wantServID, aar.AuthServID)
		})
	}
}

func TestParseAMS(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		wantInst int
		wantAlgo string
		wantHash string
		wantDom  string
		wantSel  string
		wantHdrs []string
		wantErr  bool
	}{
		{
			name: "basic AMS",
			input: "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; " +
				"h=from:to:subject; s=selector1; t=12345; " +
				"bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; " +
				"b=dGVzdA==",
			wantInst: 1,
			wantAlgo: algoRSA,
			wantHash: hashSHA256,
			wantDom:  "example.org",
			wantSel:  "selector1",
			wantHdrs: []string{"from", "to", "subject"},
		},
		{
			name: "AMS with folded signature",
			input: "i=2; a=rsa-sha256; c=relaxed/relaxed;\n" +
				" d=example.org; h=from:to:subject; s=sel;\n" +
				" t=12345; bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=;\n" +
				" b=dGVz dA==",
			wantInst: 2,
			wantAlgo: algoRSA,
			wantHash: hashSHA256,
			wantDom:  "example.org",
			wantSel:  "sel",
			wantHdrs: []string{"from", "to", "subject"},
		},
		{
			name:    "AMS missing algorithm",
			input:   "i=1; d=example.org; h=from; s=sel; bh=dGVzdA==; b=dGVzdA==",
			wantErr: true,
		},
		{
			name:    "AMS missing body hash",
			input:   "i=1; a=rsa-sha256; d=example.org; h=from; s=sel; b=dGVzdA==",
			wantErr: true,
		},
		{
			name:    "AMS missing headers",
			input:   "i=1; a=rsa-sha256; d=example.org; s=sel; bh=dGVzdA==; b=dGVzdA==",
			wantErr: true,
		},
		{
			name:    "AMS missing selector",
			input:   "i=1; a=rsa-sha256; d=example.org; h=from; bh=dGVzdA==; b=dGVzdA==",
			wantErr: true,
		},
		{
			name:    "AMS missing domain",
			input:   "i=1; a=rsa-sha256; h=from; s=sel; bh=dGVzdA==; b=dGVzdA==",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ams, err := parseAMS(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantInst, ams.Instance)
			algo := tt.wantAlgo + "-" + tt.wantHash
			assert.Equal(t, algo, ams.Algorithm)
			assert.Equal(t, tt.wantDom, ams.Domain)
			assert.Equal(t, tt.wantSel, ams.Selector)
			assert.Equal(t, tt.wantHdrs, ams.Headers)
		})
	}
}

func TestParseArcSeal(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		input    string
		wantInst int
		wantCV   string
		wantErr  bool
	}{
		{
			name:     "basic AS with cv=none",
			input:    "i=1; a=rsa-sha256; cv=none; d=example.org; s=sel; t=12345; b=dGVzdA==",
			wantInst: 1,
			wantCV:   "none",
		},
		{
			name:     "AS with cv=pass",
			input:    "i=2; a=rsa-sha256; cv=pass; d=example.org; s=sel; t=12345; b=dGVzdA==",
			wantInst: 2,
			wantCV:   "pass",
		},
		{
			name:     "AS with cv=fail",
			input:    "i=3; a=rsa-sha256; cv=fail; d=example.org; s=sel; t=12345; b=dGVzdA==",
			wantInst: 3,
			wantCV:   "fail",
		},
		{
			name:    "AS with h= tag (forbidden)",
			input:   "i=1; a=rsa-sha256; cv=none; d=example.org; s=sel; t=12345; b=dGVzdA==; h=from",
			wantErr: true,
		},
		{
			name:    "AS with invalid cv value",
			input:   "i=1; a=rsa-sha256; cv=maybe; d=example.org; s=sel; t=12345; b=dGVzdA==",
			wantErr: true,
		},
		{
			name:    "AS missing cv",
			input:   "i=1; a=rsa-sha256; d=example.org; s=sel; t=12345; b=dGVzdA==",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			as, err := parseArcSeal(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantInst, as.Instance)
			assert.Equal(t, tt.wantCV, string(as.ChainValidation))
		})
	}
}

func TestParseAMSTimestamp(t *testing.T) {
	t.Parallel()
	input := "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; " +
		"h=from:to:subject; s=sel; t=1421348401; " +
		"bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=dGVzdA=="

	ams, err := parseAMS(input)
	require.NoError(t, err)

	want := time.Unix(1421348401, 0)
	assert.True(t, ams.Timestamp.Equal(want), "timestamp = %v, want %v", ams.Timestamp, want)
}

func TestCollectArcSets(t *testing.T) {
	t.Parallel()
	msg := `ARC-Seal: i=2; a=rsa-sha256; cv=pass; d=example2.com; s=sel2; t=12345; b=dGVzdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=example2.com; h=from:to:subject; s=sel2; t=12345; bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=dGVzdA==
ARC-Authentication-Results: i=2; example2.com; spf=fail
ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example1.com; s=sel1; t=12345; b=dGVzdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example1.com; h=from:to:subject; s=sel1; t=12345; bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=dGVzdA==
ARC-Authentication-Results: i=1; example1.com; spf=pass
From: test@example.com
To: dest@example.com
Subject: Test

Body here.
`

	parsed, err := parseMessage(strings.NewReader(msg))
	require.NoError(t, err)

	sets, err := collectArcSets(parsed)
	require.NoError(t, err)

	require.Len(t, sets, 2)

	// Should be sorted by instance.
	assert.Equal(t, 1, sets[0].Instance)
	assert.Equal(t, 2, sets[1].Instance)

	// Check completeness.
	for i, s := range sets {
		assert.NotNil(t, s.AAR, "sets[%d].AAR", i)
		assert.NotNil(t, s.AMS, "sets[%d].AMS", i)
		assert.NotNil(t, s.Seal, "sets[%d].Seal", i)
	}
}

func TestCollectArcSetsEmpty(t *testing.T) {
	t.Parallel()
	msg := `From: test@example.com
To: dest@example.com
Subject: Test

Body here.
`
	parsed, err := parseMessage(strings.NewReader(msg))
	require.NoError(t, err)

	sets, err := collectArcSets(parsed)
	require.NoError(t, err)

	require.Empty(t, sets)
}

func TestParseMessageHeadersAndBody(t *testing.T) {
	t.Parallel()
	msg := "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Hello\r\n\r\nBody content here.\r\n"

	parsed, err := parseMessage(strings.NewReader(msg))
	require.NoError(t, err)

	require.Len(t, parsed.Headers, 3)

	assert.Equal(t, "From", parsed.Headers[0].Key)
	assert.Contains(t, parsed.Headers[0].Value, "test@example.com")

	assert.Contains(t, string(parsed.Body), "Body content here.")
}

func TestParseMessageWithLongBodyLine(t *testing.T) {
	t.Parallel()
	// Test that messages with very long body lines don't cause scanner failures.
	// bufio.Scanner has a default token limit of 64KB, which could cause failures
	// if we continued scanning the body after finding headers.
	longLine := strings.Repeat("A", 100000) // 100KB line, exceeds scanner default
	msg := "From: test@example.com\r\nSubject: Test\r\n\r\n" + longLine + "\r\n"

	parsed, err := parseMessage(strings.NewReader(msg))
	require.NoError(t, err)

	require.Len(t, parsed.Headers, 2)
	assert.Equal(t, "From", parsed.Headers[0].Key)
	assert.Equal(t, "Subject", parsed.Headers[1].Key)

	// Body should contain the long line
	assert.Contains(t, string(parsed.Body), longLine)
}

func TestSerializeAARRoundTrip(t *testing.T) {
	t.Parallel()
	s := Signer{
		authServID: "lists.example.org",
	}
	hdr := s.serializeAAR(1, "spf=pass smtp.mfrom=jqd@d1.example")
	// Should start with the header name.
	assert.True(t, strings.HasPrefix(hdr, "ARC-Authentication-Results:"))
	assert.Contains(t, hdr, "i=1")
	assert.Contains(t, hdr, "lists.example.org")
}

// TestUnfoldHeaderRFC5322Compliance tests that unfoldHeader correctly implements
// RFC 5322 Section 2.2.3 (Long Header Fields) and Section 3.2.2 (Folding White Space).
//
// Per RFC 5322:
//   - Folding White Space (FWS) is defined as: CRLF WSP, where WSP is space (0x20) or tab (0x09)
//   - When unfolding: "Unfolding is accomplished by simply removing any CRLF that is
//     immediately followed by WSP"
//   - The WSP after the CRLF is NOT removed during unfolding
//   - Line breaks NOT followed by WSP are not folding and should be preserved as-is
func TestUnfoldHeaderRFC5322Compliance(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		description string
	}{
		{
			name:        "CRLF followed by space",
			input:       "Subject: This is a long\r\n subject line",
			expected:    "Subject: This is a long subject line",
			description: "RFC 5322: CRLF+SPACE is FWS - remove CRLF, keep space",
		},
		{
			name:        "CRLF followed by tab",
			input:       "Subject: This is a long\r\n\tsubject line",
			expected:    "Subject: This is a long\tsubject line",
			description: "RFC 5322: CRLF+TAB is FWS - remove CRLF, keep tab",
		},
		{
			name:        "LF followed by space (liberal parsing)",
			input:       "Subject: This is a long\n subject line",
			expected:    "Subject: This is a long subject line",
			description: "Liberal parsing: Accept LF+SPACE as FWS for robustness",
		},
		{
			name:        "LF followed by tab (liberal parsing)",
			input:       "Subject: This is a long\n\tsubject line",
			expected:    "Subject: This is a long\tsubject line",
			description: "Liberal parsing: Accept LF+TAB as FWS for robustness",
		},
		{
			name:        "Multiple spaces after CRLF",
			input:       "Subject: Test\r\n    continued with multiple spaces",
			expected:    "Subject: Test    continued with multiple spaces",
			description: "Only CRLF removed, all WSP characters preserved",
		},
		{
			name:        "Multiple continuation lines",
			input:       "Subject: First line\r\n second line\r\n third line",
			expected:    "Subject: First line second line third line",
			description: "Multiple FWS sequences handled correctly",
		},
		{
			name:        "Microsoft Exchange pattern - no value on first line",
			input:       "Message-ID:\r\n <value@example.com>",
			expected:    "Message-ID: <value@example.com>",
			description: "Header with no value on first line (Microsoft Exchange pattern)",
		},
		{
			name:        "CRLF not followed by WSP - preserved",
			input:       "Subject: Line one\r\nFrom: user@example.com",
			expected:    "Subject: Line one\r\nFrom: user@example.com",
			description: "CRLF NOT followed by WSP is not FWS, should be preserved",
		},
		{
			name:        "LF not followed by WSP - preserved",
			input:       "Subject: Line one\nFrom: user@example.com",
			expected:    "Subject: Line one\nFrom: user@example.com",
			description: "LF NOT followed by WSP is not FWS, should be preserved",
		},
		{
			name:        "Mixed WSP after folding",
			input:       "Subject: Test\r\n \t value",
			expected:    "Subject: Test \t value",
			description: "Mixed space and tab after CRLF - both preserved",
		},
		{
			name:        "Empty string",
			input:       "",
			expected:    "",
			description: "Empty input returns empty output",
		},
		{
			name:        "No folding present",
			input:       "Subject: Simple value",
			expected:    "Subject: Simple value",
			description: "Headers without folding are unchanged",
		},
		{
			name:        "Only WSP, no CRLF",
			input:       "Subject:   Multiple   spaces",
			expected:    "Subject:   Multiple   spaces",
			description: "WSP without CRLF is not FWS, preserved as-is",
		},
		{
			name:        "CRLF at end with no WSP after",
			input:       "Subject: Test value\r\n",
			expected:    "Subject: Test value\r\n",
			description: "Trailing CRLF not followed by WSP is preserved",
		},
		{
			name:        "Complex real-world header",
			input:       "Content-Type: multipart/alternative;\r\n\tboundary=\"_000_Example\"",
			expected:    "Content-Type: multipart/alternative;\tboundary=\"_000_Example\"",
			description: "Real-world MIME header with parameter on continuation line",
		},
		{
			name:        "ARC-Message-Signature with multiple folds",
			input:       "ARC-Message-Signature: i=1; a=rsa-sha256;\r\n c=relaxed/relaxed;\r\n d=example.com",
			expected:    "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com",
			description: "ARC header with multiple continuation lines",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unfoldHeader(tt.input)
			assert.Equal(t, tt.expected, got, tt.description)
		})
	}
}

// TestUnfoldHeaderEdgeCases tests edge cases and boundary conditions
func TestUnfoldHeaderEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Single CRLF with space",
			input:    "\r\n ",
			expected: " ",
		},
		{
			name:     "Only CRLF",
			input:    "\r\n",
			expected: "\r\n",
		},
		{
			name:     "CRLF space at start",
			input:    "\r\n Header: value",
			expected: " Header: value",
		},
		{
			name:     "Multiple CRLF+space sequences",
			input:    "A\r\n B\r\n C\r\n D",
			expected: "A B C D",
		},
		{
			name:     "Very long continuation",
			input:    "Start\r\n " + string(make([]byte, 1000)),
			expected: "Start " + string(make([]byte, 1000)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unfoldHeader(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestUnfoldHeaderPreservesNonFWS verifies that non-FWS line breaks are preserved
func TestUnfoldHeaderPreservesNonFWS(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "CRLF followed by letter",
			input:    "Line1\r\nLine2",
			expected: "Line1\r\nLine2",
		},
		{
			name:     "CRLF followed by number",
			input:    "Line1\r\n123",
			expected: "Line1\r\n123",
		},
		{
			name:     "LF followed by letter",
			input:    "Line1\nLine2",
			expected: "Line1\nLine2",
		},
		{
			name:     "Multiple non-FWS line breaks",
			input:    "A\r\nB\r\nC",
			expected: "A\r\nB\r\nC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unfoldHeader(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestUnfoldHeaderConsistency verifies that unfolding is idempotent and consistent
func TestUnfoldHeaderConsistency(t *testing.T) {
	input := "Subject: Test\r\n value\r\n continued"
	expected := "Subject: Test value continued"

	// Unfolding should be idempotent - applying it twice gives same result
	once := unfoldHeader(input)
	twice := unfoldHeader(once)

	assert.Equal(t, once, twice, "unfoldHeader should be idempotent")
	assert.Equal(t, expected, once)
}
