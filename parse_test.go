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
	input := "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; " +
		"h=from:to:subject; s=sel; t=1421348401; " +
		"bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=dGVzdA=="

	ams, err := parseAMS(input)
	require.NoError(t, err)

	want := time.Unix(1421348401, 0)
	assert.True(t, ams.Timestamp.Equal(want), "timestamp = %v, want %v", ams.Timestamp, want)
}

func TestCollectArcSets(t *testing.T) {
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
	msg := "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Hello\r\n\r\nBody content here.\r\n"

	parsed, err := parseMessage(strings.NewReader(msg))
	require.NoError(t, err)

	require.Len(t, parsed.Headers, 3)

	assert.Equal(t, "From", parsed.Headers[0].Key)
	assert.Contains(t, parsed.Headers[0].Value, "test@example.com")

	assert.Contains(t, string(parsed.Body), "Body content here.")
}

func TestParseMessageWithLongBodyLine(t *testing.T) {
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
	s := Signer{
		authServID: "lists.example.org",
	}
	hdr := s.serializeAAR(1, "spf=pass smtp.mfrom=jqd@d1.example")
	// Should start with the header name.
	assert.True(t, strings.HasPrefix(hdr, "ARC-Authentication-Results:"))
	assert.Contains(t, hdr, "i=1")
	assert.Contains(t, hdr, "lists.example.org")
}

func TestFoldHeader(t *testing.T) {
	short := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=ex.com; s=s; b=dGVzdA=="
	folded := foldHeader(short)
	assert.Equal(t, short, folded)

	long := "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from:to:subject:date:message-id; s=selector; t=12345678; bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=dGVzdHNpZ25hdHVyZXZhbHVlaGVyZQ=="
	folded = foldHeader(long)
	for _, line := range strings.Split(folded, "\r\n") {
		assert.LessOrEqual(t, len(line), 78, "line: %q", line)
	}
}
