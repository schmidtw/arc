// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"strings"
	"testing"
	"time"
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
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if aar.Instance != tt.wantInst {
				t.Errorf("instance = %d, want %d", aar.Instance, tt.wantInst)
			}
			if aar.AuthServID != tt.wantServID {
				t.Errorf("authServID = %q, want %q", aar.AuthServID, tt.wantServID)
			}
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
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ams.Instance != tt.wantInst {
				t.Errorf("instance = %d, want %d", ams.Instance, tt.wantInst)
			}
			algo := tt.wantAlgo + "-" + tt.wantHash
			if ams.Algorithm != algo {
				t.Errorf("algorithm = %q, want %q", ams.Algorithm, algo)
			}
			if ams.Domain != tt.wantDom {
				t.Errorf("domain = %q, want %q", ams.Domain, tt.wantDom)
			}
			if ams.Selector != tt.wantSel {
				t.Errorf("selector = %q, want %q", ams.Selector, tt.wantSel)
			}
			if len(ams.Headers) != len(tt.wantHdrs) {
				t.Fatalf("headers = %v, want %v", ams.Headers, tt.wantHdrs)
			}
			for i, h := range ams.Headers {
				if h != tt.wantHdrs[i] {
					t.Errorf("header[%d] = %q, want %q", i, h, tt.wantHdrs[i])
				}
			}
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
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if as.Instance != tt.wantInst {
				t.Errorf("instance = %d, want %d", as.Instance, tt.wantInst)
			}
			if string(as.ChainValidation) != tt.wantCV {
				t.Errorf("cv = %q, want %q", as.ChainValidation, tt.wantCV)
			}
		})
	}
}

func TestParseAMSTimestamp(t *testing.T) {
	input := "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; " +
		"h=from:to:subject; s=sel; t=1421348401; " +
		"bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=dGVzdA=="

	ams, err := parseAMS(input)
	if err != nil {
		t.Fatal(err)
	}

	want := time.Unix(1421348401, 0)
	if !ams.Timestamp.Equal(want) {
		t.Errorf("timestamp = %v, want %v", ams.Timestamp, want)
	}
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
	if err != nil {
		t.Fatal(err)
	}

	sets, err := collectArcSets(parsed)
	if err != nil {
		t.Fatal(err)
	}

	if len(sets) != 2 {
		t.Fatalf("got %d sets, want 2", len(sets))
	}

	// Should be sorted by instance.
	if sets[0].Instance != 1 {
		t.Errorf("sets[0].Instance = %d, want 1", sets[0].Instance)
	}
	if sets[1].Instance != 2 {
		t.Errorf("sets[1].Instance = %d, want 2", sets[1].Instance)
	}

	// Check completeness.
	for i, s := range sets {
		if s.AAR == nil {
			t.Errorf("sets[%d].AAR is nil", i)
		}
		if s.AMS == nil {
			t.Errorf("sets[%d].AMS is nil", i)
		}
		if s.Seal == nil {
			t.Errorf("sets[%d].Seal is nil", i)
		}
	}
}

func TestCollectArcSetsEmpty(t *testing.T) {
	msg := `From: test@example.com
To: dest@example.com
Subject: Test

Body here.
`
	parsed, err := parseMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}

	sets, err := collectArcSets(parsed)
	if err != nil {
		t.Fatal(err)
	}

	if len(sets) != 0 {
		t.Fatalf("got %d sets, want 0", len(sets))
	}
}

func TestParseMessageHeadersAndBody(t *testing.T) {
	msg := "From: test@example.com\r\nTo: dest@example.com\r\nSubject: Hello\r\n\r\nBody content here.\r\n"

	parsed, err := parseMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}

	if len(parsed.Headers) != 3 {
		t.Fatalf("got %d headers, want 3", len(parsed.Headers))
	}

	if parsed.Headers[0].Key != "From" {
		t.Errorf("header[0].Key = %q, want From", parsed.Headers[0].Key)
	}
	if !strings.Contains(parsed.Headers[0].Value, "test@example.com") {
		t.Errorf("header[0].Value = %q, missing test@example.com", parsed.Headers[0].Value)
	}

	if !strings.Contains(string(parsed.Body), "Body content here.") {
		t.Errorf("body = %q, missing expected content", string(parsed.Body))
	}
}

func TestSerializeAARRoundTrip(t *testing.T) {
	s := Signer{
		authServID: "lists.example.org",
	}
	hdr := s.serializeAAR(1, "spf=pass smtp.mfrom=jqd@d1.example")
	// Should start with the header name.
	if !strings.HasPrefix(hdr, "ARC-Authentication-Results:") {
		t.Errorf("unexpected prefix: %q", hdr)
	}
	if !strings.Contains(hdr, "i=1") {
		t.Error("missing instance tag")
	}
	if !strings.Contains(hdr, "lists.example.org") {
		t.Error("missing authserv-id")
	}
}

func TestFoldHeader(t *testing.T) {
	short := "ARC-Seal: i=1; a=rsa-sha256; cv=none; d=ex.com; s=s; b=dGVzdA=="
	folded := foldHeader(short)
	if folded != short {
		t.Errorf("short header should not be folded: %q", folded)
	}

	long := "ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.org; h=from:to:subject:date:message-id; s=selector; t=12345678; bh=KWSe46TZKCcDbH4klJPo+tjk5LWJnVRlP5pvjXFZYLQ=; b=dGVzdHNpZ25hdHVyZXZhbHVlaGVyZQ=="
	folded = foldHeader(long)
	for _, line := range strings.Split(folded, "\r\n") {
		if len(line) > 78 {
			t.Errorf("folded line too long (%d): %q", len(line), line)
		}
	}
}
