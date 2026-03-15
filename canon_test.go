// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"testing"
)

func TestCanonicalizeHeaderRelaxed(t *testing.T) {
	tests := []struct {
		name  string
		hName string
		hVal  string
		want  string
	}{
		{
			name:  "lowercase header name",
			hName: "From",
			hVal:  " user@example.com",
			want:  "from:user@example.com",
		},
		{
			name:  "compress internal whitespace",
			hName: "Subject",
			hVal:  "  hello   world  ",
			want:  "subject:hello world",
		},
		{
			name:  "unfold multi-line value",
			hName: "To",
			hVal:  " user@example.com,\n other@example.com",
			want:  "to:user@example.com, other@example.com",
		},
		{
			name:  "tab to space",
			hName: "Subject",
			hVal:  "\thello\t\tworld",
			want:  "subject:hello world",
		},
		{
			name:  "CRLF folding",
			hName: "Subject",
			hVal:  " hello\r\n world",
			want:  "subject:hello world",
		},
		{
			name:  "trailing whitespace",
			hName: "From",
			hVal:  " user@example.com   ",
			want:  "from:user@example.com",
		},
		{
			name:  "mixed case header",
			hName: "ARC-Seal",
			hVal:  " i=1; a=rsa-sha256",
			want:  "arc-seal:i=1; a=rsa-sha256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalizeHeaderRelaxed(tt.hName, tt.hVal)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonicalizeHeaderRelaxedRaw(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "standard header",
			raw:  "From: user@example.com",
			want: "from:user@example.com",
		},
		{
			name: "folded header",
			raw:  "Subject: hello\n world",
			want: "subject:hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalizeHeaderRelaxedRaw(tt.raw)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCanonicalizeBodyRelaxed(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "simple body",
			body: "hello world\r\n",
			want: "hello world\r\n",
		},
		{
			name: "compress inline whitespace",
			body: "hello   world\r\n",
			want: "hello world\r\n",
		},
		{
			name: "trailing whitespace on line",
			body: "hello world   \r\n",
			want: "hello world\r\n",
		},
		{
			name: "trailing empty lines",
			body: "hello\r\n\r\n\r\n",
			want: "hello\r\n",
		},
		{
			name: "multiple lines",
			body: "line1\r\nline2\r\nline3\r\n",
			want: "line1\r\nline2\r\nline3\r\n",
		},
		{
			name: "empty body",
			body: "",
			want: "",
		},
		{
			name: "only whitespace lines",
			body: "   \r\n\t\r\n\r\n",
			want: "",
		},
		{
			name: "tab in body",
			body: "hello\tworld\r\n",
			want: "hello world\r\n",
		},
		{
			name: "LF-only line endings",
			body: "hello\nworld\n",
			want: "hello\r\nworld\r\n",
		},
		{
			name: "trailing empty lines with LF",
			body: "hello\n\n\n",
			want: "hello\r\n",
		},
		{
			name: "mixed content",
			body: "Hey gang,\r\nThis is a test message.\r\n--J.\r\n",
			want: "Hey gang,\r\nThis is a test message.\r\n--J.\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalizeBodyRelaxed([]byte(tt.body))
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", string(got), tt.want)
			}
		})
	}
}
