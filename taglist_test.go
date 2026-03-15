// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"testing"
)

func TestParseTagList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []tag
		wantErr bool
	}{
		{
			name:  "standard tag-value list",
			input: "a=rsa-sha256; d=example.com; s=sel1",
			want: []tag{
				{Key: "a", Value: "rsa-sha256"},
				{Key: "d", Value: "example.com"},
				{Key: "s", Value: "sel1"},
			},
		},
		{
			name:  "whitespace around delimiters",
			input: " a = rsa-sha256 ; d = example.com ; s = sel1 ",
			want: []tag{
				{Key: "a", Value: "rsa-sha256"},
				{Key: "d", Value: "example.com"},
				{Key: "s", Value: "sel1"},
			},
		},
		{
			name:  "trailing semicolon",
			input: "a=rsa-sha256; d=example.com;",
			want: []tag{
				{Key: "a", Value: "rsa-sha256"},
				{Key: "d", Value: "example.com"},
			},
		},
		{
			name:  "empty value",
			input: "a=; d=example.com",
			want: []tag{
				{Key: "a", Value: ""},
				{Key: "d", Value: "example.com"},
			},
		},
		{
			name:  "single tag",
			input: "a=rsa-sha256",
			want: []tag{
				{Key: "a", Value: "rsa-sha256"},
			},
		},
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "whitespace only",
			input: "   ",
			want:  nil,
		},
		{
			name:  "value with spaces",
			input: "b=abc def ghi",
			want: []tag{
				{Key: "b", Value: "abc def ghi"},
			},
		},
		{
			name:  "value with equals sign",
			input: "b=abc=def=",
			want: []tag{
				{Key: "b", Value: "abc=def="},
			},
		},
		{
			name:    "duplicate tags",
			input:   "a=1; a=2",
			wantErr: true,
		},
		{
			name:    "missing equals",
			input:   "a",
			wantErr: true,
		},
		{
			name:    "empty tag name",
			input:   "=value",
			wantErr: true,
		},
		{
			name:    "invalid tag name - starts with digit",
			input:   "1a=value",
			wantErr: true,
		},
		{
			name:    "invalid tag name - special char",
			input:   "a.b=value",
			wantErr: true,
		},
		{
			name:  "tag name with underscore",
			input: "a_b=value",
			want: []tag{
				{Key: "a_b", Value: "value"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tl, err := parseTagList(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tags := tl.Tags()
			if len(tags) != len(tt.want) {
				t.Fatalf("got %d tags, want %d", len(tags), len(tt.want))
			}
			for i, got := range tags {
				if got.Key != tt.want[i].Key || got.Value != tt.want[i].Value {
					t.Errorf("tag[%d] = {%q, %q}, want {%q, %q}",
						i, got.Key, got.Value, tt.want[i].Key, tt.want[i].Value)
				}
			}
		})
	}
}

func TestIsValidTagName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{name: "single letter", input: "a", want: true},
		{name: "uppercase letter", input: "A", want: true},
		{name: "letters only", input: "abc", want: true},
		{name: "mixed case", input: "aBcD", want: true},
		{name: "letter then digits", input: "a123", want: true},
		{name: "letter then underscore", input: "a_b", want: true},
		{name: "letter digits underscore", input: "cv_2", want: true},
		{name: "empty string", input: "", want: false},
		{name: "starts with digit", input: "1a", want: false},
		{name: "starts with underscore", input: "_a", want: false},
		{name: "contains dot", input: "a.b", want: false},
		{name: "contains hyphen", input: "a-b", want: false},
		{name: "contains space", input: "a b", want: false},
		{name: "contains equals", input: "a=b", want: false},
		{name: "non-ASCII letter", input: "\u00e9", want: false},
		{name: "ASCII then non-ASCII", input: "a\u00e9", want: false},
		{name: "digit only", input: "0", want: false},
		{name: "underscore only", input: "_", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidTagName(tt.input); got != tt.want {
				t.Errorf("isValidTagName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTagListGet(t *testing.T) {
	tl, err := parseTagList("a=rsa-sha256; d=example.com; s=sel1")
	if err != nil {
		t.Fatal(err)
	}

	v, ok := tl.Get("a")
	if !ok || v != "rsa-sha256" {
		t.Errorf("Get(a) = %q, %v; want rsa-sha256, true", v, ok)
	}

	v, ok = tl.Get("d")
	if !ok || v != "example.com" {
		t.Errorf("Get(d) = %q, %v; want example.com, true", v, ok)
	}

	v, ok = tl.Get("missing")
	if ok {
		t.Errorf("Get(missing) = %q, %v; want '', false", v, ok)
	}
}

func TestTagListRequire(t *testing.T) {
	tl, err := parseTagList("a=rsa-sha256")
	if err != nil {
		t.Fatal(err)
	}

	v, err := tl.Require("a")
	if err != nil || v != "rsa-sha256" {
		t.Errorf("Require(a) = %q, %v; want rsa-sha256, nil", v, err)
	}

	_, err = tl.Require("missing")
	if err == nil {
		t.Error("Require(missing) should return error")
	}
}
