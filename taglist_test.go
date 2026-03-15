// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want, tl.Tags())
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
			assert.Equal(t, tt.want, isValidTagName(tt.input))
		})
	}
}

func TestTagListGet(t *testing.T) {
	tl, err := parseTagList("a=rsa-sha256; d=example.com; s=sel1")
	require.NoError(t, err)

	v, ok := tl.Get("a")
	assert.True(t, ok)
	assert.Equal(t, "rsa-sha256", v)

	v, ok = tl.Get("d")
	assert.True(t, ok)
	assert.Equal(t, "example.com", v)

	_, ok = tl.Get("missing")
	assert.False(t, ok)
}

func TestTagListRequire(t *testing.T) {
	tl, err := parseTagList("a=rsa-sha256")
	require.NoError(t, err)

	v, err := tl.Require("a")
	assert.NoError(t, err)
	assert.Equal(t, "rsa-sha256", v)

	_, err = tl.Require("missing")
	assert.Error(t, err)
}
