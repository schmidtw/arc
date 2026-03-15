// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"fmt"
	"strings"
	"unicode"
)

// tagList represents a parsed tag-value list (semicolon-delimited key=value pairs).
// Tags are stored in insertion order and can be looked up by name.
type tagList struct {
	tags  []tag
	index map[string]int
}

// tag is a single tag=value pair.
type tag struct {
	Key   string
	Value string
}

// parseTagList parses a semicolon-delimited tag-value list.
// Format: tag1=value1; tag2=value2; ...
// Tag names are case-sensitive and consist of alphanumeric characters
// and underscores. Duplicate tags cause an error.
func parseTagList(s string) (tagList, error) {
	tl := tagList{
		index: make(map[string]int),
	}

	// Empty string produces an empty tag list.
	s = strings.TrimSpace(s)
	if s == "" {
		return tl, nil
	}

	for pair := range strings.SplitSeq(s, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return tagList{}, fmt.Errorf("invalid tag-value pair (missing '='): %q", pair)
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if !isValidTagName(key) {
			return tagList{}, fmt.Errorf("invalid tag name: %q", key)
		}

		if _, exists := tl.index[key]; exists {
			return tagList{}, fmt.Errorf("duplicate tag: %q", key)
		}

		tl.index[key] = len(tl.tags)
		tl.tags = append(tl.tags, tag{Key: key, Value: value})
	}

	return tl, nil
}

// Get returns the value for the given tag name and whether it was found.
func (tl *tagList) Get(key string) (string, bool) {
	idx, ok := tl.index[key]
	if !ok {
		return "", false
	}
	return tl.tags[idx].Value, true
}

// Require returns the value for the given tag name or an error if missing.
func (tl *tagList) Require(key string) (string, error) {
	v, ok := tl.Get(key)
	if !ok {
		return "", fmt.Errorf("required tag %q not found", key)
	}
	return v, nil
}

// Tags returns all tags in insertion order.
func (tl *tagList) Tags() []tag {
	return tl.tags
}

// isValidTagName checks that a tag name matches [A-Za-z][A-Za-z0-9_]*.
func isValidTagName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if c > unicode.MaxASCII {
			return false
		}

		if i == 0 {
			if !unicode.IsLetter(c) {
				return false
			}
		} else {
			if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' {
				return false
			}
		}
	}
	return true
}
