// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"fmt"
	"strings"
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
func parseTagList(s string) (*tagList, error) {
	tl := &tagList{
		index: make(map[string]int),
	}

	// Empty string produces an empty tag list.
	s = strings.TrimSpace(s)
	if s == "" {
		return tl, nil
	}

	pairs := strings.Split(s, ";")
	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		eqIdx := strings.IndexByte(pair, '=')
		if eqIdx < 0 {
			return nil, fmt.Errorf("invalid tag-value pair (missing '='): %q", pair)
		}

		key := strings.TrimSpace(pair[:eqIdx])
		value := strings.TrimSpace(pair[eqIdx+1:])

		if key == "" {
			return nil, fmt.Errorf("empty tag name in pair: %q", pair)
		}

		if !isValidTagName(key) {
			return nil, fmt.Errorf("invalid tag name: %q", key)
		}

		if _, exists := tl.index[key]; exists {
			return nil, fmt.Errorf("duplicate tag: %q", key)
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
	if len(name) == 0 {
		return false
	}
	for i, c := range name {
		if i == 0 {
			if !isAlpha(byte(c)) { //nolint:gosec // Safe conversion for ASCII
				return false
			}
		} else {
			if !isAlpha(byte(c)) && !isDigit(byte(c)) && c != '_' { //nolint:gosec // Safe conversion for ASCII
				return false
			}
		}
	}
	return true
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
