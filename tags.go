// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// amsTags holds the parsed tags from an ARC-Message-Signature header.
type amsTags struct {
	Instance int
	Algo     string
	Sig      []byte
	BodyHash []byte
	Canon    string
	Domain   string
	Headers  string
	Selector string
	Time     time.Time // optional, zero value if not present
}

// parseAMSTags parses the tag-value list from an ARC-Message-Signature header.
func parseAMSTags(s string) (amsTags, error) {
	tags := amsTags{}
	seen := make(map[string]bool)

	pairs := splitTagValue(s)
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue // skip malformed pairs
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if seen[key] {
			return amsTags{}, fmt.Errorf("duplicate tag: %q", key)
		}
		seen[key] = true

		switch key {
		case "i":
			i, err := parseInstanceValue(value)
			if err != nil {
				return amsTags{}, err
			}
			tags.Instance = i
		case "a":
			tags.Algo = value
		case "b":
			sig, err := decodeBase64Value(value)
			if err != nil {
				return amsTags{}, fmt.Errorf("invalid signature encoding: %w", err)
			}
			tags.Sig = sig
		case "bh":
			bh, err := decodeBase64Value(value)
			if err != nil {
				return amsTags{}, fmt.Errorf("invalid body hash encoding: %w", err)
			}
			tags.BodyHash = bh
		case "c":
			tags.Canon = value
		case "d":
			tags.Domain = value
		case "h":
			tags.Headers = value
		case "s":
			tags.Selector = value
		case "t":
			ts, err := parseTimestampValue(value)
			if err != nil {
				return amsTags{}, err
			}
			tags.Time = ts
		}
	}

	// Validate required fields
	if tags.Instance == 0 {
		return amsTags{}, fmt.Errorf("missing required tag: i")
	}
	if tags.Algo == "" {
		return amsTags{}, fmt.Errorf("missing required tag: a")
	}
	if len(tags.Sig) == 0 {
		return amsTags{}, fmt.Errorf("missing required tag: b")
	}
	if len(tags.BodyHash) == 0 {
		return amsTags{}, fmt.Errorf("missing required tag: bh")
	}
	if tags.Canon == "" {
		return amsTags{}, fmt.Errorf("missing required tag: c")
	}
	if tags.Domain == "" {
		return amsTags{}, fmt.Errorf("missing required tag: d")
	}
	if tags.Headers == "" {
		return amsTags{}, fmt.Errorf("missing required tag: h")
	}
	if tags.Selector == "" {
		return amsTags{}, fmt.Errorf("missing required tag: s")
	}

	return tags, nil
}

// asTags holds the parsed tags from an ARC-Seal header.
type asTags struct {
	Instance int
	Algo     string
	Sig      []byte
	CV       string
	Domain   string
	Selector string
	Time     time.Time // optional, zero value if not present
}

// parseASTags parses the tag-value list from an ARC-Seal header.
func parseASTags(s string) (asTags, error) {
	tags := asTags{}
	seen := make(map[string]bool)

	pairs := splitTagValue(s)
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if seen[key] {
			return asTags{}, fmt.Errorf("duplicate tag: %q", key)
		}
		seen[key] = true

		switch key {
		case "i":
			i, err := parseInstanceValue(value)
			if err != nil {
				return asTags{}, err
			}
			tags.Instance = i
		case "a":
			tags.Algo = value
		case "b":
			sig, err := decodeBase64Value(value)
			if err != nil {
				return asTags{}, fmt.Errorf("invalid signature encoding: %w", err)
			}
			tags.Sig = sig
		case "cv":
			tags.CV = value
		case "d":
			tags.Domain = value
		case "s":
			tags.Selector = value
		case "t":
			ts, err := parseTimestampValue(value)
			if err != nil {
				return asTags{}, err
			}
			tags.Time = ts
		case "h":
			return asTags{}, fmt.Errorf("AS contains forbidden h= tag")
		}
	}

	// Validate required fields
	if tags.Instance == 0 {
		return asTags{}, fmt.Errorf("missing required tag: i")
	}
	if tags.Algo == "" {
		return asTags{}, fmt.Errorf("missing required tag: a")
	}
	if len(tags.Sig) == 0 {
		return asTags{}, fmt.Errorf("missing required tag: b")
	}
	if tags.CV == "" {
		return asTags{}, fmt.Errorf("missing required tag: cv")
	}
	if tags.Domain == "" {
		return asTags{}, fmt.Errorf("missing required tag: d")
	}
	if tags.Selector == "" {
		return asTags{}, fmt.Errorf("missing required tag: s")
	}

	return tags, nil
}

// keyRecordTags holds the parsed tags from a DKIM key record.
type keyRecordTags struct {
	Version string // optional, empty if not present
	KeyType string // optional, defaults to "rsa"
	Hash    string // optional, empty if not present
	PubKey  []byte
}

// parseKeyRecordTags parses the tag-value list from a DKIM key record.
func parseKeyRecordTags(s string) (keyRecordTags, error) {
	tags := keyRecordTags{
		KeyType: "rsa", // default per RFC 6376
	}
	seen := make(map[string]bool)

	pairs := splitTagValue(s)
	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		if seen[key] {
			return keyRecordTags{}, fmt.Errorf("duplicate tag: %q", key)
		}
		seen[key] = true

		switch key {
		case "v":
			tags.Version = value
		case "k":
			tags.KeyType = value
		case "h":
			tags.Hash = value
		case "p":
			pubKey, err := decodeBase64Value(value)
			if err != nil {
				return keyRecordTags{}, fmt.Errorf("invalid public key encoding: %w", err)
			}
			tags.PubKey = pubKey
		}
	}

	// Validate required fields
	if len(tags.PubKey) == 0 {
		return keyRecordTags{}, fmt.Errorf("missing required tag: p")
	}

	return tags, nil
}

// splitTagValue splits a semicolon-delimited tag-value list into pairs.
func splitTagValue(s string) []string {
	var pairs []string
	for pair := range strings.SplitSeq(s, ";") {
		pair = strings.TrimSpace(pair)
		if pair != "" {
			pairs = append(pairs, pair)
		}
	}
	return pairs
}

// parseInstanceValue validates and parses an instance value string.
func parseInstanceValue(value string) (int, error) {
	i, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid instance value %q: %w", value, err)
	}
	if i < 1 || i > 50 {
		return 0, fmt.Errorf("instance value %d out of range [1, 50]", i)
	}
	return i, nil
}

// decodeBase64Value decodes a base64-encoded tag value, ignoring whitespace.
func decodeBase64Value(val string) ([]byte, error) {
	// Remove all whitespace (folding whitespace is allowed in base64 values).
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, val)
	return base64.StdEncoding.DecodeString(cleaned)
}

// parseTimestampValue parses a timestamp tag value (Unix seconds).
func parseTimestampValue(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q: %w", value, err)
	}
	return time.Unix(ts, 0), nil
}
