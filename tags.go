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
	common, err := parseCommonTags(s)
	if err != nil {
		return amsTags{}, err
	}
	return common.toAMSTags()
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
	common, err := parseCommonTags(s)
	if err != nil {
		return asTags{}, err
	}
	return common.toASTags()
}

// keyRecordTags holds the parsed tags from a DKIM key record.
type keyRecordTags struct {
	Version string // optional, empty if not present
	KeyType string // optional, defaults to "rsa"
	Hash    string // optional, empty if not present
	PubKey  []byte
}

// commonTags holds the union of all possible tags that can appear in
// ARC-Message-Signature, ARC-Seal, and DKIM key record headers.
// This struct is parsed from raw tag-value strings without validation,
// then converted to specific tag types via conversion methods.
type commonTags struct {
	// Common fields across AMS and AS
	Instance int
	Algo     string
	Sig      []byte
	Domain   string
	Selector string
	Time     time.Time

	// AMS-specific fields
	BodyHash []byte
	Canon    string
	Headers  string

	// AS-specific fields
	CV string

	// Key record-specific fields
	Version string
	KeyType string
	Hash    string
	PubKey  []byte
}

// parseCommonTags parses a tag-value list into a commonTags struct without validation.
// Duplicate tags return an error. Invalid base64 encodings or instance values return an error.
// Missing or extra tags are not validated - use conversion methods for validation.
func parseCommonTags(s string) (commonTags, error) {
	tags := commonTags{
		KeyType: "rsa", // default per RFC 6376 for key records
	}
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
			return commonTags{}, fmt.Errorf("duplicate tag: %q", key)
		}
		seen[key] = true

		switch key {
		case "i":
			i, err := parseInstanceValue(value)
			if err != nil {
				return commonTags{}, err
			}
			tags.Instance = i
		case "a":
			tags.Algo = value
		case "b":
			sig, err := decodeBase64Value(value)
			if err != nil {
				return commonTags{}, fmt.Errorf("invalid signature encoding: %w", err)
			}
			tags.Sig = sig
		case "bh":
			bh, err := decodeBase64Value(value)
			if err != nil {
				return commonTags{}, fmt.Errorf("invalid body hash encoding: %w", err)
			}
			tags.BodyHash = bh
		case "c":
			tags.Canon = value
		case "cv":
			tags.CV = value
		case "d":
			tags.Domain = value
		case "h":
			tags.Headers = value
			tags.Hash = value
		case "k":
			tags.KeyType = value
		case "p":
			pubKey, err := decodeBase64Value(value)
			if err != nil {
				return commonTags{}, fmt.Errorf("invalid public key encoding: %w", err)
			}
			tags.PubKey = pubKey
		case "s":
			tags.Selector = value
		case "t":
			ts, err := parseTimestampValue(value)
			if err != nil {
				return commonTags{}, err
			}
			tags.Time = ts
		case "v":
			tags.Version = value
		}
	}

	return tags, nil
}

// toAMSTags converts commonTags to amsTags, validating all required fields.
func (c commonTags) toAMSTags() (amsTags, error) {
	// Validate required fields
	if c.Instance == 0 {
		return amsTags{}, fmt.Errorf("missing required tag: i")
	}
	if c.Algo == "" {
		return amsTags{}, fmt.Errorf("missing required tag: a")
	}
	if len(c.Sig) == 0 {
		return amsTags{}, fmt.Errorf("missing required tag: b")
	}
	if len(c.BodyHash) == 0 {
		return amsTags{}, fmt.Errorf("missing required tag: bh")
	}
	if c.Canon == "" {
		return amsTags{}, fmt.Errorf("missing required tag: c")
	}
	if c.Domain == "" {
		return amsTags{}, fmt.Errorf("missing required tag: d")
	}
	if c.Headers == "" {
		return amsTags{}, fmt.Errorf("missing required tag: h")
	}
	if c.Selector == "" {
		return amsTags{}, fmt.Errorf("missing required tag: s")
	}

	return amsTags{
		Instance: c.Instance,
		Algo:     c.Algo,
		Sig:      c.Sig,
		BodyHash: c.BodyHash,
		Canon:    c.Canon,
		Domain:   c.Domain,
		Headers:  c.Headers,
		Selector: c.Selector,
		Time:     c.Time,
	}, nil
}

// toASTags converts commonTags to asTags, validating all required fields.
func (c commonTags) toASTags() (asTags, error) {
	// Check for forbidden fields
	if c.Headers != "" {
		return asTags{}, fmt.Errorf("AS contains forbidden h= tag")
	}

	// Validate required fields
	if c.Instance == 0 {
		return asTags{}, fmt.Errorf("missing required tag: i")
	}
	if c.Algo == "" {
		return asTags{}, fmt.Errorf("missing required tag: a")
	}
	if len(c.Sig) == 0 {
		return asTags{}, fmt.Errorf("missing required tag: b")
	}
	if c.CV == "" {
		return asTags{}, fmt.Errorf("missing required tag: cv")
	}
	if c.Domain == "" {
		return asTags{}, fmt.Errorf("missing required tag: d")
	}
	if c.Selector == "" {
		return asTags{}, fmt.Errorf("missing required tag: s")
	}

	return asTags{
		Instance: c.Instance,
		Algo:     c.Algo,
		Sig:      c.Sig,
		CV:       c.CV,
		Domain:   c.Domain,
		Selector: c.Selector,
		Time:     c.Time,
	}, nil
}

// toKeyRecordTags converts commonTags to keyRecordTags, validating all required fields.
func (c commonTags) toKeyRecordTags() (keyRecordTags, error) {
	// Validate required fields
	if len(c.PubKey) == 0 {
		return keyRecordTags{}, fmt.Errorf("missing required tag: p")
	}

	return keyRecordTags{
		Version: c.Version,
		KeyType: c.KeyType,
		Hash:    c.Hash,
		PubKey:  c.PubKey,
	}, nil
}

// parseKeyRecordTags parses the tag-value list from a DKIM key record.
func parseKeyRecordTags(s string) (keyRecordTags, error) {
	common, err := parseCommonTags(s)
	if err != nil {
		return keyRecordTags{}, err
	}
	return common.toKeyRecordTags()
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
