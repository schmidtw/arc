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
	Headers  []string

	// AS-specific fields
	CV chainStatus

	// Key record-specific fields
	Version string
	KeyType string
	Hash    string
	PubKey  []byte
}

// parseTag parses a single tag key-value pair and updates the commonTags struct.
func (c *commonTags) parseTag(key, value string) error { // nolint:funlen
	var err error

	switch key {
	case "i":
		c.Instance, err = parseInstanceValue(value)
	case "a":
		if value != algRSASHA256 && value != algEd25519SHA256 {
			return fmt.Errorf("unsupported algorithm %q", value)
		}
		c.Algo = value
	case "b":
		c.Sig, err = decodeBase64Value(value)
		if err != nil {
			err = fmt.Errorf("invalid signature encoding: %w", err)
		}
	case "bh":
		c.BodyHash, err = decodeBase64Value(value)
		if err != nil {
			err = fmt.Errorf("invalid body hash encoding: %w", err)
		}
	case "c":
		if value != "relaxed/relaxed" {
			return fmt.Errorf("unsupported canonicalization %q: only relaxed/relaxed is supported", value)
		}
		c.Canon = value
	case "cv":
		if value != "none" && value != "pass" && value != "fail" {
			return fmt.Errorf("invalid cv value: %q", value)
		}
		c.CV = chainStatus(value)
	case "d":
		c.Domain = value
	case "h":
		c.Headers = parseHeaderList(value)
		c.Hash = value
	case "k":
		c.KeyType = value
	case "p":
		c.PubKey, err = decodeBase64Value(value)
		if err != nil {
			err = fmt.Errorf("invalid public key encoding: %w", err)
		}
	case "s":
		c.Selector = value
	case "t":
		c.Time, err = parseTimestampValue(value)
	case "v":
		c.Version = value
	}
	return err
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

		if err := tags.parseTag(key, value); err != nil {
			return commonTags{}, err
		}
	}

	return tags, nil
}

// toAMS converts commonTags to ams, validating all required fields.
func (c commonTags) toAMS() (*ams, error) {
	// Validate required fields
	if c.Instance == 0 {
		return nil, fmt.Errorf("missing required tag: i")
	}
	if c.Algo == "" {
		return nil, fmt.Errorf("missing required tag: a")
	}
	if len(c.Sig) == 0 {
		return nil, fmt.Errorf("missing required tag: b")
	}
	if len(c.BodyHash) == 0 {
		return nil, fmt.Errorf("missing required tag: bh")
	}
	if c.Canon == "" {
		return nil, fmt.Errorf("missing required tag: c")
	}
	if c.Domain == "" {
		return nil, fmt.Errorf("missing required tag: d")
	}
	if len(c.Headers) == 0 {
		return nil, fmt.Errorf("missing required tag: h")
	}
	if c.Selector == "" {
		return nil, fmt.Errorf("missing required tag: s")
	}

	return &ams{
		Instance:  c.Instance,
		Algorithm: c.Algo,
		Signature: c.Sig,
		BodyHash:  c.BodyHash,
		Canon:     c.Canon,
		Domain:    c.Domain,
		Headers:   c.Headers,
		Selector:  c.Selector,
		Timestamp: c.Time,
	}, nil
}

// toAS converts commonTags to arcSeal, validating all required fields.
func (c commonTags) toAS() (*arcSeal, error) {
	// Check for forbidden fields
	if len(c.Headers) != 0 {
		return nil, fmt.Errorf("AS contains forbidden h= tag")
	}

	// Validate required fields
	if c.Instance == 0 {
		return nil, fmt.Errorf("missing required tag: i")
	}
	if c.Algo == "" {
		return nil, fmt.Errorf("missing required tag: a")
	}
	if len(c.Sig) == 0 {
		return nil, fmt.Errorf("missing required tag: b")
	}
	if c.CV == "" {
		return nil, fmt.Errorf("missing required tag: cv")
	}
	if c.Domain == "" {
		return nil, fmt.Errorf("missing required tag: d")
	}
	if c.Selector == "" {
		return nil, fmt.Errorf("missing required tag: s")
	}

	return &arcSeal{
		Instance:        c.Instance,
		Algorithm:       c.Algo,
		Signature:       c.Sig,
		ChainValidation: c.CV,
		Domain:          c.Domain,
		Selector:        c.Selector,
		Timestamp:       c.Time,
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
	ts, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q: %w", value, err)
	}
	return time.Unix(ts, 0), nil
}
