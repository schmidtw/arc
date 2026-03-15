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

// parseInstance extracts and validates the instance value from a tag list.
func parseInstance(tl tagList) (int, error) {
	iStr, err := tl.Require("i")
	if err != nil {
		return 0, fmt.Errorf("missing instance tag: %w", err)
	}
	i, err := strconv.Atoi(strings.TrimSpace(iStr))
	if err != nil {
		return 0, fmt.Errorf("invalid instance value %q: %w", iStr, err)
	}
	if i < 1 || i > 50 {
		return 0, fmt.Errorf("instance value %d out of range [1, 50]", i)
	}
	return i, nil
}

// parseTimestamp parses a timestamp tag value (Unix seconds).
func parseTimestamp(tl tagList) (time.Time, error) {
	tStr, ok := tl.Get("t")
	if !ok {
		return time.Time{}, nil
	}
	ts, err := strconv.ParseInt(strings.TrimSpace(tStr), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid timestamp %q: %w", tStr, err)
	}
	return time.Unix(ts, 0), nil
}

// decodeBase64Tag decodes a base64-encoded tag value, ignoring whitespace.
func decodeBase64Tag(val string) ([]byte, error) {
	// Remove all whitespace (folding whitespace is allowed in base64 values).
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, val)
	return base64.StdEncoding.DecodeString(cleaned)
}

// parseAAR parses an ARC-Authentication-Results header field value.
// Format: i=N; authserv-id; results...
func parseAAR(raw string) (*aar, error) {
	// The AAR has an "i=N;" prefix followed by Authentication-Results
	// content. Parse the instance tag first, then treat the remainder
	// as the auth results.

	// Unfold: collapse CRLF + whitespace continuations.
	val := unfoldHeader(raw)

	// Find first semicolon after the instance tag.
	semicolonIdx := strings.IndexByte(val, ';')
	if semicolonIdx < 0 {
		return nil, fmt.Errorf("AAR missing semicolon after instance tag")
	}

	// Parse instance.
	iPart := strings.TrimSpace(val[:semicolonIdx])
	tl, err := parseTagList(iPart)
	if err != nil {
		return nil, fmt.Errorf("parsing AAR instance: %w", err)
	}
	instance, err := parseInstance(tl)
	if err != nil {
		return nil, err
	}

	// The rest after the first semicolon is the auth results.
	rest := strings.TrimSpace(val[semicolonIdx+1:])

	// The authserv-id is the first token before any semicolon in the rest.
	authServID := rest
	resultsPart := ""
	if idx := strings.IndexByte(rest, ';'); idx >= 0 {
		authServID = strings.TrimSpace(rest[:idx])
		resultsPart = strings.TrimSpace(rest[idx+1:])
	}

	return &aar{
		Instance:   instance,
		AuthServID: authServID,
		Results:    resultsPart,
		Raw:        raw,
	}, nil
}

// parseAMS parses an ARC-Message-Signature header field value.
func parseAMS(raw string) (*ams, error) {
	val := unfoldHeader(raw)

	tl, err := parseTagList(val)
	if err != nil {
		return nil, fmt.Errorf("parsing AMS: %w", err)
	}

	instance, err := parseInstance(tl)
	if err != nil {
		return nil, err
	}

	algo, err := tl.Require("a")
	if err != nil {
		return nil, fmt.Errorf("AMS missing algorithm: %w", err)
	}

	bVal, err := tl.Require("b")
	if err != nil {
		return nil, fmt.Errorf("AMS missing signature: %w", err)
	}
	sig, err := decodeBase64Tag(bVal)
	if err != nil {
		return nil, fmt.Errorf("AMS invalid signature encoding: %w", err)
	}

	bhVal, err := tl.Require("bh")
	if err != nil {
		return nil, fmt.Errorf("AMS missing body hash: %w", err)
	}
	bh, err := decodeBase64Tag(bhVal)
	if err != nil {
		return nil, fmt.Errorf("AMS invalid body hash encoding: %w", err)
	}

	domain, err := tl.Require("d")
	if err != nil {
		return nil, fmt.Errorf("AMS missing domain: %w", err)
	}

	hVal, err := tl.Require("h")
	if err != nil {
		return nil, fmt.Errorf("AMS missing headers: %w", err)
	}
	headers := parseHeaderList(hVal)

	selector, err := tl.Require("s")
	if err != nil {
		return nil, fmt.Errorf("AMS missing selector: %w", err)
	}

	// Validate canonicalization. We only support relaxed/relaxed. Per DKIM
	// (RFC 6376 Section 3.5), the default when c= is absent is simple/simple,
	// which we do not implement.
	cVal, hasC := tl.Get("c")
	if !hasC {
		return nil, fmt.Errorf("AMS missing canonicalization (c= tag)")
	}
	cVal = strings.TrimSpace(cVal)
	if cVal != "relaxed/relaxed" {
		return nil, fmt.Errorf("AMS unsupported canonicalization %q: only relaxed/relaxed is supported", cVal)
	}

	ts, err := parseTimestamp(tl)
	if err != nil {
		return nil, err
	}

	return &ams{
		Instance:  instance,
		Algorithm: strings.TrimSpace(algo),
		Signature: sig,
		BodyHash:  bh,
		Domain:    strings.TrimSpace(domain),
		Headers:   headers,
		Selector:  strings.TrimSpace(selector),
		Timestamp: ts,
		Raw:       raw,
	}, nil
}

// parseArcSeal parses an ARC-Seal header field value.
func parseArcSeal(raw string) (*arcSeal, error) {
	val := unfoldHeader(raw)

	tl, err := parseTagList(val)
	if err != nil {
		return nil, fmt.Errorf("parsing AS: %w", err)
	}

	instance, err := parseInstance(tl)
	if err != nil {
		return nil, err
	}

	algo, err := tl.Require("a")
	if err != nil {
		return nil, fmt.Errorf("AS missing algorithm: %w", err)
	}

	bVal, err := tl.Require("b")
	if err != nil {
		return nil, fmt.Errorf("AS missing signature: %w", err)
	}
	sig, err := decodeBase64Tag(bVal)
	if err != nil {
		return nil, fmt.Errorf("AS invalid signature encoding: %w", err)
	}

	cv, err := tl.Require("cv")
	if err != nil {
		return nil, fmt.Errorf("AS missing chain validation: %w", err)
	}
	cv = strings.TrimSpace(cv)
	if cv != "none" && cv != "pass" && cv != "fail" {
		return nil, fmt.Errorf("AS invalid cv value: %q", cv)
	}

	domain, err := tl.Require("d")
	if err != nil {
		return nil, fmt.Errorf("AS missing domain: %w", err)
	}

	selector, err := tl.Require("s")
	if err != nil {
		return nil, fmt.Errorf("AS missing selector: %w", err)
	}

	// The ARC-Seal must not contain a signed headers (h=) tag.
	if _, ok := tl.Get("h"); ok {
		return nil, fmt.Errorf("AS contains forbidden h= tag")
	}

	ts, err := parseTimestamp(tl)
	if err != nil {
		return nil, err
	}

	return &arcSeal{
		Instance:        instance,
		Algorithm:       strings.TrimSpace(algo),
		Signature:       sig,
		ChainValidation: chainStatus(cv),
		Domain:          strings.TrimSpace(domain),
		Selector:        strings.TrimSpace(selector),
		Timestamp:       ts,
		Raw:             raw,
	}, nil
}

// parseHeaderList splits a colon-separated list of header names.
func parseHeaderList(val string) []string {
	parts := strings.Split(val, ":")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, strings.ToLower(p))
		}
	}
	return result
}

// unfoldHeader removes header folding (CRLF followed by whitespace).
func unfoldHeader(s string) string {
	s = strings.ReplaceAll(s, "\r\n ", " ")
	s = strings.ReplaceAll(s, "\r\n\t", " ")
	s = strings.ReplaceAll(s, "\n ", " ")
	s = strings.ReplaceAll(s, "\n\t", " ")
	return s
}
