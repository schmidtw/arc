// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"fmt"
	"strconv"
	"strings"
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

	common, err := parseCommonTags(val)
	if err != nil {
		return nil, fmt.Errorf("parsing AMS: %w", err)
	}

	result, err := common.toAMS()
	if err != nil {
		return nil, fmt.Errorf("parsing AMS: %w", err)
	}

	result.Raw = raw
	return result, nil
}

// parseArcSeal parses an ARC-Seal header field value.
func parseArcSeal(raw string) (*arcSeal, error) {
	val := unfoldHeader(raw)

	common, err := parseCommonTags(val)
	if err != nil {
		return nil, fmt.Errorf("parsing AS: %w", err)
	}

	result, err := common.toAS()
	if err != nil {
		return nil, fmt.Errorf("parsing AS: %w", err)
	}

	result.Raw = raw
	return result, nil
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
