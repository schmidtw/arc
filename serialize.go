// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"strings"
)

// filterSignHeaders removes excluded headers from the signing list and
// converts the remaining names to lowercase.
func filterSignHeaders(headers []HeaderField) []string {
	var filtered []string
	for _, h := range headers {
		lower := strings.ToLower(string(h))
		if isExcludedHeader(HeaderField(lower)) {
			continue
		}
		filtered = append(filtered, lower)
	}
	return filtered
}

// isExcludedHeader reports whether a lowercase header is in ExcludedHeaders.
func isExcludedHeader(lower HeaderField) bool {
	for k := range ExcludedHeaders {
		if strings.EqualFold(string(k), string(lower)) {
			return true
		}
	}
	return false
}

// foldHeader folds a header line at the 78-character boundary.
// It inserts CRLF + space at appropriate points.
func foldHeader(header string) string {
	if len(header) <= 78 {
		return header
	}

	var b strings.Builder
	remaining := header
	lineLen := 0

	for len(remaining) > 0 {
		if lineLen == 0 {
			// Start of a new line (first or continuation).
			// Find a good break point.
			if b.Len() > 0 {
				b.WriteString("\r\n ")
				lineLen = 1
			}
		}

		available := 78 - lineLen
		if available <= 0 {
			available = 1
		}

		if len(remaining) <= available {
			b.WriteString(remaining)
			break
		}

		// Find last good break point within available chars.
		breakAt := -1
		for i := available; i >= 1; i-- {
			if remaining[i] == ' ' || remaining[i] == ';' {
				breakAt = i
				break
			}
		}

		if breakAt <= 0 {
			// No good break point - write up to available.
			breakAt = available
		}

		b.WriteString(remaining[:breakAt])
		remaining = remaining[breakAt:]
		lineLen = 0
	}

	return b.String()
}
