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

// isExcludedHeader reports whether a lowercase header is in excludedHeaders.
func isExcludedHeader(lower HeaderField) bool {
	for k := range excludedHeaders {
		if strings.EqualFold(string(k), string(lower)) {
			return true
		}
	}
	return false
}
