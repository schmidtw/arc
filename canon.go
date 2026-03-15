// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"bytes"
	"strings"
)

// canonicalizeHeaderRelaxed applies relaxed header canonicalization:
//   - Convert header name to lowercase
//   - Unfold header value (remove CRLF before whitespace)
//   - Compress whitespace sequences to a single space
//   - Remove leading/trailing whitespace
//   - Remove whitespace before and after the colon
func canonicalizeHeaderRelaxed(name, value string) string {
	// Lowercase the header name.
	name = strings.ToLower(name)

	// Unfold: remove CRLF/LF followed by whitespace.
	value = unfoldHeader(value)

	// Compress whitespace sequences to a single space.
	value = compressWSP(value)

	// Trim leading/trailing whitespace from value.
	value = strings.TrimSpace(value)

	return name + ":" + value
}

// canonicalizeHeaderRelaxedRaw applies relaxed header canonicalization to a
// raw header line (including the "Name: Value" format).
func canonicalizeHeaderRelaxedRaw(raw string) string {
	colonIdx := strings.IndexByte(raw, ':')
	if colonIdx < 0 {
		// Shouldn't happen with valid headers.
		return strings.ToLower(strings.TrimSpace(raw))
	}

	name := raw[:colonIdx]
	value := raw[colonIdx+1:]

	return canonicalizeHeaderRelaxed(name, value)
}

// canonicalizeBodyRelaxed applies relaxed body canonicalization:
//   - Reduce whitespace sequences within a line to a single space
//   - Remove trailing whitespace at end of each line
//   - Remove all empty lines at the end of the body
//   - Ensure CRLF line endings
//
// If the body is empty, it returns an empty byte slice (not even CRLF).
func canonicalizeBodyRelaxed(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}

	// Split into lines. Handle both \r\n and \n line endings.
	var lines []string
	remaining := string(body)
	for len(remaining) > 0 {
		idx := strings.IndexByte(remaining, '\n')
		if idx < 0 {
			// Last line without newline.
			lines = append(lines, remaining)
			break
		}
		line := remaining[:idx]
		// Strip \r if present.
		line = strings.TrimRight(line, "\r")
		lines = append(lines, line)
		remaining = remaining[idx+1:]
	}

	// Process each line: compress whitespace, remove trailing whitespace.
	for i := range lines {
		lines[i] = compressWSP(lines[i])
		lines[i] = strings.TrimRight(lines[i], " \t")
	}

	// Remove empty lines at end.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if len(lines) == 0 {
		return nil
	}

	// Join with CRLF and add trailing CRLF.
	var buf bytes.Buffer
	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}

	return buf.Bytes()
}

// compressWSP replaces sequences of spaces and tabs with a single space.
func compressWSP(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inWSP := false
	for _, c := range s {
		if c == ' ' || c == '\t' {
			if !inWSP {
				b.WriteByte(' ')
				inWSP = true
			}
		} else {
			b.WriteRune(c)
			inWSP = false
		}
	}
	return b.String()
}
