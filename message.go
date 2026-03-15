// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
)

// header represents a single email header field.
type header struct {
	Key   string // Original case header name
	Value string // Value after the ": " (may contain folding)
	Raw   string // Complete raw line(s) including name, colon, and value
}

// message represents a parsed email message split into headers and body.
type message struct {
	Headers []header
	Body    []byte
	Raw     []byte
}

// parseMessage parses a raw RFC 5322 message into headers and body.
func parseMessage(r io.Reader) (*message, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return parseMessageBytes(raw)
}

// parseMessageBytes parses a raw RFC 5322 message from bytes.
func parseMessageBytes(raw []byte) (*message, error) {
	msg := &message{Raw: raw}

	// Normalize line endings to \r\n for processing.
	// But we keep the raw bytes as-is.
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	var headerLines []string
	var inBody bool
	var bodyStart int

	pos := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineLen := len(line) + 1 // +1 for newline consumed by scanner
		// Handle \r\n vs \n
		if pos+len(line)+2 <= len(raw) && raw[pos+len(line)] == '\r' && raw[pos+len(line)+1] == '\n' {
			lineLen = len(line) + 2
		}

		if !inBody {
			if line == "" || line == "\r" {
				inBody = true
				bodyStart = pos + lineLen
			} else {
				headerLines = append(headerLines, line)
			}
		}
		pos += lineLen
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Parse header lines (handling continuation lines).
	var current strings.Builder
	var currentKey string
	flush := func() {
		if currentKey != "" {
			rawHdr := current.String()
			value := rawHdr[len(currentKey)+1:] // skip "Key:"
			value = strings.TrimLeft(value, " \t")
			msg.Headers = append(msg.Headers, header{
				Key:   currentKey,
				Value: value,
				Raw:   rawHdr,
			})
		}
		current.Reset()
		currentKey = ""
	}

	for _, line := range headerLines {
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Continuation line.
			if currentKey != "" {
				current.WriteByte('\n')
				current.WriteString(line)
			}
		} else {
			flush()
			colonIdx := strings.IndexByte(line, ':')
			if colonIdx < 0 {
				// Malformed header line, treat as continuation of previous.
				if currentKey != "" {
					current.WriteByte('\n')
					current.WriteString(line)
				}
				continue
			}
			currentKey = line[:colonIdx]
			current.WriteString(line)
		}
	}
	flush()

	if inBody && bodyStart <= len(raw) {
		msg.Body = raw[bodyStart:]
	}

	return msg, nil
}

// collectArcSets extracts and groups ARC headers into arcSets.
// Returns sets ordered by instance number (ascending).
func collectArcSets(msg *message) ([]*arcSet, error) {
	sets := make(map[int]*arcSet)

	for _, h := range msg.Headers {
		key := strings.ToLower(h.Key)
		switch key {
		case "arc-authentication-results":
			aar, err := parseAAR(h.Value)
			if err != nil {
				return nil, fmt.Errorf("parsing AAR: %w", err)
			}
			aar.Raw = h.Raw
			s := getOrCreateSet(sets, aar.Instance)
			if s.AAR != nil {
				return nil, fmt.Errorf("duplicate AAR for instance %d", aar.Instance)
			}
			s.AAR = aar

		case "arc-message-signature":
			ams, err := parseAMS(h.Value)
			if err != nil {
				return nil, fmt.Errorf("parsing AMS: %w", err)
			}
			ams.Raw = h.Raw
			s := getOrCreateSet(sets, ams.Instance)
			if s.AMS != nil {
				return nil, fmt.Errorf("duplicate AMS for instance %d", ams.Instance)
			}
			s.AMS = ams

		case "arc-seal":
			as, err := parseArcSeal(h.Value)
			if err != nil {
				return nil, fmt.Errorf("parsing AS: %w", err)
			}
			as.Raw = h.Raw
			s := getOrCreateSet(sets, as.Instance)
			if s.Seal != nil {
				return nil, fmt.Errorf("duplicate AS for instance %d", as.Instance)
			}
			s.Seal = as
		}
	}

	if len(sets) == 0 {
		return nil, nil
	}

	// Convert to sorted slice.
	result := make([]*arcSet, 0, len(sets))
	for _, s := range sets {
		result = append(result, s)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Instance < result[j].Instance
	})

	return result, nil
}

func getOrCreateSet(sets map[int]*arcSet, instance int) *arcSet {
	s, ok := sets[instance]
	if !ok {
		s = &arcSet{Instance: instance}
		sets[instance] = s
	}
	return s
}
