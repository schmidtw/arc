// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"
)

// Sign creates a new ARC Set and prepends it to the message.
// The message should be a raw email message (RFC 5322 format). It returns
// the message with the new ARC headers prepended. The authResults parameter
// is the authentication results string for the ARC-Authentication-Results
// header (e.g., "spf=pass; dkim=pass").
func (s *Signer) Sign(ctx context.Context, message io.Reader, authResults string) ([]byte, error) {
	msg, err := parseMessage(message)
	if err != nil {
		return nil, fmt.Errorf("parsing message: %w", err)
	}

	return s.signMessage(ctx, msg, authResults)
}

// SignBytes creates a new ARC Set and prepends it to the message bytes.
func (s *Signer) SignBytes(ctx context.Context, message []byte, authResults string) ([]byte, error) {
	return s.Sign(ctx, bytes.NewReader(message), authResults)
}

// generateAMS creates and signs the ARC-Message-Signature header.
func (s *Signer) generateAMS(msg *message, newInstance int, ts time.Time) (string, error) {
	bodyHash := computeBodyHash(msg.Body)
	signHeaders := filterSignHeaders(s.headers)
	amsForSigning := s.serializeAMSForSigning(newInstance, signHeaders, bodyHash, ts)
	amsData := buildAMSSignedDataForSigning(msg, signHeaders, amsForSigning)

	amsSig, err := s.sign(amsData)
	if err != nil {
		return "", fmt.Errorf("signing ARC-Message-Signature: %w", err)
	}

	return s.serializeAMS(newInstance, signHeaders, bodyHash, amsSig, ts), nil
}

// generateAS creates and signs the ARC-Seal header.
func (s *Signer) generateAS(sets []*arcSet, cv chainStatus, newInstance int, aarStr, amsStr string, ts time.Time) (string, error) {
	asForSigning := s.serializeArcSealForSigning(newInstance, string(cv), ts)

	// When the chain is broken, the seal only covers the new set's headers.
	sealSets := sets
	if cv == chainFail {
		sealSets = nil
	}
	asData := buildASSignedDataForSigning(sealSets, aarStr, amsStr, asForSigning)

	asSig, err := s.sign(asData)
	if err != nil {
		return "", fmt.Errorf("signing ARC-Seal: %w", err)
	}

	return s.serializeArcSeal(newInstance, string(cv), asSig, ts), nil
}

func (s *Signer) signMessage(ctx context.Context, msg *message, authResults string) ([]byte, error) {
	// Collect existing ARC sets.
	sets, err := collectArcSets(msg)
	if err != nil {
		return nil, fmt.Errorf("collecting ARC sets: %w", err)
	}

	// Determine new instance number.
	newInstance := len(sets) + 1
	if newInstance > s.maxArcSets {
		return nil, fmt.Errorf("instance limit reached (%d)", s.maxArcSets)
	}

	// Check existing chain status.
	cv := chainNone
	if len(sets) > 0 {
		highest := sets[len(sets)-1]
		if highest.Seal != nil && highest.Seal.ChainValidation == chainFail {
			return nil, fmt.Errorf("cannot seal: most recent ARC-Seal has cv=fail")
		}
		cv, _ = s.validator.validateMessage(ctx, msg)
	}

	ts := s.timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	aarStr := s.serializeAAR(newInstance, authResults)

	amsStr, err := s.generateAMS(msg, newInstance, ts)
	if err != nil {
		return nil, err
	}

	asStr, err := s.generateAS(sets, cv, newInstance, aarStr, amsStr, ts)
	if err != nil {
		return nil, err
	}

	// Prepend the new ARC Set to the message.
	var result bytes.Buffer
	result.WriteString(asStr + "\r\n")
	result.WriteString(amsStr + "\r\n")
	result.WriteString(aarStr + "\r\n")
	result.Write(msg.Raw)

	return result.Bytes(), nil
}

// serializeAAR produces a complete ARC-Authentication-Results header line.
func (s *Signer) serializeAAR(instance int, results string) string {
	tags := []string{
		fmt.Sprintf("i=%d", instance),
		s.authServID,
		results,
	}

	return "ARC-Authentication-Results: " + strings.Join(tags, "; ")
}

// serializeAMS produces a complete ARC-Message-Signature header line.
func (s *Signer) serializeAMS(instance int, headers []string, bodyHash, signature []byte, ts time.Time) string {
	tags := []string{
		fmt.Sprintf("a=%s", s.algorithm),
		fmt.Sprintf("b=%s", base64.StdEncoding.EncodeToString(signature)),
		fmt.Sprintf("bh=%s", base64.StdEncoding.EncodeToString(bodyHash)),
		"c=relaxed/relaxed",
		fmt.Sprintf("d=%s", s.domain),
		fmt.Sprintf("h=%s", strings.Join(headers, ":")),
		fmt.Sprintf("i=%d", instance),
		fmt.Sprintf("s=%s", s.selector),
		fmt.Sprintf("t=%d", ts.Unix()),
	}

	return "ARC-Message-Signature: " + strings.Join(tags, "; ")
}

// serializeAMSForSigning produces an ARC-Message-Signature header with an
// empty signature value, used as input to the signing computation.
func (s *Signer) serializeAMSForSigning(instance int, headers []string, bodyHash []byte, ts time.Time) string {

	tags := []string{
		fmt.Sprintf("a=%s", s.algorithm),
		"b=",
		fmt.Sprintf("bh=%s", base64.StdEncoding.EncodeToString(bodyHash)),
		"c=relaxed/relaxed",
		fmt.Sprintf("d=%s", s.domain),
		fmt.Sprintf("h=%s", strings.Join(headers, ":")),
		fmt.Sprintf("i=%d", instance),
		fmt.Sprintf("s=%s", s.selector),
		fmt.Sprintf("t=%d", ts.Unix()),
	}

	return "ARC-Message-Signature: " + strings.Join(tags, "; ")
}

// serializeArcSeal produces a complete ARC-Seal header line.
func (s *Signer) serializeArcSeal(instance int, cv string, signature []byte, ts time.Time) string {

	tags := []string{
		fmt.Sprintf("a=%s", s.algorithm),
		fmt.Sprintf("b=%s", base64.StdEncoding.EncodeToString(signature)),
		fmt.Sprintf("cv=%s", cv),
		fmt.Sprintf("d=%s", s.domain),
		fmt.Sprintf("i=%d", instance),
		fmt.Sprintf("s=%s", s.selector),
		fmt.Sprintf("t=%d", ts.Unix()),
	}

	return "ARC-Seal: " + strings.Join(tags, "; ")
}

// serializeArcSealForSigning produces an ARC-Seal header with an empty
// signature value, used as input to the signing computation.
func (s *Signer) serializeArcSealForSigning(instance int, cv string, ts time.Time) string {

	tags := []string{
		fmt.Sprintf("a=%s", s.algorithm),
		"b=",
		fmt.Sprintf("cv=%s", cv),
		fmt.Sprintf("d=%s", s.domain),
		fmt.Sprintf("i=%d", instance),
		fmt.Sprintf("s=%s", s.selector),
		fmt.Sprintf("t=%d", ts.Unix()),
	}

	return "ARC-Seal: " + strings.Join(tags, "; ")
}

// buildAMSSignedDataForSigning builds the data to be signed by the
// ARC-Message-Signature. Headers are processed in the order listed in
// signHeaders, each found bottom-up in the message.
func buildAMSSignedDataForSigning(msg *message, signHeaders []string, amsForSigning string) []byte {
	var buf bytes.Buffer

	used := make(map[int]bool)

	for _, hName := range signHeaders {
		hNameLower := strings.ToLower(hName)
		for i := len(msg.Headers) - 1; i >= 0; i-- {
			if used[i] {
				continue
			}
			if strings.ToLower(msg.Headers[i].Key) == hNameLower {
				used[i] = true
				canon := canonicalizeHeaderRelaxed(msg.Headers[i].Key, msg.Headers[i].Value)
				buf.WriteString(canon)
				buf.WriteString("\r\n")
				break
			}
		}
	}

	// Add the ARC-Message-Signature header with empty signature.
	canon := canonicalizeHeaderRelaxedRaw(amsForSigning)
	buf.WriteString(canon)

	return buf.Bytes()
}

// buildASSignedDataForSigning builds the data to be signed by the ARC-Seal.
// Headers are processed within each ARC Set in order: AAR, AMS, AS for
// each instance from 1 to N.
func buildASSignedDataForSigning(existingSets []*arcSet, aarStr, amsStr, asForSigning string) []byte {
	var buf bytes.Buffer

	// Existing sets: all three headers for each instance.
	for _, s := range existingSets {
		canon := canonicalizeHeaderRelaxedRaw(s.AAR.Raw)
		buf.WriteString(canon)
		buf.WriteString("\r\n")

		canon = canonicalizeHeaderRelaxedRaw(s.AMS.Raw)
		buf.WriteString(canon)
		buf.WriteString("\r\n")

		canon = canonicalizeHeaderRelaxedRaw(s.Seal.Raw)
		buf.WriteString(canon)
		buf.WriteString("\r\n")
	}

	// New set: AAR, AMS, and the AS with empty signature (no trailing CRLF).
	buf.WriteString(canonicalizeHeaderRelaxedRaw(aarStr))
	buf.WriteString("\r\n")

	buf.WriteString(canonicalizeHeaderRelaxedRaw(amsStr))
	buf.WriteString("\r\n")
	buf.WriteString(canonicalizeHeaderRelaxedRaw(asForSigning))

	return buf.Bytes()
}
