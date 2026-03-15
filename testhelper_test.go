// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// Test constants
const (
	rsaSHA256 = "rsa-sha256"
)

// sign wraps the Signer.sign method for test convenience.
func sign(key crypto.Signer, algorithm string, data []byte) ([]byte, error) {
	s := Signer{
		algorithm: algorithm,
		key:       key,
	}
	return s.sign(data)
}

// serializeAAR creates an ARC-Authentication-Results header string
func serializeAAR(instance int, authServID, results string) string {
	return fmt.Sprintf("ARC-Authentication-Results: i=%d; %s; %s", instance, authServID, results)
}

// serializeAMSForSigning creates an ARC-Message-Signature header for signing (b= empty)
func serializeAMSForSigning(instance int, algorithm, domain, selector string, headers []string, bodyHash []byte, ts time.Time) string {
	h := strings.Join(headers, ":")
	bh := base64.StdEncoding.EncodeToString(bodyHash)
	return fmt.Sprintf("ARC-Message-Signature: i=%d; a=%s; d=%s; s=%s; t=%d; h=%s; bh=%s; b=",
		instance, algorithm, domain, selector, ts.Unix(), h, bh)
}

// serializeAMS creates a complete ARC-Message-Signature header
func serializeAMS(instance int, algorithm, domain, selector string, headers []string, bodyHash, signature []byte, ts time.Time) string {
	h := strings.Join(headers, ":")
	bh := base64.StdEncoding.EncodeToString(bodyHash)
	b := base64.StdEncoding.EncodeToString(signature)
	return fmt.Sprintf("ARC-Message-Signature: i=%d; a=%s; d=%s; s=%s; t=%d; h=%s; bh=%s; b=%s",
		instance, algorithm, domain, selector, ts.Unix(), h, bh, b)
}

// serializeArcSealForSigning creates an ARC-Seal header for signing (b= empty)
func serializeArcSealForSigning(instance int, algorithm, domain, selector string, cv string, ts time.Time) string {
	return fmt.Sprintf("ARC-Seal: i=%d; a=%s; d=%s; s=%s; t=%d; cv=%s; b=",
		instance, algorithm, domain, selector, ts.Unix(), cv)
}

// serializeArcSeal creates a complete ARC-Seal header
func serializeArcSeal(instance int, algorithm, domain, selector string, cv string, signature []byte, ts time.Time) string {
	b := base64.StdEncoding.EncodeToString(signature)
	return fmt.Sprintf("ARC-Seal: i=%d; a=%s; d=%s; s=%s; t=%d; cv=%s; b=%s",
		instance, algorithm, domain, selector, ts.Unix(), cv, b)
}

// toHeaderFields converts a slice of strings to a slice of HeaderField.
func toHeaderFields(ss []string) []HeaderField {
	hf := make([]HeaderField, len(ss))
	for i, s := range ss {
		hf[i] = HeaderField(s)
	}
	return hf
}
