// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strings"
)

// parseKeyRecord parses a public key from a DKIM DNS TXT record value.
// The record is a semicolon-delimited tag-value list as defined by RFC 6376
// Section 3.6.1. A typical record looks like:
//
//	v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4...
//
// Supported key types are RSA ([*rsa.PublicKey]) and Ed25519
// ([ed25519.PublicKey]). If the key type tag (k=) is absent, RSA is assumed.
// An empty public key tag (p=) indicates the key has been revoked and
// returns an error.
func parseKeyRecord(record string) (crypto.PublicKey, error) {
	tags, err := parseKeyRecordTags(record)
	if err != nil {
		return nil, fmt.Errorf("parsing key record: %w", err)
	}

	// Check version if present.
	if tags.Version != "" && strings.TrimSpace(tags.Version) != "DKIM1" {
		return nil, fmt.Errorf("unsupported key record version: %q", tags.Version)
	}

	// If the key record restricts hash algorithms, SHA-256 must be listed
	// since it's the only hash algorithm we support.
	if tags.Hash != "" {
		hashes := strings.Split(tags.Hash, ":")
		found := false
		for _, hash := range hashes {
			if strings.TrimSpace(hash) == hashSHA256 {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("key record h= tag %q does not include sha256", tags.Hash)
		}
	}

	keyType := strings.TrimSpace(tags.KeyType)
	keyData := tags.PubKey

	switch keyType {
	case algoRSA:
		pub, err := x509.ParsePKIXPublicKey(keyData)
		if err != nil {
			// Try parsing as PKCS#1.
			rsaPub, err2 := x509.ParsePKCS1PublicKey(keyData)
			if err2 != nil {
				return nil, fmt.Errorf("parsing RSA public key: PKIX: %v, PKCS1: %v", err, err2)
			}
			return rsaPub, nil
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key record has k=rsa but key is %T", pub)
		}
		return rsaPub, nil
	case algoEd25519:
		if len(keyData) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid ed25519 key size: %d", len(keyData))
		}
		return ed25519.PublicKey(keyData), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %q", keyType)
	}
}
