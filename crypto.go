// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
)

// sign computes a signature over the given data using the Signer's key and algorithm.
func (s *Signer) sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	return s.key.Sign(rand.Reader, hash[:], s.hashOpt)
}

// algorithmForKey returns the signing algorithm and hash option for the given key type.
func algorithmForKey(key crypto.Signer, minBits int) (string, crypto.SignerOpts, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minBits {
			return "", nil, fmt.Errorf("%w: %d bits (minimum %d)", ErrRSAKeyTooSmall, k.N.BitLen(), minBits)
		}
		return algRSASHA256, crypto.SHA256, nil
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return algEd25519SHA256, crypto.Hash(0), nil
	default:
		return "", nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// computeBodyHash computes the SHA-256 hash of the canonicalized message body.
func computeBodyHash(body []byte) []byte {
	canon := canonicalizeBodyRelaxed(body)
	hash := sha256.Sum256(canon)
	return hash[:]
}
