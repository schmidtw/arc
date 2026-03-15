// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
)

const minRSAKeyBits = 1024

// sign computes a signature over the given data using the Signer's key and algorithm.
func (s *Signer) sign(data []byte) ([]byte, error) {
	switch s.algorithm {
	case algRSASHA256:
		rsaKey, ok := s.key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("algorithm %q requires RSA key, got %T", s.algorithm, s.key)
		}
		if rsaKey.N.BitLen() < minRSAKeyBits {
			return nil, fmt.Errorf("RSA key too small: %d bits (minimum %d)", rsaKey.N.BitLen(), minRSAKeyBits)
		}
		hash := sha256.Sum256(data)
		return rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])

	case algEd25519SHA256:
		edKey, ok := s.key.(ed25519.PrivateKey)
		if !ok {
			if ptr, ok2 := s.key.(*ed25519.PrivateKey); ok2 {
				edKey = *ptr
			} else {
				return nil, fmt.Errorf("algorithm %q requires Ed25519 key, got %T", s.algorithm, s.key)
			}
		}
		hash := sha256.Sum256(data)
		return ed25519.Sign(edKey, hash[:]), nil

	default:
		return nil, fmt.Errorf("unsupported algorithm: %q", s.algorithm)
	}
}

// verify checks a signature over the given data using the provided public key
// and algorithm.
func verify(pubKey crypto.PublicKey, algorithm string, data, signature []byte) error {
	switch algorithm {
	case algRSASHA256:
		rsaKey, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %q requires RSA public key, got %T", algorithm, pubKey)
		}
		if rsaKey.N.BitLen() < minRSAKeyBits {
			return fmt.Errorf("RSA key too small: %d bits (minimum %d)", rsaKey.N.BitLen(), minRSAKeyBits)
		}
		hash := sha256.Sum256(data)
		if err := rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hash[:], signature); err != nil {
			return errors.Join(ErrInvalidSignature, err)
		}
		return nil

	case algEd25519SHA256:
		edKey, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("algorithm %q requires Ed25519 public key, got %T", algorithm, pubKey)
		}
		hash := sha256.Sum256(data)
		if !ed25519.Verify(edKey, hash[:], signature) {
			return errors.Join(ErrInvalidSignature, fmt.Errorf("ed25519 signature verification failed"))
		}
		return nil

	default:
		return fmt.Errorf("unsupported algorithm: %q", algorithm)
	}
}

// algorithmForKey returns the signing algorithm for the given key type.
func algorithmForKey(key crypto.Signer) (string, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return algRSASHA256, nil
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return algEd25519SHA256, nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

// computeBodyHash computes the SHA-256 hash of the canonicalized message body.
func computeBodyHash(body []byte) []byte {
	canon := canonicalizeBodyRelaxed(body)
	hash := sha256.Sum256(canon)
	return hash[:]
}
