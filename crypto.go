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
	hash := sha256.Sum256(data)
	return s.key.Sign(rand.Reader, hash[:], s.hashOpt)
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

// algorithmForKey returns the signing algorithm and hash option for the given key type.
func algorithmForKey(key crypto.Signer) (string, crypto.SignerOpts, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSAKeyBits {
			return "", nil, fmt.Errorf("RSA key too small: %d bits (minimum %d)", k.N.BitLen(), minRSAKeyBits)
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
