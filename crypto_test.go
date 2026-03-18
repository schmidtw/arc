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
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newVerifyFunc creates a verifyFunc from a public key, mirroring the closures
// built by lookupKey. This lets unit tests exercise sign+verify without DNS.
func newVerifyFunc(t *testing.T, pubKey crypto.PublicKey) verifyFunc {
	t.Helper()
	switch k := pubKey.(type) {
	case *rsa.PublicKey:
		return func(algorithm string, data, signature []byte) error {
			if algorithm != algRSASHA256 {
				return fmt.Errorf("algorithm mismatch: expected %s, got %s", algRSASHA256, algorithm)
			}
			hash := sha256.Sum256(data)
			if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], signature); err != nil {
				return errors.Join(ErrInvalidSignature, err)
			}
			return nil
		}
	case ed25519.PublicKey:
		return func(algorithm string, data, signature []byte) error {
			if algorithm != algEd25519SHA256 {
				return fmt.Errorf("algorithm mismatch: expected %s, got %s", algEd25519SHA256, algorithm)
			}
			hash := sha256.Sum256(data)
			if !ed25519.Verify(k, hash[:], signature) {
				return errors.Join(ErrInvalidSignature, fmt.Errorf("ed25519 signature verification failed"))
			}
			return nil
		}
	default:
		t.Fatalf("unsupported public key type: %T", pubKey)
		return nil
	}
}

func TestSignAndVerify(t *testing.T) {
	tests := []struct {
		name      string
		keyGen    func() (crypto.Signer, crypto.PublicKey, error)
		algorithm string
		hashOpt   crypto.SignerOpts
		dataSize  int
	}{
		{
			name: "RSA-SHA256 2048-bit",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
			algorithm: algRSASHA256,
			hashOpt:   crypto.SHA256,
			dataSize:  21,
		},
		{
			name: "Ed25519-SHA256",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, pub, err
			},
			algorithm: algEd25519SHA256,
			hashOpt:   crypto.Hash(0),
			dataSize:  30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, pubKey, err := tt.keyGen()
			require.NoError(t, err)

			s := Signer{
				algorithm: tt.algorithm,
				hashOpt:   tt.hashOpt,
				key:       privKey,
			}

			data := make([]byte, tt.dataSize)
			for i := range data {
				data[i] = byte('a' + i%26)
			}

			sig, err := s.sign(data)
			require.NoError(t, err)

			verify := newVerifyFunc(t, pubKey)
			require.NoError(t, verify(tt.algorithm, data, sig))
		})
	}
}

func TestSignatureVerificationFailures(t *testing.T) {
	tests := []struct {
		name          string
		keyGen        func() (crypto.Signer, crypto.PublicKey, error)
		algorithm     string
		hashOpt       crypto.SignerOpts
		signData      []byte
		verifyData    []byte
		corruptSig    bool
		expectFailure bool
	}{
		{
			name: "RSA corrupted signature",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
			algorithm:     algRSASHA256,
			hashOpt:       crypto.SHA256,
			signData:      []byte("test data for signing"),
			verifyData:    []byte("test data for signing"),
			corruptSig:    true,
			expectFailure: true,
		},
		{
			name: "RSA modified data",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					return nil, nil, err
				}
				return key, &key.PublicKey, nil
			},
			algorithm:     algRSASHA256,
			hashOpt:       crypto.SHA256,
			signData:      []byte("original data"),
			verifyData:    []byte("modified data"),
			corruptSig:    false,
			expectFailure: true,
		},
		{
			name: "Ed25519 corrupted signature",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, pub, err
			},
			algorithm:     algEd25519SHA256,
			hashOpt:       crypto.Hash(0),
			signData:      []byte("test data"),
			verifyData:    []byte("test data"),
			corruptSig:    true,
			expectFailure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, pubKey, err := tt.keyGen()
			require.NoError(t, err)

			s := Signer{
				algorithm: tt.algorithm,
				hashOpt:   tt.hashOpt,
				key:       privKey,
			}

			sig, err := s.sign(tt.signData)
			require.NoError(t, err)

			if tt.corruptSig {
				sig[0] ^= 0xFF
			}

			verify := newVerifyFunc(t, pubKey)
			err = verify(tt.algorithm, tt.verifyData, sig)
			if tt.expectFailure {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidSignature)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRSAWeakKeyRejected(t *testing.T) {
	t.Run("boundary 1024-bit key accepted", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Testing weak keys
		require.NoError(t, err)

		data := []byte("test data")
		s := Signer{
			algorithm: algRSASHA256,
			hashOpt:   crypto.SHA256,
			key:       key,
		}
		sig, err := s.sign(data)
		require.NoError(t, err)

		verify := newVerifyFunc(t, &key.PublicKey)
		require.NoError(t, verify(algRSASHA256, data, sig))
	})

	t.Run("small key rejected by algorithmForKey", func(t *testing.T) {
		// Construct a minimal RSA key with a small modulus to test our check.
		// Go 1.26+ rejects generating keys below 1024 bits, so we build one
		// manually to exercise the algorithmForKey guard.
		key := &rsa.PrivateKey{}
		key.N = new(big.Int).SetInt64(1) // 1-bit modulus
		key.E = 65537

		_, _, err := algorithmForKey(key, 1024)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "RSA key too small")
	})
}

func TestAlgorithmValidation(t *testing.T) {
	t.Run("unsupported algorithm on verify", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		data := []byte("data")
		s := Signer{
			algorithm: algRSASHA256,
			hashOpt:   crypto.SHA256,
			key:       key,
		}

		sig, err := s.sign(data)
		require.NoError(t, err)

		verify := newVerifyFunc(t, &key.PublicKey)
		err = verify("rsa-sha1", data, sig)
		require.Error(t, err)
	})
}

func TestComputeBodyHash(t *testing.T) {
	tests := []struct {
		name string
		body []byte
	}{
		{
			name: "standard body",
			body: []byte("Hey gang,\r\nThis is a test message.\r\n--J.\r\n"),
		},
		{
			name: "empty body",
			body: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := computeBodyHash(tt.body)
			require.Len(t, hash, 32)

			// Test idempotency - same body should produce same hash.
			hash2 := computeBodyHash(tt.body)
			assert.Equal(t, hash, hash2)
		})
	}
}

// Ensure ed25519.PrivateKey implements crypto.Signer (compile-time check).
var _ crypto.Signer = (ed25519.PrivateKey)(nil)
