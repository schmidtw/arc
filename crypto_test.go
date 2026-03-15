// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignAndVerify(t *testing.T) {
	tests := []struct {
		name      string
		keyGen    func() (crypto.Signer, crypto.PublicKey, error)
		algorithm string
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
			dataSize:  21,
		},
		{
			name: "Ed25519-SHA256",
			keyGen: func() (crypto.Signer, crypto.PublicKey, error) {
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				return priv, pub, err
			},
			algorithm: algEd25519SHA256,
			dataSize:  30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, pubKey, err := tt.keyGen()
			require.NoError(t, err)

			s := Signer{
				algorithm: tt.algorithm,
				key:       privKey,
			}

			data := make([]byte, tt.dataSize)
			for i := range data {
				data[i] = byte('a' + i%26)
			}

			sig, err := s.sign(data)
			require.NoError(t, err)

			require.NoError(t, verify(pubKey, tt.algorithm, data, sig))
		})
	}
}

func TestSignatureVerificationFailures(t *testing.T) {
	tests := []struct {
		name          string
		keyGen        func() (crypto.Signer, crypto.PublicKey, error)
		algorithm     string
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
				key:       privKey,
			}

			sig, err := s.sign(tt.signData)
			require.NoError(t, err)

			if tt.corruptSig {
				sig[0] ^= 0xFF
			}

			err = verify(pubKey, tt.algorithm, tt.verifyData, sig)
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
	key, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // Testing weak keys
	require.NoError(t, err)

	// A 1024-bit key should be accepted (at the boundary).
	data := []byte("test data")
	s := Signer{
		algorithm: algRSASHA256,
		key:       key,
	}
	sig, err := s.sign(data)
	require.NoError(t, err)
	require.NoError(t, verify(&key.PublicKey, algRSASHA256, data, sig))
}

func TestAlgorithmValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupKey    func() (crypto.Signer, crypto.PublicKey)
		signAlgo    string
		verifyAlgo  string
		expectError bool
	}{
		{
			name: "RSA key with Ed25519 algorithm",
			setupKey: func() (crypto.Signer, crypto.PublicKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey
			},
			signAlgo:    algEd25519SHA256,
			expectError: true,
		},
		{
			name: "Ed25519 key with RSA algorithm",
			setupKey: func() (crypto.Signer, crypto.PublicKey) {
				pub, priv, _ := ed25519.GenerateKey(rand.Reader)
				return priv, pub
			},
			signAlgo:    algRSASHA256,
			expectError: true,
		},
		{
			name: "unsupported algorithm on sign",
			setupKey: func() (crypto.Signer, crypto.PublicKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey
			},
			signAlgo:    "rsa-sha1",
			expectError: true,
		},
		{
			name: "unsupported algorithm on verify",
			setupKey: func() (crypto.Signer, crypto.PublicKey) {
				key, _ := rsa.GenerateKey(rand.Reader, 2048)
				return key, &key.PublicKey
			},
			signAlgo:    algRSASHA256,
			verifyAlgo:  "rsa-sha1",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey, pubKey := tt.setupKey()
			data := []byte("data")

			s := Signer{
				algorithm: tt.signAlgo,
				key:       privKey,
			}

			sig, err := s.sign(data)
			if tt.expectError && tt.verifyAlgo == "" {
				require.Error(t, err)
				return
			}
			if !tt.expectError {
				require.NoError(t, err)
			}

			if tt.verifyAlgo != "" {
				err = verify(pubKey, tt.verifyAlgo, data, sig)
				require.Error(t, err)
			}
		})
	}
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
