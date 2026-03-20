// SPDX-FileCopyrightText: 2026 Weston Schmidt <weston_schmidt@alumni.purdue.edu>
// SPDX-License-Identifier: Apache-2.0

package arc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

var rsaTestKeyCache = make(map[int]*rsa.PrivateKey)

func getRSATestKey(t *testing.T, size int) *rsa.PrivateKey {
	if key, ok := rsaTestKeyCache[size]; ok {
		return key
	}
	key, err := rsa.GenerateKey(rand.Reader, size)
	require.NoError(t, err)
	rsaTestKeyCache[size] = key
	return key
}
